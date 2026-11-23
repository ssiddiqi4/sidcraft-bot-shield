<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/** Small read-only reader for MaxMind DB (.mmdb) files such as GeoLite2-Country or DB-IP Lite. No libraries needed. */
class Botvanguard_Mmdb {
	private $f; private $meta; private $tree_size; private $data_start; private $v4_start = null;

	public static function open( $path ) {
		if ( ! is_readable( $path ) ) { return null; }
		$r = new self(); return $r->load( $path ) ? $r : null;
	}

	private function load( $path ) {
		$this->f = fopen( $path, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
		if ( ! $this->f ) { return false; }
		$size = filesize( $path ); $tail = min( $size, 131072 );
		fseek( $this->f, $size - $tail );
		$buf = fread( $this->f, $tail ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread
		$pos = strrpos( $buf, "\xAB\xCD\xEFMaxMind.com" );
		if ( false === $pos ) { return false; }
		$meta_off = $size - $tail + $pos + 14;
		$m = $this->decode_at( $meta_off, 0, true );
		$this->meta = is_array( $m ) ? $m : null;
		if ( ! $this->meta || empty( $this->meta['node_count'] ) || empty( $this->meta['record_size'] ) || ! in_array( (int) $this->meta['record_size'], array( 24, 28, 32 ), true ) ) { return false; }
		$this->tree_size  = (int) ( ( (int) $this->meta['record_size'] * 2 / 8 ) * (int) $this->meta['node_count'] );
		$this->data_start = $this->tree_size + 16;
		return true;
	}

	public function __destruct() { if ( $this->f ) { fclose( $this->f ); } } // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose

	private function read( $off, $len ) { fseek( $this->f, $off ); return (string) fread( $this->f, $len ); } // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread

	/** Look up an IP address; returns the record (array) or null. */
	public function get( $ip ) {
		$b = Botvanguard_Ranges::pack( $ip );
		if ( '' === $b ) { return null; }
		$v6 = 6 === (int) $this->meta['ip_version'];
		if ( 4 === strlen( $b ) && $v6 ) { $b = str_repeat( "\0", 12 ) . $b; }
		if ( 16 === strlen( $b ) && ! $v6 ) { return null; }
		$nodes = (int) $this->meta['node_count']; $rs = (int) $this->meta['record_size']; $bytes = $rs / 4;
		$node = 0; $bits = strlen( $b ) * 8;
		for ( $i = 0; $i < $bits && $node < $nodes; $i++ ) {
			$bit = ( ord( $b[ $i >> 3 ] ) >> ( 7 - ( $i & 7 ) ) ) & 1;
			$n = $this->read( $node * $bytes, (int) $bytes );
			if ( strlen( $n ) < $bytes ) { return null; }
			$o = array_values( unpack( 'C*', $n ) );
			if ( 24 === $rs ) { $node = $bit ? ( ( $o[3] << 16 ) | ( $o[4] << 8 ) | $o[5] ) : ( ( $o[0] << 16 ) | ( $o[1] << 8 ) | $o[2] ); }
			elseif ( 28 === $rs ) { $node = $bit ? ( ( ( $o[3] & 0x0F ) << 24 ) | ( $o[4] << 16 ) | ( $o[5] << 8 ) | $o[6] ) : ( ( ( $o[3] & 0xF0 ) << 20 ) | ( $o[0] << 16 ) | ( $o[1] << 8 ) | $o[2] ); }
			else { $node = $bit ? ( ( $o[4] << 24 ) | ( $o[5] << 16 ) | ( $o[6] << 8 ) | $o[7] ) : ( ( $o[0] << 24 ) | ( $o[1] << 16 ) | ( $o[2] << 8 ) | $o[3] ); }
		}
		if ( $node <= $nodes ) { return null; } // == nodes means "not in the database".
		$res = $this->decode_at( $this->tree_size + ( $node - $nodes ), 0, false );
		return is_array( $res ) ? $res : null;
	}

	public function country( $ip ) {
		$r = $this->get( $ip );
		foreach ( array( 'country', 'registered_country' ) as $k ) {
			if ( isset( $r[ $k ]['iso_code'] ) && preg_match( '/^[A-Za-z]{2}$/', $r[ $k ]['iso_code'] ) ) { return strtoupper( $r[ $k ]['iso_code'] ); }
		}
		return '';
	}

	private function decode_at( $off, $depth, $meta ) { $o = $off; return $this->decode( $o, $depth, $meta ); }

	/** Decode one value at file offset $o (advanced past it). $meta: pointers are relative to the start of the metadata. */
	private function decode( &$o, $depth, $meta ) {
		if ( $depth > 12 ) { return null; }
		$ctrl = ord( $this->read( $o++, 1 ) );
		$type = $ctrl >> 5;
		if ( 1 === $type ) { // pointer
			$ss = ( $ctrl >> 3 ) & 3; $vvv = $ctrl & 7;
			$n  = $this->read( $o, $ss + 1 ); $o += $ss + 1; $v = array_values( unpack( 'C*', $n ) );
			if ( 0 === $ss ) { $p = ( $vvv << 8 ) + $v[0]; }
			elseif ( 1 === $ss ) { $p = ( ( $vvv << 16 ) + ( $v[0] << 8 ) + $v[1] ) + 2048; }
			elseif ( 2 === $ss ) { $p = ( ( $vvv << 24 ) + ( $v[0] << 16 ) + ( $v[1] << 8 ) + $v[2] ) + 526336; }
			else { $p = ( $v[0] << 24 ) + ( $v[1] << 16 ) + ( $v[2] << 8 ) + $v[3]; }
			$t = $this->data_start + $p; if ( $meta ) { return null; }
			return $this->decode_at( $t, $depth + 1, false );
		}
		if ( 0 === $type ) { $type = 7 + ord( $this->read( $o++, 1 ) ); }
		$size = $ctrl & 0x1F;
		if ( 29 === $size ) { $size = 29 + ord( $this->read( $o++, 1 ) ); }
		elseif ( 30 === $size ) { $v = unpack( 'n', $this->read( $o, 2 ) ); $o += 2; $size = 285 + $v[1]; }
		elseif ( 31 === $size ) { $v = unpack( 'C3', $this->read( $o, 3 ) ); $o += 3; $size = 65821 + ( $v[1] << 16 ) + ( $v[2] << 8 ) + $v[3]; }
		switch ( $type ) {
			case 2: $s = $this->read( $o, $size ); $o += $size; return $s;
			case 4: $o += $size; return '';
			case 3: $s = $this->read( $o, 8 ); $o += 8; $v = unpack( 'E', $s ); return $v[1];
			case 15: $s = $this->read( $o, 4 ); $o += 4; $v = unpack( 'G', $s ); return $v[1];
			case 5: case 6: case 8: case 9: case 10:
				$s = $this->read( $o, $size ); $o += $size; $n = 0;
				foreach ( str_split( $s ) as $ch ) { $n = ( $n * 256 ) + ord( $ch ); }
				if ( 8 === $type && 4 === $size && $n >= 2147483648 ) { $n -= 4294967296; }
				return $n;
			case 14: return (bool) $size;
			case 7:
				$m = array();
				for ( $i = 0; $i < $size; $i++ ) { $k = $this->decode( $o, $depth + 1, $meta ); $v = $this->decode( $o, $depth + 1, $meta ); if ( is_string( $k ) ) { $m[ $k ] = $v; } }
				return $m;
			case 11:
				$a = array(); for ( $i = 0; $i < $size; $i++ ) { $a[] = $this->decode( $o, $depth + 1, $meta ); } return $a;
			default: return null;
		}
	}
}
