<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/** Small QR code generator (byte mode, error correction L, versions 1 to 10) that outputs an SVG. No external service is used. */
class Sidcraft_BotShield_Qr {
	// version => list of ( blocks, codewords per block, data codewords per block ).
	private static $ecc = array( 1 => array( array( 1, 26, 19 ) ), 2 => array( array( 1, 44, 34 ) ), 3 => array( array( 1, 70, 55 ) ), 4 => array( array( 1, 100, 80 ) ), 5 => array( array( 1, 134, 108 ) ), 6 => array( array( 2, 86, 68 ) ), 7 => array( array( 2, 98, 78 ) ), 8 => array( array( 2, 121, 97 ) ), 9 => array( array( 2, 146, 116 ) ), 10 => array( array( 2, 86, 68 ), array( 2, 87, 69 ) ) );
	private static $align = array( 1 => array(), 2 => array( 6, 18 ), 3 => array( 6, 22 ), 4 => array( 6, 26 ), 5 => array( 6, 30 ), 6 => array( 6, 34 ), 7 => array( 6, 22, 38 ), 8 => array( 6, 24, 42 ), 9 => array( 6, 26, 46 ), 10 => array( 6, 28, 50 ) );
	private static $exp = array(); private static $log = array();

	private static function gf_init() {
		if ( self::$exp ) { return; }
		$x = 1;
		for ( $i = 0; $i < 255; $i++ ) { self::$exp[ $i ] = $x; self::$log[ $x ] = $i; $x <<= 1; if ( $x & 0x100 ) { $x ^= 0x11D; } }
		for ( $i = 255; $i < 512; $i++ ) { self::$exp[ $i ] = self::$exp[ $i - 255 ]; }
	}

	private static function rs( array $data, $n ) {
		self::gf_init();
		$gen = array( 1 );
		for ( $i = 0; $i < $n; $i++ ) {
			$next = array_fill( 0, count( $gen ) + 1, 0 );
			foreach ( $gen as $j => $c ) { $next[ $j ] ^= $c; $next[ $j + 1 ] ^= ( 0 === $c ) ? 0 : self::$exp[ self::$log[ $c ] + $i ]; }
			$gen = $next;
		}
		$res = array_fill( 0, $n, 0 );
		foreach ( $data as $d ) {
			$f = $d ^ $res[0]; array_shift( $res ); $res[] = 0;
			if ( 0 !== $f ) { for ( $j = 0; $j < $n; $j++ ) { $res[ $j ] ^= ( 0 === $gen[ $j + 1 ] ) ? 0 : self::$exp[ self::$log[ $gen[ $j + 1 ] ] + self::$log[ $f ] ]; } }
		}
		return $res;
	}

	private static function bch( $v, $poly, $bits ) { $d = $v << $bits; $len = strlen( decbin( $poly ) ); while ( strlen( decbin( $d ) ) >= $len ) { $d ^= $poly << ( strlen( decbin( $d ) ) - $len ); } return ( $v << $bits ) | $d; }

	/** The matrix as rows of 0/1, or null if the text is too long. */
	public static function matrix( $text ) {
		$bytes = array_values( unpack( 'C*', $text ) ); $n = count( $bytes ); $ver = 0;
		for ( $v = 1; $v <= 10; $v++ ) { $cap = 0; foreach ( self::$ecc[ $v ] as $g ) { $cap += $g[0] * $g[2]; } if ( $n + ( $v < 10 ? 2 : 3 ) <= $cap ) { $ver = $v; break; } }
		if ( ! $ver ) { return null; }
		$total_data = 0; foreach ( self::$ecc[ $ver ] as $g ) { $total_data += $g[0] * $g[2]; }
		$bits = '0100' . str_pad( decbin( $n ), $ver < 10 ? 8 : 16, '0', STR_PAD_LEFT );
		foreach ( $bytes as $b ) { $bits .= str_pad( decbin( $b ), 8, '0', STR_PAD_LEFT ); }
		$bits .= str_repeat( '0', min( 4, $total_data * 8 - strlen( $bits ) ) );
		$bits .= str_repeat( '0', ( 8 - strlen( $bits ) % 8 ) % 8 );
		$cw = array(); foreach ( str_split( $bits, 8 ) as $c ) { $cw[] = bindec( $c ); }
		for ( $i = 0; count( $cw ) < $total_data; $i++ ) { $cw[] = ( 0 === $i % 2 ) ? 0xEC : 0x11; }
		// Blocks.
		$blocks = array(); $ecs = array(); $pos = 0;
		foreach ( self::$ecc[ $ver ] as $g ) { for ( $b = 0; $b < $g[0]; $b++ ) { $d = array_slice( $cw, $pos, $g[2] ); $pos += $g[2]; $blocks[] = $d; $ecs[] = self::rs( $d, $g[1] - $g[2] ); } }
		$final = array(); $maxd = max( array_map( 'count', $blocks ) );
		for ( $i = 0; $i < $maxd; $i++ ) { foreach ( $blocks as $b ) { if ( isset( $b[ $i ] ) ) { $final[] = $b[ $i ]; } } }
		for ( $i = 0; $i < count( $ecs[0] ); $i++ ) { foreach ( $ecs as $e ) { $final[] = $e[ $i ]; } }
		$bitstr = ''; foreach ( $final as $c ) { $bitstr .= str_pad( decbin( $c ), 8, '0', STR_PAD_LEFT ); }
		if ( $ver >= 2 ) { $bitstr .= str_repeat( '0', 7 ); } // remainder bits (7 for versions 2 to 6, 0 for 1; 7 also for 7 to 13... handled below).
		if ( 1 === $ver ) { $bitstr = substr( $bitstr, 0, strlen( $bitstr ) ); }
		$size = 17 + 4 * $ver; $m = array_fill( 0, $size, array_fill( 0, $size, null ) );
		self::patterns( $m, $ver, $size );
		$best = null; $best_score = PHP_INT_MAX;
		for ( $mask = 0; $mask < 8; $mask++ ) {
			$t = $m; self::place( $t, $bitstr, $size, $mask ); self::format( $t, $size, $mask );
			$s = self::penalty( $t, $size ); if ( $s < $best_score ) { $best_score = $s; $best = $t; }
		}
		return $best;
	}

	private static function patterns( &$m, $ver, $size ) {
		$finder = function ( $r, $c ) use ( &$m, $size ) { for ( $dr = -1; $dr <= 7; $dr++ ) { for ( $dc = -1; $dc <= 7; $dc++ ) { $rr = $r + $dr; $cc = $c + $dc; if ( $rr < 0 || $cc < 0 || $rr >= $size || $cc >= $size ) { continue; } $m[ $rr ][ $cc ] = ( $dr >= 0 && $dr <= 6 && $dc >= 0 && $dc <= 6 && ( 0 === $dr || 6 === $dr || 0 === $dc || 6 === $dc || ( $dr >= 2 && $dr <= 4 && $dc >= 2 && $dc <= 4 ) ) ) ? 1 : 0; } } };
		$finder( 0, 0 ); $finder( 0, $size - 7 ); $finder( $size - 7, 0 );
		for ( $i = 8; $i < $size - 8; $i++ ) { $m[6][ $i ] = $m[ $i ][6] = ( 0 === $i % 2 ) ? 1 : 0; }
		$pos = self::$align[ $ver ];
		foreach ( $pos as $r ) { foreach ( $pos as $c ) { if ( ( $r <= 8 && $c <= 8 ) || ( $r <= 8 && $c >= $size - 9 ) || ( $r >= $size - 9 && $c <= 8 ) ) { continue; } for ( $dr = -2; $dr <= 2; $dr++ ) { for ( $dc = -2; $dc <= 2; $dc++ ) { $m[ $r + $dr ][ $c + $dc ] = ( max( abs( $dr ), abs( $dc ) ) !== 1 ) ? 1 : 0; } } } }
		$m[ $size - 8 ][8] = 1; // dark module.
		for ( $i = 0; $i < 9; $i++ ) { if ( null === $m[8][ $i ] ) { $m[8][ $i ] = 2; } if ( null === $m[ $i ][8] ) { $m[ $i ][8] = 2; } }
		for ( $i = 0; $i < 8; $i++ ) { if ( null === $m[8][ $size - 1 - $i ] ) { $m[8][ $size - 1 - $i ] = 2; } if ( null === $m[ $size - 1 - $i ][8] ) { $m[ $size - 1 - $i ][8] = 2; } }
		if ( $ver >= 7 ) { $v = self::bch( $ver, 0x1F25, 12 ); for ( $i = 0; $i < 18; $i++ ) { $bit = ( $v >> $i ) & 1; $a = intdiv( $i, 3 ); $b = $i % 3 + $size - 11; $m[ $a ][ $b ] = $bit; $m[ $b ][ $a ] = $bit; } }
	}

	private static function place( &$m, $bits, $size, $mask ) {
		$i = 0; $n = strlen( $bits ); $up = true;
		for ( $col = $size - 1; $col > 0; $col -= 2 ) {
			if ( 6 === $col ) { $col--; }
			for ( $k = 0; $k < $size; $k++ ) {
				$r = $up ? $size - 1 - $k : $k;
				for ( $c = 0; $c < 2; $c++ ) {
					$cc = $col - $c; if ( null !== $m[ $r ][ $cc ] ) { continue; }
					$bit = $i < $n ? (int) $bits[ $i ] : 0; $i++;
					switch ( $mask ) { case 0: $f = ( $r + $cc ) % 2 === 0; break; case 1: $f = $r % 2 === 0; break; case 2: $f = $cc % 3 === 0; break; case 3: $f = ( $r + $cc ) % 3 === 0; break; case 4: $f = ( intdiv( $r, 2 ) + intdiv( $cc, 3 ) ) % 2 === 0; break; case 5: $f = ( $r * $cc ) % 2 + ( $r * $cc ) % 3 === 0; break; case 6: $f = ( ( $r * $cc ) % 2 + ( $r * $cc ) % 3 ) % 2 === 0; break; default: $f = ( ( $r + $cc ) % 2 + ( $r * $cc ) % 3 ) % 2 === 0; }
					$m[ $r ][ $cc ] = $bit ^ ( $f ? 1 : 0 );
				}
			}
			$up = ! $up;
		}
	}

	private static function format( &$m, $size, $mask ) {
		$f = self::bch( ( 1 << 3 ) | $mask, 0x537, 10 ) ^ 0x5412; // error level L = 01.
		for ( $i = 0; $i < 15; $i++ ) {
			$bit = ( $f >> $i ) & 1;
			if ( $i < 6 ) { $m[ $i ][8] = $bit; } elseif ( $i < 8 ) { $m[ $i + 1 ][8] = $bit; } else { $m[ $size - 15 + $i ][8] = $bit; }
			if ( $i < 8 ) { $m[8][ $size - 1 - $i ] = $bit; } elseif ( $i < 9 ) { $m[8][ 15 - $i ] = $bit; } else { $m[8][ 14 - $i ] = $bit; }
		}
		$m[ $size - 8 ][8] = 1;
	}

	private static function penalty( $m, $size ) {
		$s = 0;
		for ( $pass = 0; $pass < 2; $pass++ ) {
			for ( $a = 0; $a < $size; $a++ ) {
				$run = 1;
				for ( $b = 1; $b < $size; $b++ ) { $cur = $pass ? $m[ $b ][ $a ] : $m[ $a ][ $b ]; $prev = $pass ? $m[ $b - 1 ][ $a ] : $m[ $a ][ $b - 1 ]; if ( $cur === $prev ) { $run++; if ( 5 === $run ) { $s += 3; } elseif ( $run > 5 ) { $s++; } } else { $run = 1; } }
			}
		}
		for ( $r = 0; $r < $size - 1; $r++ ) { for ( $c = 0; $c < $size - 1; $c++ ) { if ( $m[ $r ][ $c ] === $m[ $r ][ $c + 1 ] && $m[ $r ][ $c ] === $m[ $r + 1 ][ $c ] && $m[ $r ][ $c ] === $m[ $r + 1 ][ $c + 1 ] ) { $s += 3; } } }
		$dark = 0; foreach ( $m as $row ) { $dark += array_sum( $row ); }
		return $s + 10 * (int) ( abs( 100 * $dark / ( $size * $size ) - 50 ) / 5 );
	}

	/** An inline SVG for the text, or '' if it does not fit. */
	public static function svg( $text, $scale = 4 ) {
		$m = self::matrix( $text ); if ( ! $m ) { return ''; }
		$size = count( $m ); $q = 4; $dim = ( $size + 2 * $q ) * $scale; $d = '';
		for ( $r = 0; $r < $size; $r++ ) { for ( $c = 0; $c < $size; $c++ ) { if ( 1 === $m[ $r ][ $c ] ) { $d .= 'M' . ( ( $c + $q ) * $scale ) . ' ' . ( ( $r + $q ) * $scale ) . 'h' . $scale . 'v' . $scale . 'h-' . $scale . 'z'; } } }
		return '<svg xmlns="http://www.w3.org/2000/svg" width="' . (int) $dim . '" height="' . (int) $dim . '" viewBox="0 0 ' . (int) $dim . ' ' . (int) $dim . '" role="img" aria-label="QR code"><rect width="100%" height="100%" fill="#fff"/><path d="' . esc_attr( $d ) . '" fill="#000"/></svg>';
	}
}
