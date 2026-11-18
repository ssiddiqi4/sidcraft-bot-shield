<?php
if ( ! defined( 'ABSPATH' ) ) {
	// Outside WordPress this file is only loaded by the firewall bootstrap, which defines this constant first.
	if ( ! defined( 'SIDCRAFT_BOTSHIELD_WAF' ) ) {
		exit;
	}
}

/**
 * IPv4 / IPv6 helpers: single addresses, CIDR (10.0.0.0/8, 2001:db8::/32) and dash ranges (1.2.3.4 - 1.2.3.99),
 * plus sorted binary range files that are searched without loading them into memory.
 */
class Sidcraft_BotShield_Ranges {
	/** Address as packed bytes (4 or 16). IPv4-mapped IPv6 becomes plain IPv4. */
	public static function pack( $ip ) {
		$ip = trim( (string) $ip );
		if ( '' === $ip || ! filter_var( $ip, FILTER_VALIDATE_IP ) ) { return ''; }
		$b = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $b ) { return ''; }
		if ( 16 === strlen( $b ) && "\0\0\0\0\0\0\0\0\0\0\xff\xff" === substr( $b, 0, 12 ) ) { $b = substr( $b, 12 ); }
		return $b;
	}

	/** One line to array( low, high ) packed addresses, or null if it is not valid. */
	public static function parse( $line ) {
		$line = trim( (string) $line );
		if ( '' === $line ) { return null; }
		if ( false !== strpos( $line, '/' ) ) {
			list( $net, $bits ) = array_pad( explode( '/', $line, 2 ), 2, '' );
			if ( ! ctype_digit( $bits ) ) { return null; }
			$a = self::pack( trim( $net ) ); if ( '' === $a ) { return null; }
			$len = strlen( $a ); $bits = (int) $bits;
			if ( 16 === $len && false !== strpos( $net, '.' ) && false !== strpos( $net, ':' ) ) { $bits = max( 0, $bits - 96 ); } // ::ffff:1.2.3.0/120
			if ( $bits > $len * 8 ) { return null; }
			$full = intdiv( $bits, 8 ); $rest = $bits % 8;
			$mask = str_repeat( "\xff", $full ) . ( $rest ? chr( ( 0xFF << ( 8 - $rest ) ) & 0xFF ) : '' );
			$mask = str_pad( $mask, $len, "\0" );
			return array( $a & $mask, $a | ~$mask );
		}
		if ( preg_match( '/^(\S+)\s*[-–]\s*(\S+)$/u', $line, $m ) ) {
			$a = self::pack( $m[1] ); $b = self::pack( $m[2] );
			if ( '' === $a || '' === $b || strlen( $a ) !== strlen( $b ) || strcmp( $a, $b ) > 0 ) { return null; }
			return array( $a, $b );
		}
		$a = self::pack( $line );
		return '' === $a ? null : array( $a, $a );
	}

	/** Is $ip inside any entry of a list of text lines? */
	public static function in_list( $ip, array $lines ) {
		$a = self::pack( $ip );
		if ( '' === $a ) { return false; }
		foreach ( $lines as $l ) {
			$p = self::parse( $l );
			if ( $p && strlen( $p[0] ) === strlen( $a ) && strcmp( $a, $p[0] ) >= 0 && strcmp( $a, $p[1] ) <= 0 ) { return true; }
		}
		return false;
	}

	/** Sort and merge overlapping ranges. */
	public static function merge( array $pairs ) {
		usort( $pairs, function ( $x, $y ) { return strcmp( $x[0], $y[0] ); } );
		$out = array();
		foreach ( $pairs as $p ) {
			$n = count( $out );
			if ( $n && strcmp( $p[0], $out[ $n - 1 ][1] ) <= 0 ) { if ( strcmp( $p[1], $out[ $n - 1 ][1] ) > 0 ) { $out[ $n - 1 ][1] = $p[1]; } }
			else { $out[] = $p; }
		}
		return $out;
	}

	/** Write ranges (all the same family) to a binary file of fixed-size records. Returns the number of ranges. */
	public static function write( $path, array $pairs ) {
		$pairs = self::merge( $pairs ); $data = '';
		foreach ( $pairs as $p ) { $data .= $p[0] . $p[1]; }
		$tmp = $path . '.tmp';
		if ( false === file_put_contents( $tmp, $data ) ) { return 0; } // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		if ( ! @rename( $tmp, $path ) ) { return 0; } // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.rename_rename
		return count( $pairs );
	}

	/** Binary search in a file written by write(). $len is 4 (IPv4) or 16 (IPv6). */
	public static function file_contains( $path, $packed ) {
		$len = strlen( $packed ); $rec = $len * 2;
		if ( ( 4 !== $len && 16 !== $len ) || ! is_readable( $path ) ) { return false; }
		$size = filesize( $path ); $n = intdiv( $size, $rec );
		if ( $n < 1 ) { return false; }
		$f = fopen( $path, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
		if ( ! $f ) { return false; }
		$lo = 0; $hi = $n - 1; $hit = false;
		while ( $lo <= $hi ) {
			$mid = intdiv( $lo + $hi, 2 );
			fseek( $f, $mid * $rec );
			$r = fread( $f, $rec ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread
			if ( strlen( $r ) !== $rec ) { break; }
			if ( strcmp( $packed, substr( $r, 0, $len ) ) < 0 ) { $hi = $mid - 1; }
			elseif ( strcmp( $packed, substr( $r, $len ) ) > 0 ) { $lo = $mid + 1; }
			else { $hit = true; break; }
		}
		fclose( $f ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
		return $hit;
	}
}
