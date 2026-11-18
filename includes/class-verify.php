<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/** Proves that a visitor claiming to be a search engine really comes from that company (reverse DNS, then forward DNS). */
class Sidcraft_BotShield_Verify {

	/** @return string pass|fail|unknown */
	public static function check( $ip, $suffixes ) {
		$key = 'sbs_v_' . md5( $ip . '|' . implode( ',', $suffixes ) );
		$hit = get_transient( $key );
		if ( is_string( $hit ) ) { return $hit; }
		$host = apply_filters( 'sidcraft_botshield_rdns', null, $ip );
		if ( null === $host ) { $host = function_exists( 'gethostbyaddr' ) ? @gethostbyaddr( $ip ) : false; } // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- a failed lookup is a normal outcome.
		if ( ! is_string( $host ) || '' === $host || $host === $ip ) { set_transient( $key, 'unknown', 10 * MINUTE_IN_SECONDS ); return 'unknown'; }
		$host = strtolower( rtrim( $host, '.' ) );
		$ok   = false;
		foreach ( $suffixes as $s ) { if ( strlen( $host ) > strlen( $s ) && substr( $host, -strlen( $s ) ) === $s ) { $ok = true; break; } }
		$res = 'fail';
		if ( $ok ) {
			$back = apply_filters( 'sidcraft_botshield_forward', null, $host );
			if ( null === $back ) {
				$back = array();
				$a    = function_exists( 'gethostbynamel' ) ? @gethostbynamel( $host ) : false; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				if ( is_array( $a ) ) { $back = $a; }
				if ( function_exists( 'dns_get_record' ) && false !== strpos( $ip, ':' ) ) {
					$aaaa = @dns_get_record( $host, DNS_AAAA ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
					foreach ( (array) $aaaa as $r ) { if ( ! empty( $r['ipv6'] ) ) { $back[] = $r['ipv6']; } }
				}
			}
			$want = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			foreach ( (array) $back as $b ) { if ( $want && @inet_pton( $b ) === $want ) { $res = 'pass'; break; } } // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		}
		set_transient( $key, $res, DAY_IN_SECONDS );
		return $res;
	}
}
