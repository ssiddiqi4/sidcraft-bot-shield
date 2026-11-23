<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

class Sidcraft_BotShield_Log {
	const LOG = 'sidcraft_botshield_log';
	const STATS = 'sidcraft_botshield_stats';

	public static function add( $action, $reason, $ip, $ua, $path, $country = '', $time = 0 ) {
		$time = $time ? (int) $time : time();
		$day = gmdate( 'Ymd', $time );
		$st  = get_option( self::STATS, array() ); $st = is_array( $st ) ? $st : array();
		if ( ! isset( $st[ $day ] ) ) { $st[ $day ] = array( 'blocked' => 0, 'monitored' => 0, 'reasons' => array() ); }
		$st[ $day ][ 'block' === $action ? 'blocked' : 'monitored' ]++;
		$st[ $day ]['reasons'][ $reason ] = ( $st[ $day ]['reasons'][ $reason ] ?? 0 ) + 1;
		krsort( $st ); $st = array_slice( $st, 0, 30, true );
		update_option( self::STATS, $st, false );
		if ( ! Sidcraft_BotShield_Settings::get( 'keep_log' ) ) { return; }
		$log = get_option( self::LOG, array() ); $log = is_array( $log ) ? $log : array();
		array_unshift( $log, array( 't' => $time, 'a' => $action, 'r' => $reason, 'ip' => $ip, 'ua' => substr( $ua, 0, 160 ), 'p' => substr( $path, 0, 120 ), 'c' => (string) $country ) );
		$cut = time() - 30 * DAY_IN_SECONDS;
		$log = array_values( array_filter( array_slice( $log, 0, 500 ), function ( $r ) use ( $cut ) { return $r['t'] >= $cut; } ) );
		update_option( self::LOG, $log, false );
	}

	/** Reason codes grouped into the types shown on the overview card. */
	public static function types() {
		return array(
			'bots'    => array( __( 'Bad bots', 'botvaguard' ), '#b32d2e' ),
			'probes'  => array( __( 'Attack probes & bans', 'botvaguard' ), '#8a2be2' ),
			'country' => array( __( 'Country', 'botvaguard' ), '#2271b1' ),
			'ip'      => array( __( 'Blocked addresses', 'botvaguard' ), '#bd5b00' ),
			'vpn'     => array( __( 'VPN / proxy / Tor', 'botvaguard' ), '#007a5a' ),
			'waf'     => array( __( 'Firewall rules', 'botvaguard' ), '#d63638' ),
			'login'   => array( __( 'Login protection', 'botvaguard' ), '#996800' ),
			'rest'    => array( __( 'REST API', 'botvaguard' ), '#0a7ea4' ),
			'rate'    => array( __( 'Too many requests', 'botvaguard' ), '#646970' ),
		);
	}

	public static function type_of( $reason ) {
		if ( 0 === strpos( $reason, 'bad_bot' ) || in_array( $reason, array( 'empty_ua', 'fake_bot', 'custom_block' ), true ) ) { return 'bots'; }
		if ( in_array( $reason, array( 'scanner_path', 'trap', 'banned' ), true ) ) { return 'probes'; }
		if ( 0 === strpos( $reason, 'waf_' ) || in_array( $reason, array( 'enum_author', 'blank_post' ), true ) ) { return 'waf'; }
		if ( 0 === strpos( $reason, 'rest_' ) ) { return 'rest'; }
		if ( 0 === strpos( $reason, 'brute_' ) || 'login_url' === $reason ) { return 'login'; }
		if ( 0 === strpos( $reason, 'geo_' ) ) { return 'country'; }
		if ( 'ip_blocked' === $reason ) { return 'ip'; }
		if ( in_array( $reason, array( 'tor', 'vpn', 'datacenter', 'proxy_header', 'vpn_api' ), true ) ) { return 'vpn'; }
		return 'rate';
	}

	/** Totals for the last $days days: array( blocked, monitored, by_type => array( type => count ) ). */
	public static function summary( $days ) {
		$out = array( 'blocked' => 0, 'monitored' => 0, 'by_type' => array() );
		$from = gmdate( 'Ymd', time() - ( $days - 1 ) * DAY_IN_SECONDS );
		foreach ( self::stats() as $day => $d ) {
			if ( (string) $day < $from ) { continue; }
			$out['blocked'] += (int) $d['blocked']; $out['monitored'] += (int) $d['monitored'];
			foreach ( (array) $d['reasons'] as $r => $n ) { $t = self::type_of( $r ); $out['by_type'][ $t ] = ( $out['by_type'][ $t ] ?? 0 ) + (int) $n; }
		}
		return $out;
	}

	public static function entries() { $l = get_option( self::LOG, array() ); return is_array( $l ) ? $l : array(); }
	public static function stats() { $s = get_option( self::STATS, array() ); return is_array( $s ) ? $s : array(); }
	public static function clear() { delete_option( self::LOG ); delete_option( self::STATS ); }
}
