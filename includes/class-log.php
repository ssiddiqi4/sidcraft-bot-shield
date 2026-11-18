<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

class Sidcraft_BotShield_Log {
	const LOG = 'sidcraft_botshield_log';
	const STATS = 'sidcraft_botshield_stats';

	public static function add( $action, $reason, $ip, $ua, $path ) {
		$day = gmdate( 'Ymd' );
		$st  = get_option( self::STATS, array() ); $st = is_array( $st ) ? $st : array();
		if ( ! isset( $st[ $day ] ) ) { $st[ $day ] = array( 'blocked' => 0, 'monitored' => 0, 'reasons' => array() ); }
		$st[ $day ][ 'block' === $action ? 'blocked' : 'monitored' ]++;
		$st[ $day ]['reasons'][ $reason ] = ( $st[ $day ]['reasons'][ $reason ] ?? 0 ) + 1;
		krsort( $st ); $st = array_slice( $st, 0, 14, true );
		update_option( self::STATS, $st, false );
		if ( ! Sidcraft_BotShield_Settings::get( 'keep_log' ) ) { return; }
		$log = get_option( self::LOG, array() ); $log = is_array( $log ) ? $log : array();
		array_unshift( $log, array( 't' => time(), 'a' => $action, 'r' => $reason, 'ip' => $ip, 'ua' => substr( $ua, 0, 160 ), 'p' => substr( $path, 0, 120 ) ) );
		$cut = time() - 7 * DAY_IN_SECONDS;
		$log = array_values( array_filter( array_slice( $log, 0, 100 ), function ( $r ) use ( $cut ) { return $r['t'] >= $cut; } ) );
		update_option( self::LOG, $log, false );
	}

	public static function entries() { $l = get_option( self::LOG, array() ); return is_array( $l ) ? $l : array(); }
	public static function stats() { $s = get_option( self::STATS, array() ); return is_array( $s ) ? $s : array(); }
	public static function clear() { delete_option( self::LOG ); delete_option( self::STATS ); }
}
