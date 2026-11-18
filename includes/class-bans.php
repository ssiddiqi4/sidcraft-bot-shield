<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/** Address bans. Temporary bans live in a transient; permanent ones in a small autoloaded option. The registry is the list shown to the admin. */
class Sidcraft_BotShield_Bans {
	const OPTION = 'sidcraft_botshield_bans';
	const PERM   = 'sidcraft_botshield_perm';

	/** Ban an address. $seconds of 0 means permanently. $kind 'nf' marks the missing-pages rule. */
	public static function add( $ip, $seconds, $reason, $kind = 'auto' ) {
		if ( '' === $ip ) { return; }
		$seconds = (int) $seconds; $now = time();
		$all = self::registry();
		$all[ $ip ] = array( 'until' => $seconds > 0 ? $now + $seconds : 0, 'reason' => (string) $reason, 'since' => $now, 'host' => $all[ $ip ]['host'] ?? '' );
		if ( count( $all ) > 400 ) { uasort( $all, function ( $a, $b ) { return $b['since'] <=> $a['since']; } ); $all = array_slice( $all, 0, 400, true ); }
		update_option( self::OPTION, $all, false );
		if ( $seconds > 0 ) { set_transient( 'sbs_ban_' . md5( $ip ), 1, max( 60, $seconds ) ); }
		else { $p = self::perm(); $p[ $ip ] = 1; update_option( self::PERM, $p, true ); }
		Sidcraft_BotShield_Notify::schedule( $ip, (string) $reason, $seconds, $kind );
	}

	public static function is_banned( $ip ) {
		if ( '' === $ip ) { return false; }
		if ( get_transient( 'sbs_ban_' . md5( $ip ) ) ) { return true; }
		$p = self::perm(); return isset( $p[ $ip ] );
	}

	public static function remove( $ip ) {
		delete_transient( 'sbs_ban_' . md5( $ip ) );
		$p = self::perm(); if ( isset( $p[ $ip ] ) ) { unset( $p[ $ip ] ); update_option( self::PERM, $p, true ); }
		$all = self::registry(); unset( $all[ $ip ] ); update_option( self::OPTION, $all, false );
	}

	public static function set_host( $ip, $host ) { $all = self::registry(); if ( isset( $all[ $ip ] ) ) { $all[ $ip ]['host'] = $host; update_option( self::OPTION, $all, false ); } }

	private static function perm() { $p = get_option( self::PERM, array() ); return is_array( $p ) ? $p : array(); }
	private static function registry() { $o = get_option( self::OPTION, array() ); return is_array( $o ) ? $o : array(); }

	/** Current bans (expired ones dropped). */
	public static function all() {
		$now = time();
		return array_filter( self::registry(), function ( $b ) use ( $now ) { return isset( $b['until'] ) && ( 0 === (int) $b['until'] || $b['until'] > $now ); } );
	}
}
