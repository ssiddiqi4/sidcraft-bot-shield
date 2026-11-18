<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/** Temporary address bans. The transient does the blocking; the option is the list shown in the Firewall tab. */
class Sidcraft_BotShield_Bans {
	const OPTION = 'sidcraft_botshield_bans';

	public static function add( $ip, $seconds, $reason ) {
		if ( '' === $ip ) { return; }
		set_transient( 'sbs_ban_' . md5( $ip ), 1, max( 60, (int) $seconds ) );
		$all = self::all(); $all[ $ip ] = array( 'until' => time() + (int) $seconds, 'reason' => (string) $reason, 'since' => time() );
		if ( count( $all ) > 300 ) { uasort( $all, function ( $a, $b ) { return $b['since'] <=> $a['since']; } ); $all = array_slice( $all, 0, 300, true ); }
		update_option( self::OPTION, $all, false );
	}

	public static function remove( $ip ) {
		delete_transient( 'sbs_ban_' . md5( $ip ) );
		$all = self::all(); unset( $all[ $ip ] ); update_option( self::OPTION, $all, false );
	}

	/** Current bans (expired ones dropped). */
	public static function all() {
		$o = get_option( self::OPTION, array() ); $o = is_array( $o ) ? $o : array(); $now = time();
		return array_filter( $o, function ( $b ) use ( $now ) { return isset( $b['until'] ) && $b['until'] > $now; } );
	}
}
