<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/** Settings for the firewall tab (kept apart from the bot settings so that each tab saves on its own). */
class Sidcraft_BotShield_FwSettings {
	const OPTION = 'sidcraft_botshield_fw';

	public static function defaults() {
		return array(
			'waf_mode'        => 'learning', // disabled | learning | enabled. Learning turns into enabled after 7 days.
			'waf_since'       => 0,
			'waf_disabled'    => array(),    // rule ids switched off.
			'waf_allow'       => '',         // lines: /path/ param [rule]
			'waf_ban'         => 1,          // ban an address after 5 firewall blocks in 10 minutes.
			'extended'        => 0,
			'bf_on'           => 1,
			'bf_max_login'    => 20,
			'bf_max_reset'    => 20,
			'bf_window_min'   => 240,
			'bf_lock_hours'   => 4,
			'bf_invalid_lock' => 0,
			'bf_generic'      => 1,
			'strong_pw'       => 'admins',   // off | admins | all
			'breached_pw'     => 0,
			'crawler_per_min' => 0,
			'r404_human'      => 0,
			'r404_crawler'    => 0,
			'rate_action'     => 'throttle', // throttle | block
			'hide_version'    => 0,
			'xmlrpc'          => 'allow',    // allow | multicall | all
			'enum_block'      => 0,
			'rest_users'      => 0,
			'blank_post'      => 0,
		);
	}

	public static function all() {
		$o = get_option( self::OPTION, array() ); $d = self::defaults();
		return array_merge( $d, is_array( $o ) ? array_intersect_key( $o, $d ) : array() );
	}

	public static function get( $k ) { $a = self::all(); return $a[ $k ] ?? null; }

	/** The mode that applies right now (learning ends after a week). */
	public static function effective_mode() {
		$s = self::all();
		if ( 'learning' === $s['waf_mode'] && ! $s['waf_since'] ) { $s['waf_since'] = time(); update_option( self::OPTION, $s ); } // the week starts the first time the firewall runs.
		if ( 'learning' === $s['waf_mode'] && $s['waf_since'] && time() - (int) $s['waf_since'] > 7 * DAY_IN_SECONDS ) { return 'enabled'; }
		return $s['waf_mode'];
	}

	public static function sanitize( $in ) {
		$in = is_array( $in ) ? $in : array(); $old = self::all(); $o = array();
		$mode = in_array( $in['waf_mode'] ?? '', array( 'disabled', 'learning', 'enabled' ), true ) ? $in['waf_mode'] : 'learning';
		$o['waf_mode']  = $mode;
		$o['waf_since'] = ( 'learning' === $mode && 'learning' !== $old['waf_mode'] ) || ! $old['waf_since'] ? time() : $old['waf_since'];
		$ids = array_keys( Sidcraft_BotShield_Waf::rules() ); $on = (array) ( $in['waf_rules'] ?? array() );
		$o['waf_disabled'] = isset( $in['waf_rules_present'] ) ? array_values( array_diff( $ids, array_keys( array_filter( $on ) ) ) ) : $old['waf_disabled'];
		$lines = array();
		foreach ( preg_split( '/\R/', (string) ( $in['waf_allow'] ?? '' ) ) as $l ) { $l = trim( sanitize_text_field( $l ) ); if ( '' !== $l && preg_match( '#^(\*|/\S*)(\s+\S+){0,2}$#', $l ) && count( $lines ) < 300 ) { $lines[] = $l; } }
		$o['waf_allow'] = implode( "\n", array_unique( $lines ) );
		foreach ( array( 'waf_ban', 'bf_on', 'bf_invalid_lock', 'bf_generic', 'breached_pw', 'hide_version', 'enum_block', 'rest_users', 'blank_post' ) as $k ) { $o[ $k ] = empty( $in[ $k ] ) ? 0 : 1; }
		$o['extended'] = $old['extended'];
		$o['bf_max_login']  = max( 2, min( 500, (int) ( $in['bf_max_login'] ?? 20 ) ) );
		$o['bf_max_reset']  = max( 2, min( 500, (int) ( $in['bf_max_reset'] ?? 20 ) ) );
		$o['bf_window_min'] = max( 5, min( 1440, (int) ( $in['bf_window_min'] ?? 240 ) ) );
		$o['bf_lock_hours'] = max( 1, min( 720, (int) ( $in['bf_lock_hours'] ?? 4 ) ) );
		$o['strong_pw']     = in_array( $in['strong_pw'] ?? '', array( 'off', 'admins', 'all' ), true ) ? $in['strong_pw'] : 'admins';
		foreach ( array( 'crawler_per_min', 'r404_human', 'r404_crawler' ) as $k ) { $o[ $k ] = max( 0, min( 5000, (int) ( $in[ $k ] ?? 0 ) ) ); }
		$o['rate_action'] = 'block' === ( $in['rate_action'] ?? '' ) ? 'block' : 'throttle';
		$o['xmlrpc']      = in_array( $in['xmlrpc'] ?? '', array( 'allow', 'multicall', 'all' ), true ) ? $in['xmlrpc'] : 'allow';
		return $o;
	}
}
