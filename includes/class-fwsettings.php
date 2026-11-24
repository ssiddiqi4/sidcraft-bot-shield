<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/** Settings for the firewall tab (kept apart from the bot settings so that each tab saves on its own). */
class Botvanguard_FwSettings {
	const OPTION = 'sidcraft_botshield_fw';

	public static function defaults() {
		return array(
			'waf_mode'        => 'learning', // disabled | learning | enabled. Learning turns into enabled after 7 days.
			'waf_since'       => 0,
			'waf_disabled'    => array(),    // rule ids switched off.
			'waf_allow'       => '',         // lines: /path/ param [rule]
			'waf_ban'         => 1,          // ban an address after 5 firewall blocks in 10 minutes.
			'bf_on'           => 1,
			'bf_max_login'    => 20,
			'bf_max_reset'    => 20,
			'bf_window_min'   => 240,
			'bf_lock_hours'   => 4,
			'user_on'         => 0,          // block an address that logs in with user names that do not exist.
			'user_attempts'   => 3,
			'user_minutes'    => 10,
			'user_days'       => 1,          // 0 = block for good.
			'probe_on'        => 0,          // block an address that keeps opening login / register pages without logging in.
			'probe_attempts'  => 5,
			'probe_minutes'   => 10,
			'probe_days'      => 1,
			'bf_invalid_lock' => 0,
			'bf_generic'      => 1,
			'strong_pw'       => 'admins',   // off | admins | all
			'breached_pw'     => 0,
			'crawler_per_min' => 0,
			'nf_on'           => 1,          // block addresses that keep asking for pages that do not exist.
			'nf_count'        => 15,
			'nf_minutes'      => 2,
			'nf_days'         => 7,          // 0 = block for good.
			'fb_on'           => 0,          // refuse and block an address that asks for a forbidden file name or word.
			'fb_list'         => '',         // one name or word per line, for example backup.tar.gz
			'fb_days'         => 0,          // 0 = block for good.
			'nf_exempt'       => "favicon.ico\napple-touch-icon\nrobots.txt\n.well-known\nsitemap",
			'notify_mode'     => 'nf',       // off | nf (missing-pages blocks) | all (every automatic block).
			'notify_email'    => '',
			'notify_cap'      => 20,
			'rate_action'     => 'throttle', // throttle | block
			'hide_version'    => 0,
			'xmlrpc'          => 'allow',    // allow | multicall | all
			'enum_block'      => 0,
			'rest_users'      => 0,
			'blank_post'      => 0,
			'rest_mode'       => 'allow',    // allow | monitor (log only) | login (visitors who are not logged in may only use the allow list).
			'rest_allow'      => "oembed/1.0\nsidcraft-vs/v1\nsidcraft-page-builder/v1/form\nsidcraft-page-builder/v1/mcp\nsidcraft-page-builder/v1/schema\ncontact-form-7/\nwc/store\njetpack/",
			'rest_block'      => '',         // routes always closed to visitors who are not logged in.
			'rest_rate'       => 0,          // requests a minute from one address for visitors who are not logged in (0 = off).
			'rest_auth'       => 1,          // count failed REST logins (application passwords) as failed logins.
			'core_xmlrpc'     => 0,          // refuse direct requests to xmlrpc.php.
			'core_settings'   => 0,          // refuse direct requests to wp-settings.php.
			'core_config'     => 0,          // refuse direct requests to wp-config.php.
		);
	}

	public static function all() {
		$o = get_option( self::OPTION, array() ); $d = self::defaults();
		if ( is_array( $o ) && ! isset( $o['user_on'] ) && ! empty( $o['bf_invalid_lock'] ) ) { $o['user_on'] = 1; $o['user_attempts'] = 1; } // the old "lock out at once" tick box.
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
		$ids = array_keys( Botvanguard_Waf::rules() ); $on = (array) ( $in['waf_rules'] ?? array() );
		$o['waf_disabled'] = isset( $in['waf_rules_present'] ) ? array_values( array_diff( $ids, array_keys( array_filter( $on ) ) ) ) : $old['waf_disabled'];
		$lines = array();
		foreach ( preg_split( '/\R/', (string) ( $in['waf_allow'] ?? '' ) ) as $l ) { $l = trim( sanitize_text_field( $l ) ); if ( '' !== $l && preg_match( '#^(\*|/\S*)(\s+\S+){0,2}$#', $l ) && count( $lines ) < 300 ) { $lines[] = $l; } }
		$o['waf_allow'] = implode( "\n", array_unique( $lines ) );
		foreach ( array( 'waf_ban', 'bf_on', 'user_on', 'probe_on', 'bf_generic', 'breached_pw', 'hide_version', 'enum_block', 'rest_users', 'blank_post', 'core_xmlrpc', 'core_settings', 'core_config', 'rest_auth' ) as $k ) { $o[ $k ] = empty( $in[ $k ] ) ? 0 : 1; }
		$o['bf_invalid_lock'] = 0;
		foreach ( array( 'user', 'probe' ) as $p ) {
			$o[ $p . '_attempts' ] = max( 1, min( 100, (int) ( $in[ $p . '_attempts' ] ?? 5 ) ) );
			$o[ $p . '_minutes' ]  = max( 1, min( 1440, (int) ( $in[ $p . '_minutes' ] ?? 10 ) ) );
			$o[ $p . '_days' ]     = max( 0, min( 3650, (int) ( $in[ $p . '_days' ] ?? 1 ) ) );
		}
		$o['bf_max_login']  = max( 2, min( 500, (int) ( $in['bf_max_login'] ?? 20 ) ) );
		$o['bf_max_reset']  = max( 2, min( 500, (int) ( $in['bf_max_reset'] ?? 20 ) ) );
		$o['bf_window_min'] = max( 5, min( 1440, (int) ( $in['bf_window_min'] ?? 240 ) ) );
		$o['bf_lock_hours'] = max( 1, min( 720, (int) ( $in['bf_lock_hours'] ?? 4 ) ) );
		$sp = $in['strong_pw'] ?? ''; $o['strong_pw'] = in_array( $sp, array( 'off', 'admins', 'all' ), true ) ? $sp : 'admins';
		$o['crawler_per_min'] = max( 0, min( 5000, (int) ( $in['crawler_per_min'] ?? 0 ) ) );
		$o['fb_on']      = empty( $in['fb_on'] ) ? 0 : 1;
		$o['fb_days']    = max( 0, min( 3650, (int) ( $in['fb_days'] ?? 0 ) ) );
		$fb = array(); foreach ( preg_split( '/\R/', (string) ( $in['fb_list'] ?? '' ) ) as $l ) { $l = strtolower( trim( sanitize_text_field( $l ) ) ); if ( strlen( $l ) >= 3 && strlen( $l ) <= 120 && count( $fb ) < 300 ) { $fb[] = $l; } }
		$o['fb_list']    = implode( "\n", array_unique( $fb ) );
		$o['nf_on']      = empty( $in['nf_on'] ) ? 0 : 1;
		$o['nf_count']   = max( 3, min( 1000, (int) ( $in['nf_count'] ?? 15 ) ) );
		$o['nf_minutes'] = max( 1, min( 1440, (int) ( $in['nf_minutes'] ?? 2 ) ) );
		$o['nf_days']    = max( 0, min( 3650, (int) ( $in['nf_days'] ?? 7 ) ) );
		$ex = array(); foreach ( preg_split( '/\R/', (string) ( $in['nf_exempt'] ?? '' ) ) as $l ) { $l = trim( sanitize_text_field( $l ) ); if ( '' !== $l && count( $ex ) < 100 ) { $ex[] = $l; } }
		$o['nf_exempt']  = implode( "\n", $ex );
		$nm = $in['notify_mode'] ?? 'nf'; $o['notify_mode'] = in_array( $nm, array( 'off', 'nf', 'all' ), true ) ? $nm : 'nf';
		$o['notify_email'] = ( isset( $in['notify_email'] ) && is_email( $in['notify_email'] ) ) ? sanitize_email( $in['notify_email'] ) : '';
		$o['notify_cap']  = max( 0, min( 500, (int) ( $in['notify_cap'] ?? 20 ) ) );
		$o['rate_action'] = 'block' === ( $in['rate_action'] ?? '' ) ? 'block' : 'throttle';
		$rm = $in['rest_mode'] ?? ''; $o['rest_mode'] = in_array( $rm, array( 'allow', 'monitor', 'login' ), true ) ? $rm : 'allow';
		foreach ( array( 'rest_allow', 'rest_block' ) as $k ) {
			$lines = array(); foreach ( preg_split( '/\R/', (string) ( $in[ $k ] ?? '' ) ) as $l ) { $l = trim( sanitize_text_field( $l ) ); if ( '' !== $l && preg_match( '#^/?[A-Za-z0-9_\-./]+$#', $l ) && count( $lines ) < 100 ) { $lines[] = $l; } }
			$o[ $k ] = implode( "\n", array_unique( $lines ) );
		}
		$o['rest_rate'] = max( 0, min( 5000, (int) ( $in['rest_rate'] ?? 0 ) ) );
		$xr = $in['xmlrpc'] ?? ''; $o['xmlrpc'] = in_array( $xr, array( 'allow', 'multicall', 'all' ), true ) ? $xr : 'allow';
		return $o;
	}
}
