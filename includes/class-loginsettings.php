<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/** Settings of the Login tab: two-factor login and the custom login address. */
class Sidcraft_BotShield_LoginSettings {
	const OPTION = 'sidcraft_botshield_login';

	public static function defaults() {
		return array(
			'tfa_on' => 0, 'tfa_roles' => array( 'administrator' ), 'tfa_grace' => 7, 'tfa_since' => 0,
			'tfa_email' => 1, 'tfa_totp' => 1, 'tfa_sms' => 0, 'tfa_passkey' => 1,
			'twilio_sid' => '', 'twilio_token' => '', 'twilio_from' => '',
			'url_on' => 0, 'url_slug' => '', 'url_redirect' => '404', 'url_custom' => '',
			'url_block' => 1, 'url_attempts' => 5, 'url_minutes' => 10, 'url_days' => 1,
		);
	}

	public static function all() { $o = get_option( self::OPTION, array() ); $d = self::defaults(); return array_merge( $d, is_array( $o ) ? array_intersect_key( $o, $d ) : array() ); }
	public static function get( $k ) { $a = self::all(); return $a[ $k ] ?? null; }

	public static function reserved() { return array( 'wp-admin', 'wp-login', 'wp-login.php', 'wp-content', 'wp-includes', 'wp-json', 'feed', 'rss', 'atom', 'wp-cron', 'xmlrpc', 'wp-signup', 'wp-activate', 'wp-register', 'index', 'sitemap', 'robots', 'favicon' ); }

	public static function clean_slug( $s ) { $s = strtolower( trim( (string) $s, " \t\n\r/" ) ); return preg_match( '/^[a-z0-9][a-z0-9_-]{2,39}$/', $s ) && ! in_array( $s, self::reserved(), true ) ? $s : ''; }

	public static function methods_enabled() { $s = self::all(); $m = array(); foreach ( array( 'email', 'totp', 'sms', 'passkey' ) as $k ) { if ( ! empty( $s[ 'tfa_' . $k ] ) ) { if ( 'sms' === $k && ( '' === $s['twilio_sid'] || '' === $s['twilio_token'] || '' === $s['twilio_from'] ) ) { continue; } $m[] = $k; } } return $m; }

	public static function sanitize( $in ) {
		$in = is_array( $in ) ? $in : array(); $old = self::all(); $o = array();
		$o['tfa_on'] = empty( $in['tfa_on'] ) ? 0 : 1;
		$roles = array_keys( wp_roles()->get_names() ); $o['tfa_roles'] = array_values( array_intersect( $roles, array_map( 'sanitize_key', (array) ( $in['tfa_roles'] ?? array() ) ) ) );
		$o['tfa_grace'] = max( 0, min( 90, (int) ( $in['tfa_grace'] ?? 7 ) ) );
		$o['tfa_since'] = $o['tfa_on'] && ! $old['tfa_on'] ? time() : ( $old['tfa_since'] ?: ( $o['tfa_on'] ? time() : 0 ) );
		foreach ( array( 'tfa_email', 'tfa_totp', 'tfa_sms', 'tfa_passkey' ) as $k ) { $o[ $k ] = empty( $in[ $k ] ) ? 0 : 1; }
		if ( ! $o['tfa_on'] ) { $o['tfa_since'] = 0; }
		$o['twilio_sid']   = preg_replace( '/[^A-Za-z0-9]/', '', (string) ( $in['twilio_sid'] ?? '' ) );
		$o['twilio_token'] = '' === trim( (string) ( $in['twilio_token'] ?? '' ) ) ? $old['twilio_token'] : preg_replace( '/[^A-Za-z0-9]/', '', (string) $in['twilio_token'] );
		$o['twilio_from']  = preg_replace( '/[^0-9+]/', '', (string) ( $in['twilio_from'] ?? '' ) );
		$o['url_on'] = empty( $in['url_on'] ) ? 0 : 1;
		$o['url_slug'] = self::clean_slug( $in['url_slug'] ?? '' );
		if ( '' === $o['url_slug'] ) { $o['url_on'] = 0; }
		$ur = $in['url_redirect'] ?? '404'; $o['url_redirect'] = in_array( $ur, array( '404', 'home', 'custom' ), true ) ? $ur : '404';
		$o['url_custom'] = esc_url_raw( (string) ( $in['url_custom'] ?? '' ) );
		if ( 'custom' === $o['url_redirect'] && '' === $o['url_custom'] ) { $o['url_redirect'] = '404'; }
		$o['url_block']    = empty( $in['url_block'] ) ? 0 : 1;
		$o['url_attempts'] = max( 1, min( 100, (int) ( $in['url_attempts'] ?? 5 ) ) );
		$o['url_minutes']  = max( 1, min( 1440, (int) ( $in['url_minutes'] ?? 10 ) ) );
		$o['url_days']     = max( 0, min( 3650, (int) ( $in['url_days'] ?? 1 ) ) );
		return $o;
	}
}
