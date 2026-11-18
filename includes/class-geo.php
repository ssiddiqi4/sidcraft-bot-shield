<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/** Which country is a visitor in? Uses what your host or CDN already tells us, then an optional country database file. */
class Sidcraft_BotShield_Geo {
	private static $db = false;

	/** Look an address up in the country database file only (no request headers). */
	public static function from_db( $ip ) {
		if ( false === self::$db ) { self::$db = Sidcraft_BotShield_Lists::mmdb_exists() ? Sidcraft_BotShield_Mmdb::open( Sidcraft_BotShield_Lists::mmdb_path() ) : null; }
		return self::$db ? self::$db->country( $ip ) : '';
	}

	public static function reset() { self::$db = false; }

	/** Two-letter code and where it came from, e.g. array( 'DE', 'Cloudflare' ). Empty code = unknown. */
	public static function detect( $ip ) {
		$proxy = Sidcraft_BotShield_Settings::get( 'proxy' );
		$sources = array( array( 'GEOIP_COUNTRY_CODE', __( 'server', 'sidcraft-bot-shield' ) ) ); // set by the web server itself, never by the visitor.
		if ( 'cloudflare' === $proxy ) { $sources[] = array( 'HTTP_CF_IPCOUNTRY', 'Cloudflare' ); }
		if ( 'xff' === $proxy ) { $sources[] = array( 'HTTP_CLOUDFRONT_VIEWER_COUNTRY', 'CloudFront' ); $sources[] = array( 'HTTP_GEOIP_COUNTRY_CODE', __( 'proxy', 'sidcraft-bot-shield' ) ); }
		foreach ( $sources as $s ) {
			if ( ! empty( $_SERVER[ $s[0] ] ) ) {
				$c = strtoupper( sanitize_text_field( wp_unslash( $_SERVER[ $s[0] ] ) ) );
				if ( preg_match( '/^[A-Z]{2}$/', $c ) && ! in_array( $c, array( 'XX', 'T1' ), true ) ) { return array( $c, $s[1] ); }
			}
		}
		$c = self::from_db( $ip );
		return array( $c, '' === $c ? '' : __( 'country database', 'sidcraft-bot-shield' ) );
	}

	/** Cloudflare marks Tor visitors with the pseudo country T1. */
	public static function cloudflare_tor() {
		return 'cloudflare' === Sidcraft_BotShield_Settings::get( 'proxy' ) && isset( $_SERVER['HTTP_CF_IPCOUNTRY'] ) && 'T1' === strtoupper( sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_IPCOUNTRY'] ) ) );
	}

	public static function country( $ip ) {
		$c = apply_filters( 'sidcraft_botshield_country', null, $ip );
		if ( is_string( $c ) ) { return strtoupper( $c ); }
		$d = self::detect( $ip );
		return $d[0];
	}
}
