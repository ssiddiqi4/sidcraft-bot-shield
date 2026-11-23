<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

class Botvanguard_Settings {
	const OPTION = 'sidcraft_botshield_settings';

	public static function defaults() {
		return array(
			'mode'            => 'monitor', // monitor = log only; block = answer 403.
			'allow'           => array( 'search' => 1, 'ai' => 1, 'social' => 1, 'monitor' => 1, 'services' => 1 ),
			'verify'          => 1,        // prove that "Googlebot", "Bingbot", "Applebot"... are genuine through DNS.
			'block'           => array( 'seo' => 1, 'tools' => 1, 'attack' => 1 ),
			'block_empty'     => 1,
			'block_scanners'  => 1,
			'ban_hours'       => 24,
			'honeypot'        => 0,
			'rate_limit'      => 0,
			'rate_per_min'    => 120,
			'proxy'           => 'none',   // none | cloudflare | xff
			'custom_allow'    => '',
			'custom_block'    => '',
			'ip_allow'        => '',
			'remember_admin'  => 1,        // never block an address an administrator logged in from during the last 7 days.
			'ip_block'        => '',
			'geo_mode'        => 'off',    // off | block (listed countries) | allow_only (only listed countries).
			'geo_countries'   => array(),
			'geo_unknown'     => 'allow',  // what to do when the country cannot be found: allow | block.
			'geo_bots_exempt' => 1,        // welcome bots (Google, Bing, ChatGPT...) ignore the country and VPN rules.
			'block_tor'       => 0,
			'block_vpn'       => 0,
			'block_datacenter'=> 0,
			'block_proxy_headers' => 0,
			'vpn_api'         => 'none',   // none | proxycheck
			'vpn_api_key'     => '',
			'keep_log'        => 1,
			'remove_data'     => 0,
		);
	}

	public static function all() {
		$o = get_option( self::OPTION, array() );
		$d = self::defaults();
		$o = is_array( $o ) ? $o : array();
		$out = array_merge( $d, array_intersect_key( $o, $d ) );
		foreach ( array( 'allow', 'block' ) as $k ) { $out[ $k ] = array_merge( $d[ $k ], is_array( $o[ $k ] ?? null ) ? $o[ $k ] : array() ); }
		return $out;
	}

	public static function get( $key ) { $a = self::all(); return $a[ $key ] ?? null; }

	public static function sanitize( $in ) {
		$d   = self::defaults();
		$in  = is_array( $in ) ? $in : array();
		$out = array();
		$out['mode']   = ( isset( $in['mode'] ) && 'block' === $in['mode'] ) ? 'block' : 'monitor';
		$out['allow']  = array(); foreach ( $d['allow'] as $k => $v ) { $out['allow'][ $k ] = empty( $in['allow'][ $k ] ) ? 0 : 1; }
		$out['block']  = array(); foreach ( $d['block'] as $k => $v ) { $out['block'][ $k ] = empty( $in['block'][ $k ] ) ? 0 : 1; }
		foreach ( array( 'verify', 'block_empty', 'block_scanners', 'honeypot', 'rate_limit', 'keep_log', 'remove_data', 'geo_bots_exempt', 'remember_admin', 'block_tor', 'block_vpn', 'block_datacenter', 'block_proxy_headers' ) as $k ) { $out[ $k ] = empty( $in[ $k ] ) ? 0 : 1; }
		$out['ban_hours']    = max( 1, min( 720, (int) ( $in['ban_hours'] ?? 24 ) ) );
		$out['rate_per_min'] = max( 5, min( 5000, (int) ( $in['rate_per_min'] ?? 120 ) ) );
		$pr = $in['proxy'] ?? 'none'; $out['proxy'] = in_array( $pr, array( 'none', 'cloudflare', 'xff' ), true ) ? $pr : 'none';
		foreach ( array( 'custom_allow', 'custom_block' ) as $k ) { $out[ $k ] = self::clean_lines( $in[ $k ] ?? '', false ); }
		$out['ip_allow'] = self::clean_lines( $in['ip_allow'] ?? '', true );
		$out['ip_block'] = self::clean_lines( $in['ip_block'] ?? '', true );
		$gm = $in['geo_mode'] ?? 'off'; $out['geo_mode'] = in_array( $gm, array( 'off', 'block', 'allow_only' ), true ) ? $gm : 'off';
		$out['geo_countries'] = Botvanguard_Countries::clean( $in['geo_countries'] ?? array() );
		$out['geo_unknown']   = 'block' === ( $in['geo_unknown'] ?? 'allow' ) ? 'block' : 'allow';
		$out['vpn_api']       = 'proxycheck' === ( $in['vpn_api'] ?? 'none' ) ? 'proxycheck' : 'none';
		$out['vpn_api_key']   = preg_replace( '/[^A-Za-z0-9\-_]/', '', (string) ( $in['vpn_api_key'] ?? '' ) );
		if ( 'proxycheck' === $out['vpn_api'] && '' === $out['vpn_api_key'] ) { $out['vpn_api'] = 'none'; }
		return $out;
	}

	/** One entry per line; tokens are lowercased, IPs are validated. */
	private static function clean_lines( $text, $ips ) {
		$lines = array();
		foreach ( preg_split( '/[\r\n,]+/', (string) $text ) as $l ) {
			$l = trim( sanitize_text_field( $l ) );
			if ( '' === $l ) { continue; }
			if ( $ips ) { if ( Botvanguard_Ranges::parse( $l ) && count( $lines ) < 2000 ) { $lines[] = $l; } }
			else { $lines[] = strtolower( substr( $l, 0, 80 ) ); }
		}
		return implode( "\n", array_unique( $lines ) );
	}

	/** Replace the never-block list with the lines of a text (validated). */
	public static function set_allow( $text ) { $o = self::all(); $o['ip_allow'] = self::clean_lines( $text, true ); update_option( self::OPTION, $o ); }

	/** Is this address on the never-block list? */
	public static function is_allowed_ip( $ip ) { return '' !== $ip && Botvanguard_Ranges::in_list( $ip, self::lines( 'ip_allow' ) ); }

	/** Add a line to a list option (ip_allow, ip_block, custom_allow). An address on the never-block list cannot be added to the block list. */
	public static function add_line( $key, $line ) {
		if ( 'ip_block' === $key && self::is_allowed_ip( $line ) ) { return false; }
		$o = self::all(); $lines = self::lines( $key );
		if ( ! in_array( $line, $lines, true ) && count( $lines ) < 2000 ) { $lines[] = $line; }
		$o[ $key ] = implode( "\n", $lines ); update_option( self::OPTION, $o );
		return true;
	}

	public static function remove_line( $key, $line ) {
		$o = self::all(); $o[ $key ] = implode( "\n", array_diff( self::lines( $key ), array( $line ) ) ); update_option( self::OPTION, $o );
	}

	public static function lines( $key ) { return array_values( array_filter( array_map( 'trim', explode( "\n", (string) self::get( $key ) ) ) ) ); }
}
