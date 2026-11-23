<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

class Botvaguard_Guard {
	const TRAP = 'sidcraft-trap';

	public static function init() {
		add_action( 'init', array( __CLASS__, 'run' ), 0 );
		add_action( 'wp_login', array( __CLASS__, 'remember_admin_login' ), 5, 2 );
		add_action( 'admin_init', array( __CLASS__, 'remember_admin_visit' ) );
		add_filter( 'robots_txt', array( __CLASS__, 'robots' ), 50 );
		add_action( 'wp_footer', array( __CLASS__, 'trap_link' ), 99 );
	}

	/** An administrator's address is remembered for a week so that a rule can never lock the owner out. */
	public static function remember_admin( $ip ) {
		if ( '' !== $ip && Botvaguard_Settings::get( 'remember_admin' ) ) { set_transient( 'sbs_adm_' . md5( $ip ), 1, 7 * DAY_IN_SECONDS ); }
	}
	public static function is_admin_ip( $ip ) { return '' !== $ip && Botvaguard_Settings::get( 'remember_admin' ) && (bool) get_transient( 'sbs_adm_' . md5( $ip ) ); }
	public static function remember_admin_login( $login, $user ) { if ( $user instanceof WP_User && user_can( $user, 'manage_options' ) ) { self::remember_admin( self::client_ip() ); } }
	public static function remember_admin_visit() { if ( ! wp_doing_ajax() && current_user_can( 'manage_options' ) ) { $ip = self::client_ip(); if ( '' !== $ip && ! get_transient( 'sbs_adm_' . md5( $ip ) ) ) { self::remember_admin( $ip ); } } }

	/** The visitor's IP address. Proxy headers are only trusted when the owner chose so. */
	public static function client_ip() {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		$mode = Botvaguard_Settings::get( 'proxy' );
		$h = array( 'cloudflare' => 'HTTP_CF_CONNECTING_IP', 'xff' => 'HTTP_X_FORWARDED_FOR' );
		if ( isset( $h[ $mode ] ) && ! empty( $_SERVER[ $h[ $mode ] ] ) ) {
			$v = explode( ',', sanitize_text_field( wp_unslash( $_SERVER[ $h[ $mode ] ] ) ) );
			$v = trim( $v[0] );
			if ( filter_var( $v, FILTER_VALIDATE_IP ) ) { $ip = $v; }
		}
		return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '';
	}

	public static function ip_in_list( $ip, $list ) { return Botvaguard_Ranges::in_list( $ip, (array) $list ); }

	/** Visitor-side proxy hints: the request carries headers that only proxies add. */
	public static function has_proxy_headers() {
		foreach ( array( 'HTTP_VIA', 'HTTP_FORWARDED', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_FORWARDED_FOR', 'HTTP_X_PROXY_ID', 'HTTP_PROXY_CONNECTION', 'HTTP_X_FORWARDED_HOST' ) as $h ) { if ( ! empty( $_SERVER[ $h ] ) ) { return true; } }
		return false;
	}

	/**
	 * Country, address-list and VPN / proxy / Tor rules. Returns a reason code or ''.
	 *
	 * @param array<string,mixed> $r Request (ip, optional country, tor, proxy_headers, page).
	 */
	private static function network_rules( array $r, array $s ) {
		$ip = (string) $r['ip'];
		if ( '' === $ip ) { return ''; }
		if ( 'off' !== $s['geo_mode'] && $s['geo_countries'] ) {
			$c = array_key_exists( 'country', $r ) ? strtoupper( (string) $r['country'] ) : Botvaguard_Geo::country( $ip );
			$listed = in_array( $c, $s['geo_countries'], true );
			if ( '' === $c ) { if ( 'block' === $s['geo_unknown'] ) { return 'geo_unknown'; } }
			elseif ( 'block' === $s['geo_mode'] && $listed ) { return 'geo_blocked'; }
			elseif ( 'allow_only' === $s['geo_mode'] && ! $listed ) { return 'geo_not_allowed'; }
		}
		if ( ! empty( $s['block_tor'] ) && ( ! empty( $r['tor'] ) || Botvaguard_Lists::listed( 'tor', $ip ) || Botvaguard_Geo::cloudflare_tor() ) ) { return 'tor'; }
		if ( ! empty( $s['block_vpn'] ) && Botvaguard_Lists::listed( 'vpn', $ip ) ) { return 'vpn'; }
		if ( ! empty( $s['block_datacenter'] ) && Botvaguard_Lists::listed( 'datacenter', $ip ) ) { return 'datacenter'; }
		if ( ! empty( $s['block_proxy_headers'] ) && 'none' === $s['proxy'] && ( array_key_exists( 'proxy_headers', $r ) ? $r['proxy_headers'] : self::has_proxy_headers() ) ) { return 'proxy_header'; }
		if ( 'proxycheck' === $s['vpn_api'] && '' !== $s['vpn_api_key'] && ! empty( $r['page'] ) && Botvaguard_Api::is_proxy( $ip, $s['vpn_api_key'] ) ) { return 'vpn_api'; }
		return '';
	}

	/**
	 * Decide what to do with one request. Pure function of its input so it can be tested.
	 *
	 * @param array<string,mixed> $r ip, ua, path, method, logged_in, special (admin, ajax, cron, REST).
	 * @return array{action:string,reason:string,ban:bool}
	 */
	public static function decide( array $r ) {
		$s    = Botvaguard_Settings::all();
		$ip   = (string) $r['ip']; $ua = (string) $r['ua']; $ual = strtolower( $ua ); $path = (string) $r['path'];
		$ok   = array( 'action' => 'allow', 'reason' => '', 'ban' => false );
		$deny = function ( $reason, $ban = false ) { return array( 'action' => 'block', 'reason' => $reason, 'ban' => $ban ); };
		// 1. The owner's own addresses and this server itself.
		$trusted = Botvaguard_Settings::lines( 'ip_allow' );
		if ( apply_filters( 'sidcraft_botshield_trust_loopback', true ) ) { $trusted = array_merge( $trusted, array( '127.0.0.1', '::1' ) ); if ( ! empty( $_SERVER['SERVER_ADDR'] ) ) { $trusted[] = sanitize_text_field( wp_unslash( $_SERVER['SERVER_ADDR'] ) ); } }
		if ( '' !== $ip && self::ip_in_list( $ip, $trusted ) ) { return $ok; }
		// 1b. An address an administrator logged in from recently.
		if ( self::is_admin_ip( $ip ) ) { return $ok; }
		// 2. People who are logged in.
		if ( ! empty( $r['logged_in'] ) ) { return $ok; }
		// 3. Addresses that already misbehaved.
		if ( '' !== $ip && Botvaguard_Bans::is_banned( $ip ) ) { return $deny( 'banned' ); }
		// 3b. Addresses the owner blocked (IPv4, IPv6, ranges).
		if ( '' !== $ip && self::ip_in_list( $ip, Botvaguard_Settings::lines( 'ip_block' ) ) ) { return $deny( 'ip_blocked' ); }
		// 4. Paths only attackers and traps use.
		if ( ! empty( $s['honeypot'] ) && false !== strpos( strtolower( $path ), self::TRAP ) ) { return $deny( 'trap', true ); }
		if ( ! empty( $s['block_scanners'] ) && preg_match( Botvaguard_Catalog::scanner_regex(), $path ) ) { return $deny( 'scanner_path', true ); }
		// 5. Bots that are welcome.
		$welcome = array(); $group = array();
		foreach ( Botvaguard_Catalog::allowed() as $gk => $g ) { if ( ! empty( $s['allow'][ $gk ] ) ) { foreach ( $g['bots'] as $tok => $info ) { $welcome[ $tok ] = $info[1]; $group[ $tok ] = $gk; } } }
		foreach ( Botvaguard_Settings::lines( 'custom_allow' ) as $tok ) { $welcome[ $tok ] = null; }
		$custom_block = Botvaguard_Settings::lines( 'custom_block' );
		$blocked_by_owner = false; $welcome_hit = false;
		foreach ( $custom_block as $t ) { if ( false !== strpos( $ual, $t ) ) { $blocked_by_owner = true; } }
		if ( ! $blocked_by_owner ) {
			foreach ( $welcome as $tok => $suffixes ) {
				if ( '' === $tok || false === strpos( $ual, $tok ) ) { continue; }
				if ( ! empty( $s['verify'] ) && is_array( $suffixes ) && '' !== $ip && 'fail' === Botvaguard_Verify::check( $ip, $suffixes ) ) { return $deny( 'fake_bot' ); }
				if ( 'services' === ( $group[ $tok ] ?? '' ) || ! empty( $s['geo_bots_exempt'] ) || ! empty( $r['cron'] ) ) { return $ok; }
				$welcome_hit = true; break;
			}
		}
		// 5b. Country, VPN, proxy and Tor rules (not for wp-cron, which WordPress calls on itself).
		if ( empty( $r['cron'] ) ) {
			$r['page'] = empty( $r['special'] ) && in_array( strtoupper( (string) $r['method'] ), array( 'GET', 'HEAD' ), true );
			$why = self::network_rules( $r, $s );
			if ( '' !== $why ) { return $deny( $why ); }
		}
		if ( $welcome_hit ) { return $ok; }
		// 6. Unwanted bots (page requests only, so apps, forms and webhooks keep working).
		$method = strtoupper( (string) $r['method'] );
		if ( empty( $r['special'] ) && in_array( $method, array( 'GET', 'HEAD' ), true ) ) {
			if ( $blocked_by_owner ) { return $deny( 'custom_block' ); }
			foreach ( Botvaguard_Catalog::blocked() as $gk => $g ) {
				if ( empty( $s['block'][ $gk ] ) ) { continue; }
				foreach ( $g['tokens'] as $t ) { if ( false !== strpos( $ual, $t ) ) { return $deny( 'bad_bot_' . $gk ); } }
			}
			if ( ! empty( $s['block_empty'] ) && '' === trim( $ua ) ) { return $deny( 'empty_ua' ); }
		}
		// 7. Optional speed limit for everyone else.
		if ( ! empty( $s['rate_limit'] ) && '' !== $ip && empty( $r['special'] ) ) {
			$k = 'sbs_rate_' . md5( $ip ); $n = (int) get_transient( $k ) + 1; set_transient( $k, $n, MINUTE_IN_SECONDS );
			if ( $n > (int) $s['rate_per_min'] ) { return $deny( 'rate_limit' ); }
		}
		return $ok;
	}

	public static function run() {
		self::unlock_flow();
		$ip   = self::client_ip();
		$ua   = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? wp_parse_url( esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ), PHP_URL_PATH ) : '';
		$special = is_admin() || wp_doing_ajax() || wp_doing_cron() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) || ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) || ( defined( 'WP_CLI' ) && WP_CLI ) || false !== strpos( (string) $uri, '/wp-json/' ) || false !== strpos( (string) $uri, 'wp-login.php' );
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || 'cli' === PHP_SAPI ) { return; } // not a web request.
		$d = self::decide( array( 'ip' => $ip, 'ua' => $ua, 'path' => (string) $uri, 'method' => isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : 'GET', 'logged_in' => is_user_logged_in(), 'special' => $special, 'cron' => wp_doing_cron() ) );
		if ( 'block' !== $d['action'] ) { return; }
		$enforce = 'block' === Botvaguard_Settings::get( 'mode' );
		$skip_log = false;
		if ( 'banned' === $d['reason'] && '' !== $ip ) { $lk = 'sbs_blogged_' . md5( $ip ); $skip_log = (bool) get_transient( $lk ); if ( ! $skip_log ) { set_transient( $lk, 1, MINUTE_IN_SECONDS ); } }
		if ( ! $skip_log ) {
			Botvaguard_Log::add( $enforce ? 'block' : 'monitor', $d['reason'], $ip, $ua, (string) $uri, 'off' !== Botvaguard_Settings::get( 'geo_mode' ) ? Botvaguard_Geo::country( $ip ) : '' );
		}
		if ( ! $enforce ) { return; }
		if ( $d['ban'] && '' !== $ip ) { Botvaguard_Bans::add( $ip, (int) Botvaguard_Settings::get( 'ban_hours' ) * HOUR_IN_SECONDS, $d['reason'] ); }
		if ( 'rate_limit' !== $d['reason'] ) { self::banned_page( $ip, $d['reason'] ); }
		status_header( 429 );
		nocache_headers();
		header( 'X-Robots-Tag: noindex, nofollow' );
		if ( 'rate_limit' === $d['reason'] ) { header( 'Retry-After: 60' ); }
		header( 'Content-Type: text/plain; charset=UTF-8' );
		echo esc_html__( 'Access denied.', 'botvaguard' );
		exit;
	}

	/** Unlock link from the email, and the request form on the block page. Both work while the address is blocked. */
	private static function unlock_flow() {
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || 'cli' === PHP_SAPI ) { return; }
		if ( isset( $_GET['sbs_unlock'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- the signed link is the proof.
			$ip = Botvaguard_Notify::check_unlock( sanitize_text_field( wp_unslash( $_GET['sbs_unlock'] ) ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			status_header( $ip ? 200 : 403 ); nocache_headers(); header( 'Content-Type: text/html; charset=UTF-8' );
			if ( $ip ) { Botvaguard_Bans::remove( $ip ); set_transient( 'sbs_adm_' . md5( $ip ), 1, 7 * DAY_IN_SECONDS ); foreach ( array( 'sbs_nf_', 'sbs_lf_', 'sbs_fp_', 'sbs_wafn_', 'sbs_rate_' ) as $p ) { delete_transient( $p . md5( $ip ) ); } }
			echo '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>' . esc_html__( 'Unblock', 'botvaguard' ) . '</title></head><body style="font:16px/1.5 sans-serif;max-width:480px;margin:12vh auto;padding:0 16px"><p>' . esc_html( $ip ? sprintf( /* translators: %s: IP address */ __( 'The address %s is unblocked.', 'botvaguard' ), $ip ) : __( 'This unlock link is not valid any more.', 'botvaguard' ) ) . '</p><p><a href="' . esc_url( home_url( '/' ) ) . '">' . esc_html__( 'Go to the site', 'botvaguard' ) . '</a></p></body></html>';
			exit;
		}
		if ( isset( $_POST['sbs_unlock_request'] ) ) { $ip = self::client_ip(); if ( '' !== $ip ) { Botvaguard_Notify::request_unlock( $ip ); } } // phpcs:ignore WordPress.Security.NonceVerification.Missing -- visitors have no nonce; the action only emails the owner.
	}

	/** What a blocked address sees: a short message and a button that emails the site owner an unlock link. */
	public static function banned_page( $ip, $reason = 'banned' ) {
		status_header( 403 ); nocache_headers(); header( 'X-Robots-Tag: noindex, nofollow' ); header( 'Content-Type: text/html; charset=UTF-8' );
		$sent = isset( $_POST['sbs_unlock_request'] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- display only.
		echo '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>' . esc_html__( 'Access denied', 'botvaguard' ) . '</title></head><body style="font:16px/1.5 -apple-system,Segoe UI,sans-serif;max-width:520px;margin:12vh auto;padding:0 16px;color:#1d2327"><h1 style="font-size:22px">' . esc_html__( 'Access denied', 'botvaguard' ) . '</h1><p>' . esc_html( 'banned' === $reason ? __( 'Your address has been blocked because it sent too many suspicious requests.', 'botvaguard' ) : __( 'Your request was stopped by the security rules of this site.', 'botvaguard' ) ) . '</p>';
		if ( $sent ) { echo '<p style="background:#edfaef;border-left:4px solid #00a32a;padding:8px 12px">' . esc_html__( 'If you are the owner of this site, an unlock link was emailed to the site administrator.', 'botvaguard' ) . '</p>'; }
		else { echo '<p>' . esc_html__( 'If you are the owner of this site and blocked yourself, you can ask for an unlock link by email.', 'botvaguard' ) . '</p><form method="post"><input type="hidden" name="sbs_unlock_request" value="1"><button style="font:inherit;padding:8px 14px;cursor:pointer">' . esc_html__( 'Email me an unlock link', 'botvaguard' ) . '</button></form>'; }
		echo '<p style="color:#646970;font-size:13px">' . esc_html( $ip ) . ( defined( 'SIDCRAFT_BOTSHIELD_DEBUG' ) && SIDCRAFT_BOTSHIELD_DEBUG ? ' &middot; ' . esc_html( $reason ) : '' ) . '</p></body></html>';
		exit;
	}

	public static function robots( $out ) {
		if ( Botvaguard_Settings::get( 'honeypot' ) ) { $out .= "\nUser-agent: *\nDisallow: /" . self::TRAP . "/\n"; }
		return $out;
	}

	/** A link no person sees and no polite bot follows (robots.txt forbids it). Whoever opens it is a bad bot. */
	public static function trap_link() {
		if ( Botvaguard_Settings::get( 'honeypot' ) ) { echo '<a href="' . esc_url( home_url( '/' . self::TRAP . '/' ) ) . '" rel="nofollow noindex" aria-hidden="true" tabindex="-1" style="position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden">.</a>'; }
	}
}
