<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

// phpcs:disable WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput, WordPress.WP.AlternativeFunctions -- a firewall reads the raw request; local files are the firewall's own.

/** The advanced firewall: rule engine, login protection, rate limits, hardening and optional extended protection. */
class Sidcraft_BotShield_Firewall {
	const MARK = 'Sidcraft Bot Shield Firewall';

	public static function init() {
		add_action( 'init', array( __CLASS__, 'run' ), 1 );
		add_action( 'template_redirect', array( __CLASS__, 'on_404' ), 1 );
		$s = Sidcraft_BotShield_FwSettings::all();
		if ( $s['bf_on'] ) {
			add_action( 'wp_login_failed', array( __CLASS__, 'login_failed' ), 10, 2 );
			add_action( 'lostpassword_post', array( __CLASS__, 'reset_request' ), 10, 1 );
		}
		if ( $s['bf_generic'] ) { add_filter( 'authenticate', array( __CLASS__, 'generic_error' ), 100, 1 ); }
		if ( 'off' !== $s['strong_pw'] ) {
			add_action( 'user_profile_update_errors', array( __CLASS__, 'check_profile_pw' ), 10, 3 );
			add_action( 'validate_password_reset', array( __CLASS__, 'check_reset_pw' ), 10, 2 );
		}
		if ( $s['breached_pw'] ) { add_filter( 'wp_authenticate_user', array( __CLASS__, 'breached_login' ), 20, 2 ); }
		if ( $s['hide_version'] ) {
			remove_action( 'wp_head', 'wp_generator' ); add_filter( 'the_generator', '__return_empty_string' );
			add_filter( 'style_loader_src', array( __CLASS__, 'strip_ver' ), 20 ); add_filter( 'script_loader_src', array( __CLASS__, 'strip_ver' ), 20 );
		}
		if ( 'all' === $s['xmlrpc'] ) { add_filter( 'xmlrpc_enabled', '__return_false' ); }
		if ( 'multicall' === $s['xmlrpc'] ) { add_filter( 'xmlrpc_methods', array( __CLASS__, 'no_multicall' ) ); }
		if ( $s['rest_users'] ) { add_filter( 'rest_endpoints', array( __CLASS__, 'hide_rest_users' ) ); }
		add_action( 'admin_init', array( __CLASS__, 'import_waf_log' ) );
		Sidcraft_BotShield_Notify::init();
	}

	private static function ip() { return Sidcraft_BotShield_Guard::client_ip(); }
	private static function ua() { return isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : ''; }
	private static function path() { $u = isset( $_SERVER['REQUEST_URI'] ) ? wp_parse_url( esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ), PHP_URL_PATH ) : ''; return (string) $u; }

	private static function trusted( $ip ) {
		if ( '' === $ip ) { return false; }
		$t = Sidcraft_BotShield_Settings::lines( 'ip_allow' );
		if ( apply_filters( 'sidcraft_botshield_trust_loopback', true ) ) { $t = array_merge( $t, array( '127.0.0.1', '::1' ) ); }
		return Sidcraft_BotShield_Ranges::in_list( $ip, $t );
	}

	private static function deny( $reason, $status = 403, $retry = 0 ) {
		status_header( $status ); nocache_headers(); header( 'X-Robots-Tag: noindex, nofollow' );
		if ( $retry ) { header( 'Retry-After: ' . (int) $retry ); }
		header( 'Content-Type: text/plain; charset=UTF-8' );
		echo esc_html( 429 === $status ? __( 'Too many requests. Please slow down.', 'sidcraft-bot-shield' ) : __( 'Blocked by the Sidcraft Bot Shield firewall.', 'sidcraft-bot-shield' ) );
		exit;
	}

	// ---- Rule engine in WordPress ----
	public static function run() {
		if ( 'cli' === PHP_SAPI || ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() ) { return; }
		$s = Sidcraft_BotShield_FwSettings::all(); $ip = self::ip(); $ua = self::ua(); $path = self::path();
		if ( '' !== $ip && self::trusted( $ip ) ) { return; }
		$logged = is_user_logged_in(); $admin = $logged && current_user_can( 'manage_options' );
		// Simple hardening checks that need no rules.
		if ( ! $logged ) {
			if ( $s['enum_block'] && isset( $_GET['author'] ) && '' !== (string) $_GET['author'] && preg_match( '/^\d+$/', (string) wp_unslash( $_GET['author'] ) ) ) { self::hit( 'enum_author', $ip, $ua, $path, 'enum' ); }
			if ( $s['blank_post'] && 'POST' === ( $_SERVER['REQUEST_METHOD'] ?? '' ) && '' === $ua && empty( $_SERVER['HTTP_REFERER'] ) ) { self::hit( 'blank_post', $ip, $ua, $path, 'blank' ); }
			self::crawler_rate( $s, $ip, $ua, $path );
		}
		$mode = Sidcraft_BotShield_FwSettings::effective_mode();
		if ( 'disabled' === $mode || defined( 'SIDCRAFT_BOTSHIELD_WAF_DONE' ) ) { return; }
		$files = array();
		foreach ( $_FILES as $f ) { if ( is_array( $f ) && isset( $f['name'] ) && ! is_array( $f['name'] ) ) { $files[ (string) $f['name'] ] = (string) ( $f['tmp_name'] ?? '' ); } }
		$cookies = $_COOKIE; foreach ( array_keys( $cookies ) as $k ) { if ( 0 === strpos( (string) $k, 'wordpress_' ) || 0 === strpos( (string) $k, 'wp-settings' ) ) { unset( $cookies[ $k ] ); } }
		$req = array( 'path' => $path, 'get' => wp_unslash( $_GET ), 'post' => wp_unslash( $_POST ), 'cookies' => wp_unslash( $cookies ), 'files' => $files,
			'headers' => array( 'user-agent' => $ua, 'referer' => isset( $_SERVER['HTTP_REFERER'] ) ? wp_unslash( $_SERVER['HTTP_REFERER'] ) : '', 'x-forwarded-for' => isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ? wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) : '' ) );
		$hit = Sidcraft_BotShield_Waf::inspect( $req, array( 'disabled' => $s['waf_disabled'], 'allow' => preg_split( '/\R/', (string) $s['waf_allow'], -1, PREG_SPLIT_NO_EMPTY ) ) );
		if ( ! $hit ) { return; }
		if ( $admin ) { // Administrators are never blocked; in learning mode their requests teach the firewall what is normal.
			if ( 'learning' === $mode ) { self::learn( $path, $hit ); }
			return;
		}
		Sidcraft_BotShield_Log::add( 'enabled' === $mode ? 'block' : 'monitor', 'waf_' . $hit['rule'], $ip, $ua, $path . ( '' !== $hit['param'] ? '  [' . substr( $hit['param'], 0, 40 ) . ']' : '' ) );
		if ( 'enabled' !== $mode ) { return; }
		if ( $s['waf_ban'] && '' !== $ip ) {
			$k = 'sbs_wafn_' . md5( $ip ); $n = (int) get_transient( $k ) + 1; set_transient( $k, $n, 10 * MINUTE_IN_SECONDS );
			if ( $n >= 5 ) { Sidcraft_BotShield_Bans::add( $ip, (int) Sidcraft_BotShield_Settings::get( 'ban_hours' ) * HOUR_IN_SECONDS, 'Repeated firewall blocks' ); }
		}
		self::deny( 'waf' );
	}

	/** Remember that an administrator legitimately sent this parameter here. */
	private static function learn( $path, $hit ) {
		$base = preg_replace( '/\[.*$/', '', $hit['param'] );
		if ( '' === $base || 'upload_php' === $hit['rule'] ) { return; }
		$s = Sidcraft_BotShield_FwSettings::all(); $lines = preg_split( '/\R/', (string) $s['waf_allow'], -1, PREG_SPLIT_NO_EMPTY );
		$line = $path . ' ' . $base . ' ' . $hit['rule'];
		if ( ! in_array( $line, $lines, true ) && count( $lines ) < 300 ) { $lines[] = $line; $s['waf_allow'] = implode( "\n", $lines ); update_option( Sidcraft_BotShield_FwSettings::OPTION, $s ); }
	}

	/** Log (and block) a simple rule hit. */
	private static function hit( $reason, $ip, $ua, $path, $kind ) {
		Sidcraft_BotShield_Log::add( 'block', $reason, $ip, $ua, $path );
		self::deny( $kind );
	}

	// ---- Login protection ----
	private static function count_fail( $prefix, $ip, $window_min ) {
		$k = $prefix . md5( $ip ); $d = get_transient( $k );
		if ( ! is_array( $d ) ) { $d = array( 'n' => 0, 'until' => time() + $window_min * MINUTE_IN_SECONDS ); }
		$d['n']++; set_transient( $k, $d, max( 60, $d['until'] - time() ) );
		return $d['n'];
	}

	public static function login_failed( $username ) {
		$ip = self::ip(); if ( '' === $ip || self::trusted( $ip ) ) { return; }
		$s = Sidcraft_BotShield_FwSettings::all();
		$invalid = $s['bf_invalid_lock'] && '' !== (string) $username && ! username_exists( (string) $username ) && ! email_exists( (string) $username );
		$n = self::count_fail( 'sbs_lf_', $ip, (int) $s['bf_window_min'] );
		if ( $invalid || $n >= (int) $s['bf_max_login'] ) {
			Sidcraft_BotShield_Bans::add( $ip, (int) $s['bf_lock_hours'] * HOUR_IN_SECONDS, $invalid ? 'Login with a user that does not exist' : 'Too many failed logins' );
			Sidcraft_BotShield_Log::add( 'block', $invalid ? 'brute_invalid' : 'brute_login', $ip, self::ua(), self::path() );
		}
	}

	public static function reset_request() {
		$ip = self::ip(); if ( '' === $ip || self::trusted( $ip ) ) { return; }
		$s = Sidcraft_BotShield_FwSettings::all();
		if ( self::count_fail( 'sbs_fp_', $ip, (int) $s['bf_window_min'] ) >= (int) $s['bf_max_reset'] ) {
			Sidcraft_BotShield_Bans::add( $ip, (int) $s['bf_lock_hours'] * HOUR_IN_SECONDS, 'Too many password reset requests' );
			Sidcraft_BotShield_Log::add( 'block', 'brute_reset', $ip, self::ua(), self::path() );
		}
	}

	/** Same message for a wrong user name and a wrong password, so that user names cannot be guessed. */
	public static function generic_error( $user ) {
		if ( is_wp_error( $user ) && array_intersect( array( 'invalid_username', 'invalid_email', 'incorrect_password' ), $user->get_error_codes() ) ) {
			return new WP_Error( 'authentication_failed', __( '<strong>Error:</strong> the user name or password is not correct.', 'sidcraft-bot-shield' ) );
		}
		return $user;
	}

	// ---- Passwords ----
	public static function common_passwords() {
		return array( 'password', 'password1', 'password123', '123456', '1234567', '12345678', '123456789', '1234567890', 'qwerty', 'qwerty123', 'qwertyuiop', 'abc123', 'letmein', 'welcome', 'welcome1', 'admin', 'admin123', 'administrator', 'iloveyou', 'monkey', 'dragon', 'football', 'baseball', 'master', 'sunshine', 'princess', 'login', 'passw0rd', 'p@ssw0rd', 'changeme', 'wordpress', 'trustno1', '111111', '000000', '121212', '654321', 'superman', 'michael', 'shadow', 'whatever' );
	}

	/** Why a password is too weak, or '' when it is fine. */
	public static function weak_reason( $pw, $login = '', $email = '' ) {
		if ( strlen( $pw ) < 12 ) { return __( 'use at least 12 characters', 'sidcraft-bot-shield' ); }
		$l = strtolower( $pw );
		foreach ( self::common_passwords() as $c ) { if ( strlen( $c ) >= 4 && false !== strpos( $l, $c ) && strlen( $pw ) < strlen( $c ) + 8 ) { return __( 'do not use a common password', 'sidcraft-bot-shield' ); } }
		if ( '' !== $login && false !== strpos( $l, strtolower( $login ) ) && strlen( $login ) >= 4 ) { return __( 'do not include your user name', 'sidcraft-bot-shield' ); }
		$local = '' !== $email ? strtolower( strstr( $email, '@', true ) ) : '';
		if ( strlen( $local ) >= 4 && false !== strpos( $l, $local ) ) { return __( 'do not include your email name', 'sidcraft-bot-shield' ); }
		$classes = (int) preg_match( '/[a-z]/', $pw ) + (int) preg_match( '/[A-Z]/', $pw ) + (int) preg_match( '/\d/', $pw ) + (int) preg_match( '/[^A-Za-z0-9]/', $pw );
		if ( $classes < 3 ) { return __( 'mix upper and lower case letters, numbers and symbols', 'sidcraft-bot-shield' ); }
		if ( preg_match( '/^(.)\1+$/', $pw ) ) { return __( 'do not repeat one character', 'sidcraft-bot-shield' ); }
		return '';
	}

	private static function needs_strong( $user_roles ) {
		$mode = Sidcraft_BotShield_FwSettings::get( 'strong_pw' );
		return 'all' === $mode || ( 'admins' === $mode && array_intersect( (array) $user_roles, array( 'administrator', 'editor', 'shop_manager' ) ) );
	}

	public static function check_profile_pw( $errors, $update, $user ) {
		if ( empty( $user->user_pass ) ) { return; }
		$roles = isset( $user->role ) && '' !== $user->role ? array( $user->role ) : ( ! empty( $user->ID ) ? (array) get_userdata( $user->ID )->roles : array() );
		if ( ! self::needs_strong( $roles ) ) { return; }
		$why = self::weak_reason( (string) $user->user_pass, (string) ( $user->user_login ?? '' ), (string) ( $user->user_email ?? '' ) );
		if ( '' !== $why ) { $errors->add( 'sbs_weak_pw', sprintf( /* translators: %s: advice */ __( '<strong>Error:</strong> this password is too weak: %s.', 'sidcraft-bot-shield' ), $why ) ); }
		elseif ( Sidcraft_BotShield_FwSettings::get( 'breached_pw' ) && self::breached( (string) $user->user_pass ) ) { $errors->add( 'sbs_breached_pw', __( '<strong>Error:</strong> this password appeared in a known data breach. Choose another one.', 'sidcraft-bot-shield' ) ); }
	}

	public static function check_reset_pw( $errors, $user ) {
		$pw = isset( $_POST['pass1'] ) ? (string) wp_unslash( $_POST['pass1'] ) : '';
		if ( '' === $pw || ! $user || ! self::needs_strong( $user->roles ) ) { return; }
		$why = self::weak_reason( $pw, $user->user_login, $user->user_email );
		if ( '' !== $why ) { $errors->add( 'sbs_weak_pw', sprintf( /* translators: %s: advice */ __( '<strong>Error:</strong> this password is too weak: %s.', 'sidcraft-bot-shield' ), $why ) ); }
		elseif ( Sidcraft_BotShield_FwSettings::get( 'breached_pw' ) && self::breached( $pw ) ) { $errors->add( 'sbs_breached_pw', __( '<strong>Error:</strong> this password appeared in a known data breach. Choose another one.', 'sidcraft-bot-shield' ) ); }
	}

	/** Has this password appeared in a breach? Only the first 5 characters of its SHA-1 hash leave the site. Fails open. */
	public static function breached( $pw ) {
		$h = strtoupper( sha1( $pw ) ); $pre = substr( $h, 0, 5 ); $suf = substr( $h, 5 );
		$k = 'sbs_pwn_' . $pre; $body = get_transient( $k );
		if ( false === $body ) {
			$r = wp_safe_remote_get( 'https://api.pwnedpasswords.com/range/' . $pre, array( 'timeout' => 3, 'headers' => array( 'Add-Padding' => 'true' ) ) );
			if ( is_wp_error( $r ) || 200 !== (int) wp_remote_retrieve_response_code( $r ) ) { return false; }
			$body = (string) wp_remote_retrieve_body( $r ); set_transient( $k, $body, DAY_IN_SECONDS );
		}
		foreach ( preg_split( '/\R/', $body ) as $line ) { $p = explode( ':', trim( $line ) ); if ( 2 === count( $p ) && $p[0] === $suf && (int) $p[1] > 0 ) { return true; } }
		return false;
	}

	/** Administrators whose password is in a breach cannot log in until they reset it. */
	public static function breached_login( $user, $password ) {
		if ( is_wp_error( $user ) || ! $user instanceof WP_User || ! user_can( $user, 'manage_options' ) || '' === (string) $password ) { return $user; }
		if ( wp_check_password( $password, $user->user_pass, $user->ID ) && self::breached( (string) $password ) ) {
			return new WP_Error( 'sbs_breached', sprintf( /* translators: %s: link */ __( '<strong>Error:</strong> your password appeared in a known data breach, so it cannot be used. Please %s.', 'sidcraft-bot-shield' ), '<a href="' . esc_url( wp_lostpassword_url() ) . '">' . esc_html__( 'reset it', 'sidcraft-bot-shield' ) . '</a>' ) );
		}
		return $user;
	}

	// ---- Rate limits ----
	private static function is_crawler( $ua ) {
		$u = strtolower( $ua );
		if ( '' === $u ) { return false; }
		foreach ( Sidcraft_BotShield_Catalog::allowed() as $g ) { foreach ( $g['bots'] as $tok => $i ) { if ( '' !== $tok && false !== strpos( $u, $tok ) ) { return true; } } }
		return (bool) preg_match( '/bot|crawl|spider|slurp|scrape|fetch|python|curl|wget|http-client/', $u );
	}

	private static function is_search_engine( $ua ) {
		$u = strtolower( $ua ); $g = Sidcraft_BotShield_Catalog::allowed();
		foreach ( $g['search']['bots'] ?? array() as $tok => $i ) { if ( '' !== $tok && false !== strpos( $u, $tok ) ) { return true; } }
		return false;
	}

	private static function limit_hit( $reason, $ip, $ua, $path, $s ) {
		Sidcraft_BotShield_Log::add( 'block', $reason, $ip, $ua, $path );
		if ( 'block' === $s['rate_action'] ) { Sidcraft_BotShield_Bans::add( $ip, (int) Sidcraft_BotShield_Settings::get( 'ban_hours' ) * HOUR_IN_SECONDS, 'Rate limit' ); self::deny( 'rate' ); }
		self::deny( 'rate', 429, 60 );
	}

	private static function crawler_rate( $s, $ip, $ua, $path ) {
		if ( ! $s['crawler_per_min'] || '' === $ip || is_admin() || wp_doing_ajax() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) { return; }
		if ( ! self::is_crawler( $ua ) || self::is_search_engine( $ua ) ) { return; }
		$k = 'sbs_rc_' . md5( $ip ); $n = (int) get_transient( $k ) + 1; set_transient( $k, $n, MINUTE_IN_SECONDS );
		if ( $n > (int) $s['crawler_per_min'] ) { self::limit_hit( 'rate_crawler', $ip, $ua, $path, $s ); }
	}

	/** Block addresses that keep asking for pages that do not exist (bots looking for weak spots). */
	public static function on_404() {
		if ( ! is_404() ) { return; }
		$s = Sidcraft_BotShield_FwSettings::all(); $ip = self::ip(); $ua = self::ua();
		if ( ! $s['nf_on'] || '' === $ip || self::trusted( $ip ) || is_user_logged_in() || self::is_search_engine( $ua ) || Sidcraft_BotShield_Bans::is_banned( $ip ) ) { return; }
		$path = self::path();
		foreach ( preg_split( '/\R/', (string) $s['nf_exempt'], -1, PREG_SPLIT_NO_EMPTY ) as $x ) { if ( false !== stripos( $path, $x ) ) { return; } }
		$k = 'sbs_nf_' . md5( $ip ); $now = time(); $win = (int) $s['nf_minutes'] * MINUTE_IN_SECONDS;
		$hits = get_transient( $k ); $hits = is_array( $hits ) ? array_values( array_filter( $hits, function ( $t ) use ( $now, $win ) { return $t > $now - $win; } ) ) : array();
		$hits[] = $now; $hits = array_slice( $hits, -( (int) $s['nf_count'] ) );
		set_transient( $k, $hits, $win );
		if ( count( $hits ) >= (int) $s['nf_count'] ) {
			delete_transient( $k );
			Sidcraft_BotShield_Log::add( 'block', 'rate_404', $ip, $ua, $path );
			Sidcraft_BotShield_Bans::add( $ip, (int) $s['nf_days'] * DAY_IN_SECONDS, sprintf( /* translators: 1: number 2: minutes */ __( '%1$d missing pages in %2$d minutes', 'sidcraft-bot-shield' ), (int) $s['nf_count'], (int) $s['nf_minutes'] ), 'nf' );
			self::deny( 'rate' );
		}
	}

	// ---- Hardening ----
	public static function strip_ver( $src ) {
		global $wp_version;
		return ( is_string( $src ) && false !== strpos( $src, 'ver=' . $wp_version ) ) ? remove_query_arg( 'ver', $src ) : $src;
	}
	public static function no_multicall( $m ) { unset( $m['system.multicall'], $m['system.listMethods'], $m['system.getCapabilities'] ); return $m; }
	public static function hide_rest_users( $e ) {
		if ( ! is_user_logged_in() ) { foreach ( array_keys( $e ) as $r ) { if ( 0 === strpos( $r, '/wp/v2/users' ) ) { unset( $e[ $r ] ); } } }
		return $e;
	}

	// ---- Extended protection (runs before WordPress) ----
	public static function ext_dir() { return rtrim( Sidcraft_BotShield_Lists::dir(), '/' ); }

	public static function config_array() {
		$s = Sidcraft_BotShield_FwSettings::all(); $g = Sidcraft_BotShield_Settings::all();
		$trusted = Sidcraft_BotShield_Settings::lines( 'ip_allow' ); $trusted[] = '127.0.0.1'; $trusted[] = '::1';
		return array( 'mode' => Sidcraft_BotShield_FwSettings::effective_mode(), 'disabled' => $s['waf_disabled'], 'allow' => preg_split( '/\R/', (string) $s['waf_allow'], -1, PREG_SPLIT_NO_EMPTY ), 'trusted' => $trusted, 'proxy_header' => 'cloudflare' === $g['proxy'] ? 'HTTP_CF_CONNECTING_IP' : ( 'xff' === $g['proxy'] ? 'HTTP_X_FORWARDED_FOR' : '' ) );
	}

	public static function ext_sync() {
		if ( ! self::ext_on() || ! Sidcraft_BotShield_Lists::ensure_dir() ) { return; }
		file_put_contents( self::ext_dir() . '/waf-config.json', wp_json_encode( self::config_array() ) );
	}

	private static function fs() {
		require_once ABSPATH . 'wp-admin/includes/file.php'; WP_Filesystem(); global $wp_filesystem; return $wp_filesystem;
	}

	private static function strip_block( $text, $c ) {
		return trim( (string) preg_replace( '/\R?' . preg_quote( $c . ' BEGIN ' . self::MARK, '/' ) . '.*?' . preg_quote( $c . ' END ' . self::MARK, '/' ) . '\R?/s', "\n", $text ) );
	}

	/** First active auto_prepend_file setting in a config file: array( line, value ), or null. Comments and empty values are ignored. */
	public static function find_prepend( $text ) {
		foreach ( preg_split( '/\R/', (string) $text ) as $i => $line ) {
			if ( preg_match( '/^\s*(?:php_(?:admin_)?value\s+)?auto_prepend_file\s*[= ]\s*(.*)$/i', $line, $m ) ) {
				$v = trim( $m[1], " \t\"'" );
				if ( '' !== $v && 'none' !== strtolower( $v ) ) { return array( $i + 1, $v ); }
			}
		}
		return null;
	}

	const ERR  = 'sidcraft_botshield_ext_error';
	const FLAG = 'sidcraft_botshield_ext_on'; // kept apart from the saved settings, whose sanitizer would reset it.

	public static function ext_on() { return (bool) get_option( self::FLAG, 0 ); }

	/** Read a file (WordPress filesystem first, then plain PHP). */
	private static function read_file( $path ) {
		$fs = self::fs(); if ( $fs && $fs->exists( $path ) ) { $t = $fs->get_contents( $path ); if ( is_string( $t ) ) { return $t; } }
		return is_readable( $path ) ? (string) file_get_contents( $path ) : '';
	}

	/** Write a file and check that it was really saved. Returns '' or the reason. */
	private static function write_file( $path, $content ) {
		$fs = self::fs();
		if ( $fs && $fs->put_contents( $path, $content, 0644 ) && self::read_file( $path ) === $content ) { return ''; }
		$ok = file_exists( $path ) ? is_writable( $path ) : is_writable( dirname( $path ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable
		if ( ! $ok ) { return sprintf( /* translators: %s: file name */ __( '%s cannot be written by WordPress (file permissions).', 'sidcraft-bot-shield' ), basename( $path ) ); }
		if ( false === file_put_contents( $path, $content ) ) { return sprintf( /* translators: %s: file name */ __( '%s could not be written.', 'sidcraft-bot-shield' ), basename( $path ) ); }
		return self::read_file( $path ) === $content ? '' : sprintf( /* translators: %s: file name */ __( '%s was written but the change did not stay (the host may manage this file).', 'sidcraft-bot-shield' ), basename( $path ) );
	}

	/** The exact lines to add by hand: array( ini, htaccess ). */
	public static function manual_lines() {
		$p = wp_normalize_path( self::ext_dir() . '/prepend.php' );
		$ini = 'auto_prepend_file = "' . $p . '"';
		$ht  = "<IfModule mod_php.c>\n\tphp_value auto_prepend_file \"{$p}\"\n</IfModule>\n<IfModule mod_php7.c>\n\tphp_value auto_prepend_file \"{$p}\"\n</IfModule>\n<IfModule mod_php8.c>\n\tphp_value auto_prepend_file \"{$p}\"\n</IfModule>\n<IfModule LiteSpeed>\n\tphp_value auto_prepend_file \"{$p}\"\n</IfModule>";
		return array( $ini, $ht );
	}

	public static function ext_error() { $e = get_option( self::ERR, array() ); return is_array( $e ) && ! empty( $e['msg'] ) ? $e : null; }

	/** Install the pre-WordPress firewall. Returns '' on success or an error message (also kept for the admin screen). */
	public static function ext_enable() {
		$err = self::ext_enable_run();
		if ( '' === $err ) { delete_option( self::ERR ); } else { update_option( self::ERR, array( 'msg' => $err, 'manual' => self::ext_on(), 'time' => time() ), false ); }
		return $err;
	}

	private static function ext_enable_run() {
		if ( ! Sidcraft_BotShield_Lists::ensure_dir() ) { return __( 'The folder wp-content/uploads/sidcraft-bot-shield cannot be created or written.', 'sidcraft-bot-shield' ); }
		$root = trailingslashit( ABSPATH ); $ini = $root . '.user.ini'; $ht = $root . '.htaccess';
		foreach ( array( $ini, $ht ) as $f ) {
			if ( ! file_exists( $f ) ) { continue; }
			$found = self::find_prepend( self::strip_block( self::strip_block( self::read_file( $f ), '#' ), ';' ) );
			if ( $found ) {
				$who = false !== stripos( $found[1], 'wordfence' ) ? ' ' . __( 'It belongs to the Wordfence firewall: in Wordfence, open Firewall → All Firewall Options → Optimize the Wordfence Firewall → Remove Extended Protection, or deactivate Wordfence. Only one firewall can run before WordPress at a time.', 'sidcraft-bot-shield' ) : ' ' . __( 'Only one firewall can run before WordPress at a time: remove that line (or the other firewall plugin) first, or keep using the normal protection without extended mode.', 'sidcraft-bot-shield' );
				return sprintf( /* translators: 1: file name 2: line number 3: value */ __( '%1$s already sets auto_prepend_file on line %2$d: %3$s.', 'sidcraft-bot-shield' ), basename( $f ), $found[0], $found[1] ) . $who;
			}
		}
		$dir = self::ext_dir(); $inc = wp_normalize_path( SIDCRAFT_BOTSHIELD_DIR . 'includes' );
		$stub = "<?php\n// Generated by Sidcraft Bot Shield. Safe to delete: it does nothing if the plugin is missing.\nif ( defined( 'SIDCRAFT_BOTSHIELD_WAF_LOADED' ) ) { return; }\ndefine( 'SIDCRAFT_BOTSHIELD_WAF_LOADED', 1 );\ntry {\n\t\$r = '" . addslashes( $inc ) . "/class-ranges.php'; \$w = '" . addslashes( $inc ) . "/class-waf.php';\n\tif ( is_file( \$r ) && is_file( \$w ) && is_file( __DIR__ . '/waf-config.json' ) ) { define( 'SIDCRAFT_BOTSHIELD_WAF', 1 ); require_once \$r; require_once \$w; Sidcraft_BotShield_Waf::bootstrap( __DIR__ . '/waf-config.json', __DIR__ ); }\n} catch ( \\Throwable \$e ) { return; }\n";
		if ( false === file_put_contents( $dir . '/prepend.php', $stub ) ) { return __( 'The firewall start file could not be written to wp-content/uploads/sidcraft-bot-shield.', 'sidcraft-bot-shield' ); } // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		update_option( self::FLAG, 1 );
		self::ext_sync();
		if ( ! is_file( $dir . '/waf-config.json' ) ) { return __( 'The firewall settings file could not be written to wp-content/uploads/sidcraft-bot-shield.', 'sidcraft-bot-shield' ); }
		$m = self::manual_lines(); $p = wp_normalize_path( $dir . '/prepend.php' );
		$ht_block = "# BEGIN " . self::MARK . "\n" . $m[1] . "\n# END " . self::MARK . "\n";
		$ini_block = "; BEGIN " . self::MARK . "\n" . $m[0] . "\n; END " . self::MARK . "\n";
		$problems = array();
		$cur = file_exists( $ht ) ? self::strip_block( self::read_file( $ht ), '#' ) : '';
		$e = self::write_file( $ht, $ht_block . ( '' !== $cur ? "\n" . $cur . "\n" : '' ) ); if ( '' !== $e ) { $problems[] = $e; }
		$cur = file_exists( $ini ) ? self::strip_block( self::read_file( $ini ), ';' ) : '';
		$e = self::write_file( $ini, $ini_block . ( '' !== $cur ? "\n" . $cur . "\n" : '' ) ); if ( '' !== $e ) { $problems[] = $e; }
		// One of the two files is enough: .htaccess for Apache with mod_php, .user.ini for PHP-FPM / CGI / LiteSpeed.
		if ( count( $problems ) >= 2 ) { return implode( ' ', $problems ); }
		return '';
	}

	/** Remove the pre-WordPress firewall lines. $keep_flag keeps the "enabled" setting (used on deactivation). */
	public static function ext_disable( $keep_flag = false ) {
		$root = trailingslashit( ABSPATH );
		foreach ( array( array( '.htaccess', '#' ), array( '.user.ini', ';' ) ) as $f ) {
			if ( file_exists( $root . $f[0] ) ) { $t = self::read_file( $root . $f[0] ); if ( false !== strpos( $t, self::MARK ) ) { self::write_file( $root . $f[0], self::strip_block( $t, $f[1] ) . "\n" ); } }
		}
		if ( ! $keep_flag ) { delete_option( self::FLAG ); delete_option( self::ERR ); }
	}

	/** array( enabled flag, last time the pre-WordPress firewall ran or 0 ). */
	public static function ext_status() {
		$seen = self::ext_dir() . '/waf-seen.txt';
		return array( self::ext_on(), is_file( $seen ) ? (int) filemtime( $seen ) : 0 );
	}

	/** Move blocks recorded by the pre-WordPress firewall into the normal log. */
	public static function import_waf_log() {
		$f = self::ext_dir() . '/waf-log.jsonl';
		if ( ! is_file( $f ) || ! filesize( $f ) ) { return; }
		$tmp = $f . '.' . wp_generate_password( 6, false ) . '.tmp';
		if ( ! @rename( $f, $tmp ) ) { return; } // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		foreach ( (array) file( $tmp, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES ) as $l ) {
			$r = json_decode( $l, true );
			if ( is_array( $r ) && ! empty( $r['rule'] ) ) { Sidcraft_BotShield_Log::add( 'block' === ( $r['m'] ?? 'block' ) ? 'block' : 'monitor', 'waf_' . sanitize_key( $r['rule'] ), sanitize_text_field( $r['ip'] ?? '' ), sanitize_text_field( $r['ua'] ?? '' ), sanitize_text_field( ( $r['p'] ?? '' ) . '  [' . ( $r['param'] ?? '' ) . ']' ), '', (int) ( $r['t'] ?? time() ) ); }
		}
		wp_delete_file( $tmp );
	}
}
