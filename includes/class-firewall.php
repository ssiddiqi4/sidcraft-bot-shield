<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

// phpcs:disable WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput, WordPress.WP.AlternativeFunctions -- a firewall reads the raw request; local files are the firewall's own.

/** The advanced firewall: rule engine, login protection, rate limits, hardening and optional extended protection. */
class Botvanguard_Firewall {
	const MARK = 'Sidcraft Bot Shield Firewall';

	public static function init() {
		add_action( 'init', array( __CLASS__, 'run' ), 1 );
		add_action( 'template_redirect', array( __CLASS__, 'on_404' ), 1 );
		$s = Botvanguard_FwSettings::all();
		if ( $s['bf_on'] || $s['user_on'] ) { add_action( 'wp_login_failed', array( __CLASS__, 'login_failed' ), 10, 2 ); }
		if ( $s['bf_on'] ) {
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
		if ( 'allow' !== $s['rest_mode'] || '' !== trim( (string) $s['rest_block'] ) || (int) $s['rest_rate'] > 0 ) { add_filter( 'rest_authentication_errors', array( __CLASS__, 'rest_guard' ), 99 ); }
		if ( $s['rest_auth'] ) { add_action( 'application_password_failed_authentication', array( __CLASS__, 'rest_auth_failed' ) ); }
		self::core_block_now( $s );
		add_action( 'update_option_' . Botvanguard_FwSettings::OPTION, array( __CLASS__, 'core_sync' ) );
		add_action( 'add_option_' . Botvanguard_FwSettings::OPTION, array( __CLASS__, 'core_sync' ) );
		Botvanguard_Notify::init();
	}

	private static function ip() { return Botvanguard_Guard::client_ip(); }
	private static function ua() { return isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : ''; }
	private static function path() { $u = isset( $_SERVER['REQUEST_URI'] ) ? wp_parse_url( esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ), PHP_URL_PATH ) : ''; return (string) $u; }

	private static function trusted( $ip ) {
		if ( '' === $ip ) { return false; }
		$t = Botvanguard_Settings::lines( 'ip_allow' );
		if ( apply_filters( 'sidcraft_botshield_trust_loopback', true ) ) { $t = array_merge( $t, array( '127.0.0.1', '::1' ) ); }
		return Botvanguard_Ranges::in_list( $ip, $t ) || Botvanguard_Guard::is_admin_ip( $ip );
	}

	private static function deny( $reason, $status = 403, $retry = 0 ) {
		status_header( $status ); nocache_headers(); header( 'X-Robots-Tag: noindex, nofollow' );
		if ( $retry ) { header( 'Retry-After: ' . (int) $retry ); }
		header( 'Content-Type: text/plain; charset=UTF-8' );
		echo esc_html( 429 === $status ? __( 'Too many requests. Please slow down.', 'botvanguard' ) : __( 'Blocked by the Sidcraft BotVanguard firewall.', 'botvanguard' ) );
		exit;
	}

	// ---- Rule engine in WordPress ----
	public static function run() {
		if ( 'cli' === PHP_SAPI || ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() ) { return; }
		$s = Botvanguard_FwSettings::all(); $ip = self::ip(); $ua = self::ua(); $path = self::path();
		if ( '' !== $ip && self::trusted( $ip ) ) { return; }
		self::probe();
		self::abuse_check( $s, $ip, $ua, $path );
		self::forbidden_names( $s, $ip, $ua, $path );
		$logged = is_user_logged_in(); $admin = $logged && current_user_can( 'manage_options' );
		// Simple hardening checks that need no rules.
		if ( ! $logged ) {
			if ( $s['enum_block'] && isset( $_GET['author'] ) && '' !== (string) $_GET['author'] && preg_match( '/^\d+$/', (string) wp_unslash( $_GET['author'] ) ) ) { self::hit( 'enum_author', $ip, $ua, $path, 'enum' ); }
			if ( $s['blank_post'] && 'POST' === ( $_SERVER['REQUEST_METHOD'] ?? '' ) && '' === $ua && empty( $_SERVER['HTTP_REFERER'] ) ) { self::hit( 'blank_post', $ip, $ua, $path, 'blank' ); }
			self::crawler_rate( $s, $ip, $ua, $path );
		}
		$mode = Botvanguard_FwSettings::effective_mode();
		if ( 'disabled' === $mode || defined( 'SIDCRAFT_BOTSHIELD_WAF_DONE' ) ) { return; }
		$files = array();
		foreach ( $_FILES as $f ) { if ( is_array( $f ) && isset( $f['name'] ) && ! is_array( $f['name'] ) ) { $files[ (string) $f['name'] ] = (string) ( $f['tmp_name'] ?? '' ); } }
		$cookies = $_COOKIE; foreach ( array_keys( $cookies ) as $k ) { if ( 0 === strpos( (string) $k, 'wordpress_' ) || 0 === strpos( (string) $k, 'wp-settings' ) ) { unset( $cookies[ $k ] ); } }
		$req = array( 'path' => $path, 'get' => wp_unslash( $_GET ), 'post' => wp_unslash( $_POST ), 'cookies' => wp_unslash( $cookies ), 'files' => $files,
			'headers' => array( 'user-agent' => $ua, 'referer' => isset( $_SERVER['HTTP_REFERER'] ) ? wp_unslash( $_SERVER['HTTP_REFERER'] ) : '', 'x-forwarded-for' => isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ? wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) : '' ) );
		$hit = Botvanguard_Waf::inspect( $req, array( 'disabled' => $s['waf_disabled'], 'allow' => preg_split( '/\R/', (string) $s['waf_allow'], -1, PREG_SPLIT_NO_EMPTY ) ) );
		if ( ! $hit ) { return; }
		if ( $admin ) { // Administrators are never blocked; in learning mode their requests teach the firewall what is normal.
			if ( 'learning' === $mode ) { self::learn( $path, $hit ); }
			return;
		}
		Botvanguard_Log::add( 'enabled' === $mode ? 'block' : 'monitor', 'waf_' . $hit['rule'], $ip, $ua, $path . ( '' !== $hit['param'] ? '  [' . substr( $hit['param'], 0, 40 ) . ']' : '' ) );
		if ( 'enabled' !== $mode ) { return; }
		if ( $s['waf_ban'] && '' !== $ip ) {
			$k = 'sbs_wafn_' . md5( $ip ); $n = (int) get_transient( $k ) + 1; set_transient( $k, $n, 10 * MINUTE_IN_SECONDS );
			if ( $n >= 5 ) { Botvanguard_Bans::add( $ip, (int) Botvanguard_Settings::get( 'ban_hours' ) * HOUR_IN_SECONDS, 'Repeated firewall blocks' ); }
		}
		self::deny( 'waf' );
	}

	/** Remember that an administrator legitimately sent this parameter here. */
	private static function learn( $path, $hit ) {
		$base = preg_replace( '/\[.*$/', '', $hit['param'] );
		if ( '' === $base || 'upload_php' === $hit['rule'] ) { return; }
		$s = Botvanguard_FwSettings::all(); $lines = preg_split( '/\R/', (string) $s['waf_allow'], -1, PREG_SPLIT_NO_EMPTY );
		$line = $path . ' ' . $base . ' ' . $hit['rule'];
		if ( ! in_array( $line, $lines, true ) && count( $lines ) < 300 ) { $lines[] = $line; $s['waf_allow'] = implode( "\n", $lines ); update_option( Botvanguard_FwSettings::OPTION, $s ); }
	}

	/** Log (and block) a simple rule hit. */
	private static function hit( $reason, $ip, $ua, $path, $kind ) {
		Botvanguard_Log::add( 'block', $reason, $ip, $ua, $path );
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
		$s = Botvanguard_FwSettings::all();
		if ( $s['user_on'] && '' !== (string) $username && ! username_exists( (string) $username ) && ! email_exists( (string) $username ) && self::window_hit( 'sbs_uu_', $ip, (int) $s['user_attempts'], (int) $s['user_minutes'] ) ) {
			Botvanguard_Bans::add( $ip, (int) $s['user_days'] * DAY_IN_SECONDS, sprintf( /* translators: 1: number 2: minutes */ __( '%1$d logins with user names that do not exist in %2$d minutes', 'botvanguard' ), (int) $s['user_attempts'], (int) $s['user_minutes'] ), 'url' );
			Botvanguard_Log::add( 'block', 'brute_invalid', $ip, self::ua(), self::path() );
			return;
		}
		if ( ! $s['bf_on'] ) { return; }
		$n = self::count_fail( 'sbs_lf_', $ip, (int) $s['bf_window_min'] );
		if ( $n >= (int) $s['bf_max_login'] ) {
			Botvanguard_Bans::add( $ip, (int) $s['bf_lock_hours'] * HOUR_IN_SECONDS, 'Too many failed logins' );
			Botvanguard_Log::add( 'block', 'brute_login', $ip, self::ua(), self::path() );
		}
	}

	/** Record one event for this address and say whether it has now happened $attempts times within $minutes. */
	private static function window_hit( $prefix, $ip, $attempts, $minutes ) {
		$k = $prefix . md5( $ip ); $now = time(); $win = $minutes * MINUTE_IN_SECONDS;
		$hits = get_transient( $k ); $hits = is_array( $hits ) ? array_values( array_filter( $hits, function ( $t ) use ( $now, $win ) { return $t > $now - $win; } ) ) : array();
		$hits[] = $now; $hits = array_slice( $hits, -$attempts ); set_transient( $k, $hits, $win );
		if ( count( $hits ) < $attempts ) { return false; }
		delete_transient( $k );
		return true;
	}

	/**
	 * Someone who is not logged in keeps opening the login, dashboard or register pages. Reading the login page and then
	 * posting the form is a normal login and does not count; only repeated page requests do.
	 */
	public static function probe() {
		$s = Botvanguard_FwSettings::all(); if ( ! $s['probe_on'] || wp_doing_ajax() ) { return; }
		$ip = self::ip(); if ( '' === $ip || self::trusted( $ip ) || Botvanguard_Bans::is_banned( $ip ) ) { return; }
		foreach ( array_keys( $_COOKIE ) as $c ) { if ( 0 === strpos( (string) $c, 'wordpress_logged_in_' ) ) { return; } }
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		$path = trim( rawurldecode( self::path() ), '/' ); $base = trim( (string) wp_parse_url( home_url(), PHP_URL_PATH ), '/' );
		if ( '' !== $base && 0 === strpos( $path . '/', $base . '/' ) ) { $path = ltrim( substr( $path, strlen( $base ) ), '/' ); }
		$file = basename( $path ); $custom = Botvanguard_LoginSettings::get( 'url_on' ); // with a custom login address the "wrong address" option already counts these three.
		$hit = false;
		if ( ! $custom ) {
			if ( 'wp-login.php' === $file && 'get' === $method ) { $act = isset( $_GET['action'] ) ? sanitize_key( wp_unslash( $_GET['action'] ) ) : ''; $hit = ( '' === $act || 'register' === $act ); } // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- only reading which page was asked for.
			elseif ( 0 === strpos( $path . '/', 'wp-admin/' ) && ! in_array( $file, array( 'admin-ajax.php', 'admin-post.php', 'load-styles.php', 'load-scripts.php', 'upgrade.php', 'install.php' ), true ) ) { $hit = true; }
			elseif ( 'wp-register.php' === $file || 'wp-signup.php' === $file ) { $hit = true; }
		}
		if ( ! $hit && in_array( strtolower( $path ), array( 'register', 'signup', 'sign-up', 'registration' ), true ) ) { add_action( 'template_redirect', array( __CLASS__, 'probe_404' ), 2 ); }
		if ( $hit ) { self::probe_count( $s, $ip ); }
	}

	/** /register and friends only count when the site has no such page. */
	public static function probe_404() {
		if ( ! is_404() ) { return; }
		$s = Botvanguard_FwSettings::all(); $ip = self::ip();
		if ( '' !== $ip && ! is_user_logged_in() ) { self::probe_count( $s, $ip ); }
	}

	private static function probe_count( $s, $ip ) {
		if ( ! self::window_hit( 'sbs_pr_', $ip, (int) $s['probe_attempts'], (int) $s['probe_minutes'] ) ) { return; }
		Botvanguard_Log::add( 'block', 'brute_probe', $ip, self::ua(), self::path() );
		Botvanguard_Bans::add( $ip, (int) $s['probe_days'] * DAY_IN_SECONDS, sprintf( /* translators: 1: number 2: minutes */ __( '%1$d visits to login or register pages in %2$d minutes', 'botvanguard' ), (int) $s['probe_attempts'], (int) $s['probe_minutes'] ), 'url' );
		Botvanguard_Guard::banned_page( $ip );
	}

	public static function reset_request() {
		$ip = self::ip(); if ( '' === $ip || self::trusted( $ip ) ) { return; }
		$s = Botvanguard_FwSettings::all();
		if ( self::count_fail( 'sbs_fp_', $ip, (int) $s['bf_window_min'] ) >= (int) $s['bf_max_reset'] ) {
			Botvanguard_Bans::add( $ip, (int) $s['bf_lock_hours'] * HOUR_IN_SECONDS, 'Too many password reset requests' );
			Botvanguard_Log::add( 'block', 'brute_reset', $ip, self::ua(), self::path() );
		}
	}

	/** Same message for a wrong user name and a wrong password, so that user names cannot be guessed. */
	public static function generic_error( $user ) {
		if ( is_wp_error( $user ) && array_intersect( array( 'invalid_username', 'invalid_email', 'incorrect_password' ), $user->get_error_codes() ) ) {
			return new WP_Error( 'authentication_failed', __( '<strong>Error:</strong> the user name or password is not correct.', 'botvanguard' ) );
		}
		return $user;
	}

	// ---- Passwords ----
	public static function common_passwords() {
		return array( 'password', 'password1', 'password123', '123456', '1234567', '12345678', '123456789', '1234567890', 'qwerty', 'qwerty123', 'qwertyuiop', 'abc123', 'letmein', 'welcome', 'welcome1', 'admin', 'admin123', 'administrator', 'iloveyou', 'monkey', 'dragon', 'football', 'baseball', 'master', 'sunshine', 'princess', 'login', 'passw0rd', 'p@ssw0rd', 'changeme', 'wordpress', 'trustno1', '111111', '000000', '121212', '654321', 'superman', 'michael', 'shadow', 'whatever' );
	}

	/** Why a password is too weak, or '' when it is fine. */
	public static function weak_reason( $pw, $login = '', $email = '' ) {
		if ( strlen( $pw ) < 12 ) { return __( 'use at least 12 characters', 'botvanguard' ); }
		$l = strtolower( $pw );
		foreach ( self::common_passwords() as $c ) { if ( strlen( $c ) >= 4 && false !== strpos( $l, $c ) && strlen( $pw ) < strlen( $c ) + 8 ) { return __( 'do not use a common password', 'botvanguard' ); } }
		if ( '' !== $login && false !== strpos( $l, strtolower( $login ) ) && strlen( $login ) >= 4 ) { return __( 'do not include your user name', 'botvanguard' ); }
		$local = '' !== $email ? strtolower( strstr( $email, '@', true ) ) : '';
		if ( strlen( $local ) >= 4 && false !== strpos( $l, $local ) ) { return __( 'do not include your email name', 'botvanguard' ); }
		$classes = (int) preg_match( '/[a-z]/', $pw ) + (int) preg_match( '/[A-Z]/', $pw ) + (int) preg_match( '/\d/', $pw ) + (int) preg_match( '/[^A-Za-z0-9]/', $pw );
		if ( $classes < 3 ) { return __( 'mix upper and lower case letters, numbers and symbols', 'botvanguard' ); }
		if ( preg_match( '/^(.)\1+$/', $pw ) ) { return __( 'do not repeat one character', 'botvanguard' ); }
		return '';
	}

	private static function needs_strong( $user_roles ) {
		$mode = Botvanguard_FwSettings::get( 'strong_pw' );
		return 'all' === $mode || ( 'admins' === $mode && array_intersect( (array) $user_roles, array( 'administrator', 'editor', 'shop_manager' ) ) );
	}

	public static function check_profile_pw( $errors, $update, $user ) {
		if ( empty( $user->user_pass ) ) { return; }
		$roles = isset( $user->role ) && '' !== $user->role ? array( $user->role ) : ( ! empty( $user->ID ) ? (array) get_userdata( $user->ID )->roles : array() );
		if ( ! self::needs_strong( $roles ) ) { return; }
		$why = self::weak_reason( (string) $user->user_pass, (string) ( $user->user_login ?? '' ), (string) ( $user->user_email ?? '' ) );
		if ( '' !== $why ) { $errors->add( 'sbs_weak_pw', sprintf( /* translators: %s: advice */ __( '<strong>Error:</strong> this password is too weak: %s.', 'botvanguard' ), $why ) ); }
		elseif ( Botvanguard_FwSettings::get( 'breached_pw' ) && self::breached( (string) $user->user_pass ) ) { $errors->add( 'sbs_breached_pw', __( '<strong>Error:</strong> this password appeared in a known data breach. Choose another one.', 'botvanguard' ) ); }
	}

	public static function check_reset_pw( $errors, $user ) {
		$pw = isset( $_POST['pass1'] ) ? (string) wp_unslash( $_POST['pass1'] ) : '';
		if ( '' === $pw || ! $user || ! self::needs_strong( $user->roles ) ) { return; }
		$why = self::weak_reason( $pw, $user->user_login, $user->user_email );
		if ( '' !== $why ) { $errors->add( 'sbs_weak_pw', sprintf( /* translators: %s: advice */ __( '<strong>Error:</strong> this password is too weak: %s.', 'botvanguard' ), $why ) ); }
		elseif ( Botvanguard_FwSettings::get( 'breached_pw' ) && self::breached( $pw ) ) { $errors->add( 'sbs_breached_pw', __( '<strong>Error:</strong> this password appeared in a known data breach. Choose another one.', 'botvanguard' ) ); }
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
			return new WP_Error( 'sbs_breached', sprintf( /* translators: %s: link */ __( '<strong>Error:</strong> your password appeared in a known data breach, so it cannot be used. Please %s.', 'botvanguard' ), '<a href="' . esc_url( wp_lostpassword_url() ) . '">' . esc_html__( 'reset it', 'botvanguard' ) . '</a>' ) );
		}
		return $user;
	}

	// ---- Rate limits ----
	private static function is_crawler( $ua ) {
		$u = strtolower( $ua );
		if ( '' === $u ) { return false; }
		foreach ( Botvanguard_Catalog::allowed() as $g ) { foreach ( $g['bots'] as $tok => $i ) { if ( '' !== $tok && false !== strpos( $u, $tok ) ) { return true; } } }
		return (bool) preg_match( '/bot|crawl|spider|slurp|scrape|fetch|python|curl|wget|http-client/', $u );
	}

	private static function is_search_engine( $ua ) {
		$u = strtolower( $ua ); $g = Botvanguard_Catalog::allowed();
		foreach ( $g['search']['bots'] ?? array() as $tok => $i ) { if ( '' !== $tok && false !== strpos( $u, $tok ) ) { return true; } }
		return false;
	}

	private static function limit_hit( $reason, $ip, $ua, $path, $s ) {
		Botvanguard_Log::add( 'block', $reason, $ip, $ua, $path );
		if ( 'block' === $s['rate_action'] ) { Botvanguard_Bans::add( $ip, (int) Botvanguard_Settings::get( 'ban_hours' ) * HOUR_IN_SECONDS, 'Rate limit' ); self::deny( 'rate' ); }
		self::deny( 'rate', 429, 60 );
	}

	private static function crawler_rate( $s, $ip, $ua, $path ) {
		if ( ! $s['crawler_per_min'] || '' === $ip || is_admin() || wp_doing_ajax() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) { return; }
		if ( ! self::is_crawler( $ua ) || self::is_search_engine( $ua ) ) { return; }
		$k = 'sbs_rc_' . md5( $ip ); $n = (int) get_transient( $k ) + 1; set_transient( $k, $n, MINUTE_IN_SECONDS );
		if ( $n > (int) $s['crawler_per_min'] ) { self::limit_hit( 'rate_crawler', $ip, $ua, $path, $s ); }
	}

	/** The AbuseIPDB abuse confidence score (0-100) of an address, or -1 when it could not be looked up. Remembered for a while so one visitor costs one lookup. */
	public static function abuse_score( $ip, $s ) {
		$ck = 'sbs_ab_' . md5( $ip ); $c = get_transient( $ck );
		if ( false !== $c ) { return (int) $c; }
		if ( get_transient( 'sbs_ab_pause' ) ) { return -1; } // the daily allowance is used up, try again later.
		$res = wp_remote_get( add_query_arg( array( 'ipAddress' => $ip, 'maxAgeInDays' => 90 ), 'https://api.abuseipdb.com/api/v2/check' ), array( 'timeout' => 3, 'headers' => array( 'Key' => (string) $s['ab_key'], 'Accept' => 'application/json' ) ) );
		if ( is_wp_error( $res ) ) { update_option( 'sidcraft_botshield_ab_err', $res->get_error_message(), false ); set_transient( $ck, -1, 10 * MINUTE_IN_SECONDS ); return -1; }
		$code = (int) wp_remote_retrieve_response_code( $res ); $j = json_decode( (string) wp_remote_retrieve_body( $res ), true );
		if ( 200 !== $code || ! isset( $j['data']['abuseConfidenceScore'] ) ) {
			if ( 429 === $code ) { set_transient( 'sbs_ab_pause', 1, HOUR_IN_SECONDS ); }
			/* translators: %d: HTTP status code */
			update_option( 'sidcraft_botshield_ab_err', 429 === $code ? __( 'AbuseIPDB says the daily number of checks is used up.', 'botvanguard' ) : sprintf( __( 'AbuseIPDB answered with code %d. Check the API key.', 'botvanguard' ), $code ), false );
			set_transient( $ck, -1, 10 * MINUTE_IN_SECONDS ); return -1;
		}
		delete_option( 'sidcraft_botshield_ab_err' );
		$score = max( 0, min( 100, (int) $j['data']['abuseConfidenceScore'] ) );
		set_transient( $ck, $score, max( 1, (int) $s['ab_hours'] ) * HOUR_IN_SECONDS );
		return $score;
	}

	/** True for a real search engine crawler: it says so in its name AND its address belongs to that company. Someone who only claims to be Googlebot is not exempt. */
	private static function verified_search_engine( $ip, $ua ) {
		$u = strtolower( $ua ); $g = Botvanguard_Catalog::allowed();
		foreach ( $g['search']['bots'] ?? array() as $tok => $i ) {
			if ( '' === $tok || false === strpos( $u, $tok ) ) { continue; }
			return ! is_array( $i[1] ) || 'fail' !== Botvanguard_Verify::check( $ip, $i[1] ); // a lookup that cannot finish is given the benefit of the doubt.
		}
		return false;
	}

	/** Deny a visitor whose address has an AbuseIPDB score above the owner's limit. Search engines (checked by address, not only by name), logged-in users, the owner's own addresses and private addresses are let through. */
	private static function abuse_check( $s, $ip, $ua, $path ) {
		if ( empty( $s['ab_on'] ) || '' === trim( (string) $s['ab_key'] ) || '' === $ip || is_user_logged_in() ) { return; }
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) { return; }
		if ( self::verified_search_engine( $ip, $ua ) ) { return; }
		$score = self::abuse_score( $ip, $s );
		if ( $score <= (int) $s['ab_min'] ) { return; }
		Botvanguard_Log::add( 'block', 'abuseipdb', $ip, $ua, $path );
		self::deny( 'abuse' );
	}

	/** The first line of the owner's forbidden list found in the request address (case does not matter), or ''. */
	public static function forbidden_match( $list, $text ) {
		$t = strtolower( rawurldecode( (string) $text ) );
		$parts = null;
		foreach ( preg_split( '/\R/', (string) $list, -1, PREG_SPLIT_NO_EMPTY ) as $l ) {
			$l = strtolower( trim( $l ) ); if ( strlen( $l ) < 3 ) { continue; }
			if ( false === strpos( $l, '*' ) && false === strpos( $l, '?' ) ) { if ( false !== strpos( $t, $l ) ) { return $l; } continue; }
			// A wildcard line (* = any characters, ? = one character) must match a whole piece of the address: each folder or file name, each search word, or the whole path when the line holds a slash.
			if ( null === $parts ) { $parts = preg_split( '#[/?&=\s]+#', $t, -1, PREG_SPLIT_NO_EMPTY ); $parts[] = (string) strtok( $t, '?' ); }
			$re = '#^' . str_replace( array( '\\*', '\\?' ), array( '.*', '.' ), preg_quote( $l, '#' ) ) . '$#';
			foreach ( $parts as $p ) { if ( preg_match( $re, $p ) ) { return $l; } }
		}
		return '';
	}

	/** Refuse, and block for good (or for the chosen days), an address that asks for a forbidden file name or word such as backup.tar.gz. Never applies to logged-in users, the owner's own addresses or search engines. */
	private static function forbidden_names( $s, $ip, $ua, $path ) {
		if ( empty( $s['fb_on'] ) || '' === trim( (string) $s['fb_list'] ) || '' === $ip || is_user_logged_in() || self::is_search_engine( $ua ) || Botvanguard_Bans::is_banned( $ip ) ) { return; }
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : $path;
		$hit  = self::forbidden_match( $s['fb_list'], $uri );
		if ( '' === $hit ) { return; }
		Botvanguard_Log::add( 'block', 'forbidden_name', $ip, $ua, $path );
		/* translators: %s: the forbidden name that was requested */
		Botvanguard_Bans::add( $ip, (int) $s['fb_days'] * DAY_IN_SECONDS, sprintf( __( 'Asked for forbidden name: %s', 'botvanguard' ), $hit ), 'fb' );
		self::deny( 'forbidden' );
	}

	/** Block addresses that keep asking for pages that do not exist (bots looking for weak spots). */
	public static function on_404() {
		if ( ! is_404() ) { return; }
		$s = Botvanguard_FwSettings::all(); $ip = self::ip(); $ua = self::ua();
		if ( ! $s['nf_on'] || '' === $ip || self::trusted( $ip ) || is_user_logged_in() || self::is_search_engine( $ua ) || Botvanguard_Bans::is_banned( $ip ) ) { return; }
		$path = self::path();
		foreach ( preg_split( '/\R/', (string) $s['nf_exempt'], -1, PREG_SPLIT_NO_EMPTY ) as $x ) { if ( false !== stripos( $path, $x ) ) { return; } }
		$k = 'sbs_nf_' . md5( $ip ); $now = time(); $win = (int) $s['nf_minutes'] * MINUTE_IN_SECONDS;
		$hits = get_transient( $k ); $hits = is_array( $hits ) ? array_values( array_filter( $hits, function ( $t ) use ( $now, $win ) { return $t > $now - $win; } ) ) : array();
		$hits[] = $now; $hits = array_slice( $hits, -( (int) $s['nf_count'] ) );
		set_transient( $k, $hits, $win );
		if ( count( $hits ) >= (int) $s['nf_count'] ) {
			delete_transient( $k );
			Botvanguard_Log::add( 'block', 'rate_404', $ip, $ua, $path );
			Botvanguard_Bans::add( $ip, (int) $s['nf_days'] * DAY_IN_SECONDS, sprintf( /* translators: 1: number 2: minutes */ __( '%1$d missing pages in %2$d minutes', 'botvanguard' ), (int) $s['nf_count'], (int) $s['nf_minutes'] ), 'nf' );
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
	public static function ext_dir() { return rtrim( Botvanguard_Lists::dir(), '/' ); }

	public static function config_array() {
		$s = Botvanguard_FwSettings::all(); $g = Botvanguard_Settings::all();
		$trusted = Botvanguard_Settings::lines( 'ip_allow' ); $trusted[] = '127.0.0.1'; $trusted[] = '::1';
		return array( 'mode' => Botvanguard_FwSettings::effective_mode(), 'disabled' => $s['waf_disabled'], 'allow' => preg_split( '/\R/', (string) $s['waf_allow'], -1, PREG_SPLIT_NO_EMPTY ), 'trusted' => $trusted, 'proxy_header' => 'cloudflare' === $g['proxy'] ? 'HTTP_CF_CONNECTING_IP' : ( 'xff' === $g['proxy'] ? 'HTTP_X_FORWARDED_FOR' : '' ) );
	}

	public static function ext_sync() {
		if ( ! self::ext_on() || ! Botvanguard_Lists::ensure_dir() ) { return; }
		file_put_contents( self::ext_dir() . '/waf-config.json', wp_json_encode( self::config_array() ) );
	}

	private static function fs() {
		require_once ABSPATH . 'wp-admin/includes/file.php'; WP_Filesystem(); global $wp_filesystem; return $wp_filesystem;
	}

	private static function strip_block( $text, $c, $mark = null ) {
		$mark = null === $mark ? self::MARK : $mark;
		return trim( (string) preg_replace( '/\R?' . preg_quote( $c . ' BEGIN ' . $mark, '/' ) . '.*?' . preg_quote( $c . ' END ' . $mark, '/' ) . '\R?/s', "\n", $text ) );
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
		if ( ! $ok ) { return sprintf( /* translators: %s: file name */ __( '%s cannot be written by WordPress (file permissions).', 'botvanguard' ), basename( $path ) ); }
		if ( false === file_put_contents( $path, $content ) ) { return sprintf( /* translators: %s: file name */ __( '%s could not be written.', 'botvanguard' ), basename( $path ) ); }
		return self::read_file( $path ) === $content ? '' : sprintf( /* translators: %s: file name */ __( '%s was written but the change did not stay (the host may manage this file).', 'botvanguard' ), basename( $path ) );
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
		if ( ! Botvanguard_Lists::ensure_dir() ) { return __( 'The folder wp-content/uploads/sidcraft-bot-shield cannot be created or written.', 'botvanguard' ); }
		$root = trailingslashit( ABSPATH ); $ini = $root . '.user.ini'; $ht = $root . '.htaccess';
		foreach ( array( $ini, $ht ) as $f ) {
			if ( ! file_exists( $f ) ) { continue; }
			$found = self::find_prepend( self::strip_block( self::strip_block( self::read_file( $f ), '#' ), ';' ) );
			if ( $found ) {
				$who = false !== stripos( $found[1], 'wordfence' ) ? ' ' . __( 'It belongs to the Wordfence firewall: in Wordfence, open Firewall → All Firewall Options → Optimize the Wordfence Firewall → Remove Extended Protection, or deactivate Wordfence. Only one firewall can run before WordPress at a time.', 'botvanguard' ) : ' ' . __( 'Only one firewall can run before WordPress at a time: remove that line (or the other firewall plugin) first, or keep using the normal protection without extended mode.', 'botvanguard' );
				return sprintf( /* translators: 1: file name 2: line number 3: value */ __( '%1$s already sets auto_prepend_file on line %2$d: %3$s.', 'botvanguard' ), basename( $f ), $found[0], $found[1] ) . $who;
			}
		}
		$dir = self::ext_dir(); $inc = wp_normalize_path( BOTVANGUARD_DIR . 'includes' );
		$stub = "<?php\n// Generated by Sidcraft BotVanguard. Safe to delete: it does nothing if the plugin is missing.\nif ( defined( 'SIDCRAFT_BOTSHIELD_WAF_LOADED' ) ) { return; }\ndefine( 'SIDCRAFT_BOTSHIELD_WAF_LOADED', 1 );\ntry {\n\t\$r = '" . addslashes( $inc ) . "/class-ranges.php'; \$w = '" . addslashes( $inc ) . "/class-waf.php';\n\tif ( is_file( \$r ) && is_file( \$w ) && is_file( __DIR__ . '/waf-config.json' ) ) { define( 'SIDCRAFT_BOTSHIELD_WAF', 1 ); require_once \$r; require_once \$w; Botvanguard_Waf::bootstrap( __DIR__ . '/waf-config.json', __DIR__ ); }\n} catch ( \\Throwable \$e ) { return; }\n";
		if ( false === file_put_contents( $dir . '/prepend.php', $stub ) ) { return __( 'The firewall start file could not be written to wp-content/uploads/sidcraft-bot-shield.', 'botvanguard' ); } // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		update_option( self::FLAG, 1 );
		self::ext_sync();
		if ( ! is_file( $dir . '/waf-config.json' ) ) { return __( 'The firewall settings file could not be written to wp-content/uploads/sidcraft-bot-shield.', 'botvanguard' ); }
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
			if ( is_array( $r ) && ! empty( $r['rule'] ) ) { Botvanguard_Log::add( 'block' === ( $r['m'] ?? 'block' ) ? 'block' : 'monitor', 'waf_' . sanitize_key( $r['rule'] ), sanitize_text_field( $r['ip'] ?? '' ), sanitize_text_field( $r['ua'] ?? '' ), sanitize_text_field( ( $r['p'] ?? '' ) . '  [' . ( $r['param'] ?? '' ) . ']' ), '', (int) ( $r['t'] ?? time() ) ); }
		}
		wp_delete_file( $tmp );
	}

	/* ---------- Block direct requests to core files (xmlrpc.php, wp-settings.php, wp-config.php) ---------- */

	const CORE_MARK = 'Sidcraft Bot Shield Core Files';
	const CORE_ERR  = 'sidcraft_botshield_core_error';

	/** Names (without .php) the owner switched on. */
	public static function core_files() {
		$s = Botvanguard_FwSettings::all(); $f = array();
		if ( $s['core_xmlrpc'] ) { $f[] = 'xmlrpc'; }
		if ( $s['core_settings'] ) { $f[] = 'wp-settings'; }
		if ( $s['core_config'] ) { $f[] = 'wp-config'; }
		return $f;
	}

	/** Second line of defence, used when the server rule is missing: refuse the request as soon as this plugin loads. wp-settings.php stops WordPress before any plugin loads, so only the server rule can block that file. */
	private static function core_block_now( $s ) {
		$script = isset( $_SERVER['SCRIPT_FILENAME'] ) ? basename( (string) wp_unslash( $_SERVER['SCRIPT_FILENAME'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- only compared with fixed names.
		$hit = ( $s['core_xmlrpc'] && ( ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) || 'xmlrpc.php' === $script ) && ! self::trusted( self::ip() ) )
			|| ( $s['core_config'] && 'wp-config.php' === $script )
			|| ( $s['core_settings'] && 'wp-settings.php' === $script );
		if ( ! $hit ) { return; }
		if ( ! headers_sent() ) { http_response_code( 403 ); header( 'Content-Type: text/plain; charset=utf-8' ); header( 'Cache-Control: no-store' ); }
		echo 'Forbidden';
		exit;
	}

	/** Write (or remove) the server rule in .htaccess. Safe to call at any time. */
	public static function core_sync( $a = null, $b = null ) {
		$files = self::core_files(); $ht = trailingslashit( ABSPATH ) . '.htaccess';
		$soft  = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( (string) wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- only searched for a word.
		$cur   = file_exists( $ht ) ? self::read_file( $ht ) : '';
		$has   = false !== strpos( $cur, self::CORE_MARK );
		if ( ! $files ) {
			if ( $has ) { $e = self::write_file( $ht, self::strip_block( $cur, '#', self::CORE_MARK ) . "\n" ); if ( '' !== $e ) { update_option( self::CORE_ERR, $e, false ); return; } }
			delete_option( self::CORE_ERR ); return;
		}
		if ( false !== strpos( $soft, 'nginx' ) && false === strpos( $soft, 'apache' ) && false === strpos( $soft, 'litespeed' ) ) {
			update_option( self::CORE_ERR, 'nginx', false ); return; // .htaccess does nothing on nginx: the admin screen shows the lines to add by hand.
		}
		$rule  = "# BEGIN " . self::CORE_MARK . "\n" . self::core_htaccess( $files ) . "\n# END " . self::CORE_MARK . "\n";
		$base  = '' !== $cur ? self::strip_block( $cur, '#', self::CORE_MARK ) : '';
		$e = self::write_file( $ht, $rule . ( '' !== $base ? "\n" . $base . "\n" : '' ) );
		if ( '' !== $e ) { update_option( self::CORE_ERR, $e, false ); } else { delete_option( self::CORE_ERR ); }
	}

	/** Called when the plugin is deactivated: take the server rule out (the settings stay). */
	public static function core_remove() {
		$ht = trailingslashit( ABSPATH ) . '.htaccess';
		if ( ! file_exists( $ht ) ) { return; }
		$cur = self::read_file( $ht );
		if ( false !== strpos( $cur, self::CORE_MARK ) ) { self::write_file( $ht, self::strip_block( $cur, '#', self::CORE_MARK ) . "\n" ); }
	}

	/** Apache and LiteSpeed lines for .htaccess. */
	public static function core_htaccess( $files ) {
		$alt = implode( '|', array_map( 'preg_quote', $files ) );
		return "<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteRule ^(?:" . $alt . ")\\.php$ - [F,L]\n</IfModule>";
	}

	/** nginx lines to add by hand. */
	public static function core_nginx( $files ) {
		return 'location ~* ^/(?:' . implode( '|', array_map( 'preg_quote', $files ) ) . ')\.php$ {' . "\n\tdeny all;\n}";
	}

	/* ---------- REST API (/wp-json/) protection ---------- */

	/** A failed REST login (application password) counts like a failed login on the login page. */
	public static function rest_auth_failed( $error = null ) { self::login_failed( '' ); }

	/** The route being asked for, such as /wp/v2/posts. */
	private static function rest_route() {
		global $wp; $r = '';
		if ( isset( $wp->query_vars['rest_route'] ) && is_string( $wp->query_vars['rest_route'] ) ) { $r = $wp->query_vars['rest_route']; }
		if ( '' === $r && isset( $_GET['rest_route'] ) && is_string( $_GET['rest_route'] ) ) { $r = sanitize_text_field( wp_unslash( $_GET['rest_route'] ) ); } // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- plain-permalink form of the same address.
		if ( '' === $r ) { $path = self::path(); $pre = '/' . rest_get_url_prefix() . '/'; $pos = strpos( $path, $pre ); if ( false !== $pos ) { $r = substr( $path, $pos + strlen( $pre ) - 1 ); } }
		return '/' . trim( strtolower( $r ), '/' );
	}

	/** True when the route is one of the lines (a line matches itself and everything below it). */
	private static function route_in( $route, $lines ) {
		$route = trim( strtolower( $route ), '/' );
		foreach ( preg_split( '/\R/', (string) $lines, -1, PREG_SPLIT_NO_EMPTY ) as $l ) {
			$l = trim( strtolower( trim( $l ) ), '/' );
			if ( '' === $l ) { continue; }
			if ( $route === $l || 0 === strpos( $route, $l . '/' ) ) { return true; }
		}
		return false;
	}

	/** Filter on rest_authentication_errors: close the REST API to visitors who are not logged in, as the settings say. */
	public static function rest_guard( $result ) {
		if ( ! empty( $result ) || is_user_logged_in() ) { return $result; }
		$ip = self::ip(); if ( '' !== $ip && self::trusted( $ip ) ) { return $result; }
		$s = Botvanguard_FwSettings::all(); $route = self::rest_route(); $why = '';
		if ( (int) $s['rest_rate'] > 0 && '' !== $ip && self::count_fail( 'sbs_rr_', $ip, 1 ) > (int) $s['rest_rate'] ) { $why = 'rest_rate'; }
		elseif ( '' !== trim( (string) $s['rest_block'] ) && self::route_in( $route, $s['rest_block'] ) ) { $why = 'rest_blocked'; }
		elseif ( in_array( $s['rest_mode'], array( 'login', 'monitor' ), true ) && ! self::route_in( $route, $s['rest_allow'] ) ) { $why = 'rest_login'; }
		if ( '' === $why ) { return $result; }
		$watch = ( 'monitor' === $s['rest_mode'] && 'rest_login' === $why );
		Botvanguard_Log::add( $watch ? 'monitor' : 'block', $why, $ip, self::ua(), self::path() );
		if ( $watch ) { return $result; }
		return new WP_Error( 'rest_forbidden', 'rest_rate' === $why ? __( 'Too many requests. Please slow down.', 'botvanguard' ) : __( 'The REST API is not open to visitors who are not logged in.', 'botvanguard' ), array( 'status' => 'rest_rate' === $why ? 429 : rest_authorization_required_code() ) );
	}

	/** After moving from the old plugin folder, point the pre-WordPress firewall at this plugin's files (the old folder is about to be deleted). */
	public static function ext_refresh() {
		if ( ! self::ext_on() || get_transient( 'botvanguard_ext_chk' ) ) { return; }
		set_transient( 'botvanguard_ext_chk', 1, 12 * HOUR_IN_SECONDS );
		$stub = self::ext_dir() . '/prepend.php';
		$cur  = is_file( $stub ) ? (string) file_get_contents( $stub ) : '';
		if ( false === strpos( $cur, wp_normalize_path( BOTVANGUARD_DIR . 'includes' ) ) ) { self::ext_enable(); }
	}
}
