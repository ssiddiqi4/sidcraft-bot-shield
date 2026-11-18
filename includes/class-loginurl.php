<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

// phpcs:disable WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput -- routing happens before WordPress knows who the visitor is.

/** Custom login address: /wp-login.php and /wp-admin stop working for visitors, and the login page lives at /your-secret instead. */
class Sidcraft_BotShield_LoginUrl {
	private static $slug = ''; private static $is_login = false; private static $block = false;

	public static function init() {
		if ( defined( 'SIDCRAFT_BOTSHIELD_LOGIN_URL_OFF' ) && SIDCRAFT_BOTSHIELD_LOGIN_URL_OFF ) { return; }
		$s = Sidcraft_BotShield_LoginSettings::all();
		if ( ! $s['url_on'] || '' === $s['url_slug'] || is_multisite() ) { return; }
		self::$slug = $s['url_slug'];
		add_action( 'plugins_loaded', array( __CLASS__, 'route' ), 9999 );
		add_action( 'wp_loaded', array( __CLASS__, 'serve' ), 0 );
		add_action( 'init', array( __CLASS__, 'guard_admin' ), 1 );
		add_filter( 'site_url', array( __CLASS__, 'site_url' ), 10, 4 );
		add_filter( 'network_site_url', array( __CLASS__, 'site_url' ), 10, 3 );
		add_filter( 'wp_redirect', array( __CLASS__, 'redirect' ), 10, 2 );
		add_filter( 'login_url', array( __CLASS__, 'login_url' ), 10, 3 );
		remove_action( 'template_redirect', 'wp_redirect_admin_locations', 1000 );
	}

	/** The login address, e.g. https://example.com/mysecret/ */
	public static function url( $scheme = null ) { return home_url( '/' . self::$slug . '/', $scheme ); }

	private static function request_path() {
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : ''; $p = (string) wp_parse_url( $uri, PHP_URL_PATH );
		$base = (string) wp_parse_url( home_url(), PHP_URL_PATH ); if ( '' !== $base && 0 === strpos( $p, $base ) ) { $p = substr( $p, strlen( $base ) ); }
		return trim( rawurldecode( $p ), '/' );
	}

	public static function route() {
		global $pagenow; $path = self::request_path();
		if ( $path === self::$slug ) { self::$is_login = true; $pagenow = 'wp-login.php'; $_SERVER['SCRIPT_NAME'] = '/wp-login.php'; return; }
		if ( 'wp-login.php' === basename( $path ) && ! defined( 'DOING_CRON' ) ) { self::$block = true; }
		elseif ( 0 === strpos( $path, 'wp-register.php' ) || 'wp-signup.php' === $path ) { self::$block = true; }
	}

	/** Visitors who are not logged in cannot open the dashboard files. */
	public static function guard_admin() {
		if ( self::$is_login || wp_doing_ajax() || defined( 'DOING_CRON' ) || ( defined( 'WP_CLI' ) && WP_CLI ) ) { return; }
		$path = self::request_path();
		if ( 0 !== strpos( $path . '/', 'wp-admin/' ) ) { return; }
		$file = basename( $path );
		if ( in_array( $file, array( 'admin-ajax.php', 'admin-post.php', 'load-styles.php', 'load-scripts.php', 'upgrade.php', 'install.php' ), true ) ) { return; }
		if ( ! is_user_logged_in() && is_blog_installed() ) { self::$block = true; self::serve(); }
	}

	public static function serve() {
		global $pagenow;
		if ( self::$is_login ) {
			if ( ! headers_sent() ) { nocache_headers(); }
			$pagenow = 'wp-login.php';
			require_once ABSPATH . 'wp-login.php';
			exit;
		}
		if ( ! self::$block ) { return; }
		$s = Sidcraft_BotShield_LoginSettings::all();
		self::count_wrong_address( $s );
		if ( 'home' === $s['url_redirect'] ) { wp_safe_redirect( home_url( '/' ) ); exit; }
		if ( 'custom' === $s['url_redirect'] && '' !== $s['url_custom'] ) { wp_safe_redirect( $s['url_custom'] ); exit; }
		global $wp_query; if ( ! $wp_query ) { status_header( 404 ); exit; }
		$wp_query->set_404(); status_header( 404 ); nocache_headers();
		if ( ! defined( 'WP_USE_THEMES' ) ) { define( 'WP_USE_THEMES', true ); } // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- core constant the theme loader needs
		add_filter( 'show_admin_bar', '__return_false' ); remove_action( 'wp_body_open', 'wp_admin_bar_render', 0 ); remove_action( 'wp_footer', 'wp_admin_bar_render', 1000 );
		require ABSPATH . WPINC . '/template-loader.php';
		exit;
	}

	/** A visitor who keeps opening the old login addresses is blocked after the number of tries the admin chose. */
	private static function count_wrong_address( $s ) {
		if ( empty( $s['url_block'] ) || is_user_logged_in() ) { return; }
		foreach ( array_keys( $_COOKIE ) as $c ) { if ( 0 === strpos( (string) $c, 'wordpress_logged_in_' ) ) { return; } } // someone with a login cookie (for example an expired session) is not a bot.
		$ip = Sidcraft_BotShield_Guard::client_ip(); if ( '' === $ip ) { return; }
		$trusted = Sidcraft_BotShield_Settings::lines( 'ip_allow' ); if ( apply_filters( 'sidcraft_botshield_trust_loopback', true ) ) { $trusted = array_merge( $trusted, array( '127.0.0.1', '::1' ) ); }
		if ( Sidcraft_BotShield_Ranges::in_list( $ip, $trusted ) || Sidcraft_BotShield_Bans::is_banned( $ip ) ) { return; }
		$k = 'sbs_wu_' . md5( $ip ); $now = time(); $win = (int) $s['url_minutes'] * MINUTE_IN_SECONDS;
		$hits = get_transient( $k ); $hits = is_array( $hits ) ? array_values( array_filter( $hits, function ( $t ) use ( $now, $win ) { return $t > $now - $win; } ) ) : array();
		$hits[] = $now; $hits = array_slice( $hits, -( (int) $s['url_attempts'] ) ); set_transient( $k, $hits, $win );
		if ( count( $hits ) < (int) $s['url_attempts'] ) { return; }
		delete_transient( $k );
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		Sidcraft_BotShield_Log::add( 'block', 'login_url', $ip, $ua, self::request_path() );
		Sidcraft_BotShield_Bans::add( $ip, (int) $s['url_days'] * DAY_IN_SECONDS, sprintf( /* translators: 1: number 2: minutes */ __( '%1$d tries at a wrong login address in %2$d minutes', 'sidcraft-bot-shield' ), (int) $s['url_attempts'], (int) $s['url_minutes'] ), 'url' );
		Sidcraft_BotShield_Guard::banned_page( $ip );
	}

	/** wp-login.php links become links to the secret address. */
	public static function site_url( $url, $path = '', $scheme = null, $blog_id = null ) {
		if ( is_string( $path ) && false !== strpos( $path, 'wp-login.php' ) && ( null === $scheme || in_array( $scheme, array( 'login', 'login_post', 'rpc', 'https', 'http', 'relative' ), true ) ) ) { return self::swap( $url ); }
		return $url;
	}

	public static function login_url( $login_url, $redirect = '', $force_reauth = false ) { return self::swap( $login_url ); }

	public static function redirect( $location, $status = 302 ) { return false !== strpos( (string) $location, 'wp-login.php' ) ? self::swap( $location ) : $location; }

	private static function swap( $url ) { return preg_replace( '#/wp-login\.php(?=$|\?|/|\#)#', '/' . self::$slug . '/', (string) $url, 1 ); }
}
