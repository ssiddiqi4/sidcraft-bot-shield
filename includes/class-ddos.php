<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * DDoS protection for the web server layer: an "under attack" mode that asks every visitor for a small browser check
 * before WordPress does any real work, limits how often one address may ask, and can switch on by itself.
 *
 * It cannot stop a flood that fills the server's network line. For that, use a CDN or your host's DDoS protection too.
 */
class Botvanguard_Ddos {
	const OPTION = 'sidcraft_botshield_ddos';
	const UNTIL  = 'botvanguard_ddos_until'; // time until which the mode is on (started by hand or by the automatic switch).
	const COOKIE = 'bvg_ddos';

	public static function defaults() {
		return array(
			'mode'         => 'auto',   // off | auto | on
			'auto_rate'    => 600,      // automatic switch: requests a minute to the whole site that start the mode.
			'auto_minutes' => 30,       // ... and how long it stays on.
			'challenge'    => 1,        // ask visitors for the browser check.
			'pow'          => 1,        // the browser check includes a small calculation (costs bots more than people).
			'cookie_hours' => 6,        // a visitor who passed is not asked again for this long.
			'rate_limit'   => 120,      // requests a minute from one address, for visitors who passed the check (0 = no limit).
			'ban_minutes'  => 30,       // how long an address that goes over the limit is blocked.
			'block_cron'   => 1,        // refuse outside calls to wp-cron.php while the mode is on.
			'exempt'       => "wc-api=\n/wc-api/",  // addresses (parts of the URL) that are never asked: payment and webhook callbacks.
		);
	}

	public static function all() { $o = get_option( self::OPTION, array() ); $d = self::defaults(); return array_merge( $d, is_array( $o ) ? array_intersect_key( $o, $d ) : array() ); }

	public static function sanitize( $in ) {
		$in = is_array( $in ) ? $in : array(); $o = array();
		$m = $in['mode'] ?? ''; $o['mode'] = in_array( $m, array( 'off', 'auto', 'on' ), true ) ? $m : 'auto';
		$o['auto_rate']    = max( 30, min( 100000, (int) ( $in['auto_rate'] ?? 600 ) ) );
		$o['auto_minutes'] = max( 5, min( 1440, (int) ( $in['auto_minutes'] ?? 30 ) ) );
		$o['cookie_hours'] = max( 1, min( 72, (int) ( $in['cookie_hours'] ?? 6 ) ) );
		$o['rate_limit']   = max( 0, min( 5000, (int) ( $in['rate_limit'] ?? 120 ) ) );
		$o['ban_minutes']  = max( 1, min( 1440, (int) ( $in['ban_minutes'] ?? 30 ) ) );
		foreach ( array( 'challenge', 'pow', 'block_cron' ) as $k ) { $o[ $k ] = empty( $in[ $k ] ) ? 0 : 1; }
		$lines = array(); foreach ( preg_split( '/\R/', (string) ( $in['exempt'] ?? '' ) ) as $l ) { $l = trim( sanitize_text_field( $l ) ); if ( '' !== $l && count( $lines ) < 100 ) { $lines[] = $l; } }
		$o['exempt'] = implode( "\n", $lines );
		return $o;
	}

	public static function init() {
		add_action( 'plugins_loaded', array( __CLASS__, 'run' ), 0 );
		add_action( 'admin_init', array( __CLASS__, 'register' ) );
		add_action( 'admin_post_botvanguard_ddos_start', array( __CLASS__, 'start' ) );
		add_action( 'admin_post_botvanguard_ddos_stop', array( __CLASS__, 'stop' ) );
	}

	public static function register() { register_setting( 'botvanguard_ddos_group', self::OPTION, array( 'type' => 'array', 'sanitize_callback' => array( __CLASS__, 'sanitize' ), 'default' => self::defaults() ) ); }

	/** The emergency switches that work without the dashboard: a line in wp-config.php, or an empty file uploaded by FTP. */
	public static function forced() {
		if ( ( defined( 'BOTVANGUARD_DDOS' ) && BOTVANGUARD_DDOS ) || ( defined( 'BOTVAGUARD_DDOS' ) && BOTVAGUARD_DDOS ) || ( defined( 'SIDCRAFT_BOTSHIELD_DDOS' ) && SIDCRAFT_BOTSHIELD_DDOS ) ) { return 'constant'; }
		if ( defined( 'WP_CONTENT_DIR' ) && ( file_exists( WP_CONTENT_DIR . '/botvanguard-ddos' ) || file_exists( WP_CONTENT_DIR . '/botvaguard-ddos' ) ) ) { return 'file'; }
		return '';
	}

	/** Whether the mode is on right now, and why: constant | file | on | manual | auto, or '' for off. */
	public static function status( $s = null ) {
		$s = $s ? $s : self::all();
		$f = self::forced(); if ( '' !== $f ) { return $f; }
		if ( 'on' === $s['mode'] ) { return 'on'; }
		$u = (int) get_option( self::UNTIL, 0 );
		if ( $u > time() ) { return 'auto' === get_option( 'botvanguard_ddos_how', '' ) ? 'auto' : 'manual'; }
		return '';
	}

	private static function dir() { $d = rtrim( Botvanguard_Lists::dir(), '/' ) . '/ddos/'; if ( ! is_dir( $d ) ) { Botvanguard_Lists::ensure_dir(); wp_mkdir_p( $d ); } return $d; }

	private static function ua() { return isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : ''; }
	private static function uri() { return isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : ''; } // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- only searched for fixed words.

	/** One byte per request into a file named for the minute: the cheapest way to count a flood. */
	private static function tick() {
		$d = self::dir(); $f = $d . 'm' . gmdate( 'YmdHi' ) . '.cnt';
		$new = ! file_exists( $f );
		@file_put_contents( $f, '.', FILE_APPEND ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- must not slow down or break the request.
		if ( $new ) { foreach ( (array) glob( $d . 'm*.cnt' ) as $old ) { if ( $old !== $f && filemtime( $old ) < time() - 600 ) { @unlink( $old ); } } } // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.unlink_unlink
		clearstatcache( true, $f );
		return (int) filesize( $f );
	}

	/** Requests to the whole site in the current minute (0 when the counter has not run). */
	public static function last_minute() { $f = self::dir() . 'm' . gmdate( 'YmdHi' ) . '.cnt'; return is_file( $f ) ? (int) filesize( $f ) : 0; }

	/** Browser checks shown today. */
	public static function challenged_today() { $f = self::dir() . 'c' . gmdate( 'Ymd' ) . '.cnt'; return is_file( $f ) ? (int) filesize( $f ) : 0; }

	private static function trusted( $ip, $ua ) {
		$list = Botvanguard_Settings::lines( 'ip_allow' ); $list[] = '127.0.0.1'; $list[] = '::1';
		if ( '' !== $ip && Botvanguard_Guard::ip_in_list( $ip, $list ) ) { return true; }
		if ( Botvanguard_Guard::is_admin_ip( $ip ) ) { return true; }
		// Search engines and other bots that are welcome and prove who they are (the same check as bot blocking).
		$s = Botvanguard_Settings::all(); $ual = strtolower( $ua );
		foreach ( Botvanguard_Catalog::allowed() as $gk => $g ) {
			if ( empty( $s['allow'][ $gk ] ) ) { continue; }
			foreach ( $g['bots'] as $tok => $info ) {
				if ( '' === $tok || false === strpos( $ual, $tok ) ) { continue; }
				$suffixes = $info[1];
				if ( is_array( $suffixes ) && '' !== $ip ) { return 'fail' !== Botvanguard_Verify::check( $ip, $suffixes ); }
				return true;
			}
		}
		return false;
	}

	private static function prefix( $ip ) {
		if ( false !== strpos( $ip, ':' ) ) { return implode( ':', array_slice( explode( ':', $ip ), 0, 4 ) ); } // IPv6: the /64.
		$p = explode( '.', $ip ); return implode( '.', array_slice( $p, 0, 3 ) ); // IPv4: the /24, so a phone moving between nearby addresses keeps its pass.
	}

	private static function token( $ip, $ua, $exp ) { return $exp . '.' . hash_hmac( 'sha256', $exp . '|' . self::prefix( $ip ) . '|' . md5( $ua ), wp_salt( 'auth' ) ); }

	private static function cookie_ok( $ip, $ua, $s ) {
		if ( empty( $_COOKIE[ self::COOKIE ] ) || ! is_string( $_COOKIE[ self::COOKIE ] ) ) { return false; }
		$v = explode( '.', sanitize_text_field( wp_unslash( $_COOKIE[ self::COOKIE ] ) ) );
		if ( count( $v ) < 3 ) { return false; }
		$nonce = (string) array_pop( $v ); $tok = implode( '.', $v ); $exp = (int) $v[0];
		if ( $exp < time() || ! hash_equals( self::token( $ip, $ua, $exp ), $tok ) ) { return false; }
		if ( ! empty( $s['pow'] ) && 0 !== strpos( hash( 'sha256', $tok . '.' . $nonce ), '000' ) ) { return false; }
		return true;
	}

	private static function count_ip( $ip ) {
		$k = 'bvg_dr_' . md5( $ip );
		if ( function_exists( 'wp_using_ext_object_cache' ) && wp_using_ext_object_cache() ) { wp_cache_add( $k, 0, 'botvanguard', 60 ); $n = wp_cache_incr( $k, 1, 'botvanguard' ); return false === $n ? 1 : (int) $n; }
		$n = (int) get_transient( $k ) + 1; set_transient( $k, $n, MINUTE_IN_SECONDS ); return $n;
	}

	private static function stop_request( $code, $text, $extra = array() ) {
		if ( ! headers_sent() ) {
			http_response_code( $code ); header( 'Content-Type: text/plain; charset=utf-8' ); header( 'Cache-Control: no-store' ); header( 'X-Robots-Tag: noindex' ); header( 'Retry-After: 60' );
			foreach ( $extra as $h ) { header( $h ); }
		}
		echo esc_html( $text ); exit;
	}

	/** Runs early, before themes and most plugins. */
	public static function run() {
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || ( 'cli' === PHP_SAPI && empty( $_SERVER['REMOTE_ADDR'] ) ) ) { return; } // command line runs have no visitor.
		$s = self::all(); $why = self::status( $s );
		if ( '' === $why && 'auto' !== $s['mode'] ) { return; }
		$ip = Botvanguard_Guard::client_ip();
		if ( '' === $why ) { // automatic switch: count the request, and start the mode when the site gets more than it should.
			if ( self::tick() > (int) $s['auto_rate'] ) { update_option( self::UNTIL, time() + (int) $s['auto_minutes'] * MINUTE_IN_SECONDS, false ); update_option( 'botvanguard_ddos_how', 'auto', false ); Botvanguard_Log::add( 'block', 'ddos_start', $ip, self::ua(), self::uri() ); }
			return;
		}
		$ua = self::ua(); $uri = self::uri();
		if ( self::trusted( $ip, $ua ) ) { return; }
		if ( is_user_logged_in() ) { return; }
		foreach ( preg_split( '/\R/', (string) $s['exempt'], -1, PREG_SPLIT_NO_EMPTY ) as $x ) { if ( false !== strpos( $uri, trim( $x ) ) ) { return; } }
		$force = self::forced(); $rate = $s['rate_limit'];
		if ( defined( 'BOTVANGUARD_DDOS_RATE' ) && (int) BOTVANGUARD_DDOS_RATE > 0 ) { $rate = (int) BOTVANGUARD_DDOS_RATE; } elseif ( defined( 'BOTVAGUARD_DDOS_RATE' ) && (int) BOTVAGUARD_DDOS_RATE > 0 ) { $rate = (int) BOTVAGUARD_DDOS_RATE; }
		if ( 'constant' === $force || 'file' === $force ) { $s['challenge'] = 1; if ( ! $rate ) { $rate = 60; } }
		if ( $s['block_cron'] && false !== strpos( $uri, 'wp-cron.php' ) ) { self::stop_request( 403, 'Forbidden' ); }
		if ( '' !== $ip && Botvanguard_Bans::is_banned( $ip ) ) { self::stop_request( 403, 'Forbidden' ); }
		if ( ! $s['challenge'] ) {
			if ( $rate && '' !== $ip && self::count_ip( $ip ) > $rate ) { self::over_limit( $ip, $s ); }
			return;
		}
		if ( self::cookie_ok( $ip, $ua, $s ) ) {
			if ( $rate && '' !== $ip && self::count_ip( $ip ) > $rate ) { self::over_limit( $ip, $s ); }
			return;
		}
		self::challenge_page( $ip, $ua, $s );
	}

	private static function over_limit( $ip, $s ) {
		Botvanguard_Bans::add( $ip, (int) $s['ban_minutes'] * MINUTE_IN_SECONDS, 'DDoS: too many requests', 'auto' );
		Botvanguard_Log::add( 'block', 'ddos_rate', $ip, self::ua(), self::uri() );
		self::stop_request( 429, 'Too many requests. Please try again later.' );
	}

	private static function challenge_page( $ip, $ua, $s ) {
		@file_put_contents( self::dir() . 'c' . gmdate( 'Ymd' ) . '.cnt', '.', FILE_APPEND ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- counts the check, must never break the page.
		$life = (int) $s['cookie_hours'] * HOUR_IN_SECONDS; $tok = self::token( $ip, $ua, time() + $life );
		if ( ! headers_sent() ) {
			http_response_code( 503 ); header( 'Content-Type: text/html; charset=utf-8' ); header( 'Cache-Control: no-store, max-age=0' ); header( 'X-Robots-Tag: noindex' ); header( 'Retry-After: 5' );
		}
		$name = esc_html( wp_specialchars_decode( (string) get_option( 'blogname', '' ), ENT_QUOTES ) );
		$js = self::js( $tok, $life, ! empty( $s['pow'] ) );
		echo '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>' . esc_html( $name ) . '</title>'
			. '<style>body{font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#f6f7f7;color:#1d2327;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}div{text-align:center;padding:24px}small{color:#646970}</style></head><body><div>'
			. '<p><strong>' . esc_html__( 'Checking your browser before opening the site…', 'botvanguard' ) . '</strong></p><p><small>' . esc_html__( 'This takes a moment and protects the site from an attack. You will be sent on automatically.', 'botvanguard' ) . '</small></p>'
			. '<noscript><p>' . esc_html__( 'Please turn on JavaScript to continue.', 'botvanguard' ) . '</p></noscript></div><script>' . $js . '</script></body></html>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- the script is built from a signed token made of digits, letters and dots.
		exit;
	}

	/** The browser side: find a number that makes a SHA-256 hash start with three zeros, store it in a cookie, reload. */
	private static function js( $tok, $life, $pow ) {
		$tok = preg_replace( '/[^0-9a-f.]/', '', $tok );
		$sha = 'function S(ascii){function R(v,a){return(v>>>a)|(v<<(32-a))}var P=Math.pow,M=P(2,32),L=\'length\',i,j,res=\'\',W=[],B=ascii[L]*8,H=S.h=S.h||[],K=S.k=S.k||[],pc=K[L],C={};for(var c=2;pc<64;c++){if(!C[c]){for(i=0;i<313;i+=c){C[i]=c}H[pc]=(P(c,.5)*M)|0;K[pc++]=(P(c,1/3)*M)|0}}ascii+=\'\x80\';while(ascii[L]%64-56)ascii+=\'\x00\';for(i=0;i<ascii[L];i++){j=ascii.charCodeAt(i);if(j>>8)return;W[i>>2]|=j<<((3-i)%4)*8}W[W[L]]=((B/M)|0);W[W[L]]=B;for(j=0;j<W[L];){var w=W.slice(j,j+=16),o=H;H=H.slice(0,8);for(i=0;i<64;i++){var w15=w[i-15],w2=w[i-2],a=H[0],e=H[4],t1=H[7]+(R(e,6)^R(e,11)^R(e,25))+((e&H[5])^((~e)&H[6]))+K[i]+(w[i]=(i<16)?w[i]:(w[i-16]+(R(w15,7)^R(w15,18)^(w15>>>3))+w[i-7]+(R(w2,17)^R(w2,19)^(w2>>>10)))|0),t2=(R(a,2)^R(a,13)^R(a,22))+((a&H[1])^(a&H[2])^(H[1]&H[2]));H=[(t1+t2)|0].concat(H);H[4]=(H[4]+t1)|0}for(i=0;i<8;i++){H[i]=(H[i]+o[i])|0}}for(i=0;i<8;i++){for(j=3;j+1;j--){var b=(H[i]>>(j*8))&255;res+=((b<16)?0:\'\')+b.toString(16)}}return res}';
		$ck = 'document.cookie="' . self::COOKIE . '="+T+"."+n+"; path=/; max-age=' . (int) $life . '; SameSite=Lax"+(location.protocol=="https:"?"; Secure":"");location.reload();';
		if ( ! $pow ) { return 'var T="' . $tok . '",n=0;setTimeout(function(){' . $ck . '},1200);'; }
		return $sha . 'var T="' . $tok . '",n=0;(function f(){var e=Date.now();while(Date.now()-e<40){if(S(T+"."+n).indexOf("000")===0){' . $ck . 'return}n++}setTimeout(f,0)})();';
	}

	// ---- admin ----

	public static function start() {
		if ( ! current_user_can( 'manage_options' ) ) { wp_die( esc_html__( 'Not allowed.', 'botvanguard' ), 403 ); }
		check_admin_referer( 'botvanguard_ddos' );
		$m = isset( $_POST['minutes'] ) ? max( 5, min( 1440, (int) $_POST['minutes'] ) ) : 60;
		update_option( self::UNTIL, time() + $m * MINUTE_IN_SECONDS, false ); update_option( 'botvanguard_ddos_how', 'manual', false );
		wp_safe_redirect( admin_url( 'admin.php?page=botvanguard-ddos&bvg=started' ) ); exit;
	}

	public static function stop() {
		if ( ! current_user_can( 'manage_options' ) ) { wp_die( esc_html__( 'Not allowed.', 'botvanguard' ), 403 ); }
		check_admin_referer( 'botvanguard_ddos' );
		delete_option( self::UNTIL ); delete_option( 'botvanguard_ddos_how' );
		wp_safe_redirect( admin_url( 'admin.php?page=botvanguard-ddos&bvg=stopped' ) ); exit;
	}

	public static function tab( $base ) {
		$s = self::all(); $why = self::status( $s ); $O = self::OPTION;
		$labels = array( 'constant' => __( 'ON: forced by a line in wp-config.php', 'botvanguard' ), 'file' => __( 'ON: forced by the file wp-content/botvanguard-ddos', 'botvanguard' ), 'on' => __( 'ON: always on (setting below)', 'botvanguard' ), 'manual' => __( 'ON: started by hand', 'botvanguard' ), 'auto' => __( 'ON: started automatically because of a surge of requests', 'botvanguard' ) );
		$bvg = isset( $_GET['bvg'] ) ? sanitize_key( wp_unslash( $_GET['bvg'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only.
		if ( ( 'started' === $bvg && '' !== $why ) || ( 'stopped' === $bvg && '' === $why ) ) { echo '<div class="notice notice-success is-dismissible"><p>' . esc_html( 'started' === $bvg ? __( 'Attack mode is on.', 'botvanguard' ) : __( 'Attack mode is off.', 'botvanguard' ) ) . '</p></div>'; }
		echo '<p style="max-width:820px">' . esc_html__( 'A DDoS attack sends so many requests that your site slows down or stops. Attack mode makes every visitor pass a short browser check before WordPress does any real work. Attack tools almost never pass it, real visitors do in a moment. Search engines you allow and logged-in users are never asked.', 'botvanguard' ) . '</p>';
		echo '<div class="notice notice-' . ( '' === $why ? 'info' : 'warning' ) . ' inline" style="max-width:820px"><p><strong>' . esc_html__( 'Status:', 'botvanguard' ) . '</strong> ' . esc_html( '' === $why ? __( 'Off (watching: it starts by itself on a surge, if set to Automatic below)', 'botvanguard' ) : $labels[ $why ] ) . '</p>';
		$until = (int) get_option( self::UNTIL, 0 ); if ( $until > time() && in_array( $why, array( 'auto', 'manual' ), true ) ) { echo '<p>' . esc_html( sprintf( /* translators: %s: time */ __( 'It switches off in %s.', 'botvanguard' ), human_time_diff( time(), $until ) ) ) . '</p>'; }
		echo '<p>' . esc_html( sprintf( /* translators: 1: requests this minute 2: checks today */ __( 'Requests to your site this minute (counted while Automatic or on): %1$s. Browser checks shown today: %2$s.', 'botvanguard' ), number_format_i18n( self::last_minute() ), number_format_i18n( self::challenged_today() ) ) ) . '</p></div>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="margin:12px 0">'; wp_nonce_field( 'botvanguard_ddos' );
		if ( in_array( $why, array( 'auto', 'manual' ), true ) ) { echo '<input type="hidden" name="action" value="botvanguard_ddos_stop"><button class="button">' . esc_html__( 'Switch attack mode off now', 'botvanguard' ) . '</button>'; }
		elseif ( '' === $why ) { echo '<input type="hidden" name="action" value="botvanguard_ddos_start"><label>' . esc_html__( 'Switch it on for', 'botvanguard' ) . ' <select name="minutes"><option value="30">30 ' . esc_html__( 'minutes', 'botvanguard' ) . '</option><option value="60" selected>1 ' . esc_html__( 'hour', 'botvanguard' ) . '</option><option value="240">4 ' . esc_html__( 'hours', 'botvanguard' ) . '</option><option value="1440">24 ' . esc_html__( 'hours', 'botvanguard' ) . '</option></select></label> <button class="button button-primary">' . esc_html__( 'Start attack mode', 'botvanguard' ) . '</button>'; }
		echo '</form>';
		echo '<h2>' . esc_html__( 'Settings', 'botvanguard' ) . '</h2><form method="post" action="options.php">'; settings_fields( 'botvanguard_ddos_group' );
		$num = function ( $k, $min, $max ) use ( $s, $O ) { return '<input type="number" class="small-text" min="' . (int) $min . '" max="' . (int) $max . '" name="' . esc_attr( $O ) . '[' . esc_attr( $k ) . ']" value="' . (int) $s[ $k ] . '">'; };
		$chk = function ( $k, $l ) use ( $s, $O ) { return '<p><label><input type="checkbox" name="' . esc_attr( $O ) . '[' . esc_attr( $k ) . ']" value="1" ' . checked( ! empty( $s[ $k ] ), true, false ) . '> ' . esc_html( $l ) . '</label></p>'; };
		echo '<p>';
		foreach ( array( 'off' => __( 'Off: never start by itself (you can still start it by hand or from wp-config.php)', 'botvanguard' ), 'auto' => __( 'Automatic (recommended): start by itself when the site gets a surge of requests', 'botvanguard' ), 'on' => __( 'Always on: every visitor passes the browser check (only for sites under constant attack)', 'botvanguard' ) ) as $k => $l ) { echo '<label style="display:block;margin:3px 0"><input type="radio" name="' . esc_attr( $O ) . '[mode]" value="' . esc_attr( $k ) . '" ' . checked( $s['mode'], $k, false ) . '> ' . esc_html( $l ) . '</label>'; }
		echo '</p><p>' . esc_html__( 'Automatic start: when the whole site gets more than', 'botvanguard' ) . ' ' . $num( 'auto_rate', 30, 100000 ) . ' ' . esc_html__( 'requests in one minute, stay on for', 'botvanguard' ) . ' ' . $num( 'auto_minutes', 5, 1440 ) . ' ' . esc_html__( 'minutes.', 'botvanguard' ) . '</p>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $num() escapes its parts.
		echo $chk( 'challenge', __( 'Ask visitors for the browser check', 'botvanguard' ) ) . $chk( 'pow', __( 'Include a small calculation in the check (makes it costlier for attack tools; a few seconds at most on an old phone)', 'botvanguard' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $chk() escapes.
		echo '<p>' . esc_html__( 'A visitor who passed is not asked again for', 'botvanguard' ) . ' ' . $num( 'cookie_hours', 1, 72 ) . ' ' . esc_html__( 'hours.', 'botvanguard' ) . '</p>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo '<p>' . esc_html__( 'Limit: no more than', 'botvanguard' ) . ' ' . $num( 'rate_limit', 0, 5000 ) . ' ' . esc_html__( 'requests a minute from one address (0 = no limit); an address that goes over is blocked for', 'botvanguard' ) . ' ' . $num( 'ban_minutes', 1, 1440 ) . ' ' . esc_html__( 'minutes.', 'botvanguard' ) . '</p>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo $chk( 'block_cron', __( 'Refuse outside calls to wp-cron.php while attack mode is on (a favourite target)', 'botvanguard' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo '<p><label for="bvg-ex"><strong>' . esc_html__( 'Never asked (part of the address, one per line)', 'botvanguard' ) . '</strong></label><br><textarea id="bvg-ex" name="' . esc_attr( $O ) . '[exempt]" rows="4" class="large-text code">' . esc_textarea( $s['exempt'] ) . '</textarea><br><span class="description">' . esc_html__( 'Payment and webhook callbacks come from servers, not browsers, so they cannot pass the check. The defaults cover WooCommerce (wc-api). Add the address of any other callback, for example /wp-json/stripe/.', 'botvanguard' ) . '</span></p>';
		submit_button( __( 'Save DDoS settings', 'botvanguard' ) ); echo '</form>';
		echo '<h2>' . esc_html__( 'Under attack and cannot log in?', 'botvanguard' ) . '</h2><div style="max-width:820px"><p>' . esc_html__( 'Use FTP or your host’s file manager. Either of these switches attack mode on at once, without the dashboard:', 'botvanguard' ) . '</p>';
		echo '<p><strong>1.</strong> ' . esc_html__( 'Add this line to wp-config.php, above the line that says “That’s all, stop editing”:', 'botvanguard' ) . '</p><pre style="user-select:all;background:#fff;border:1px solid #c3c4c7;padding:8px">define( \'BOTVANGUARD_DDOS\', true );</pre>';
		echo '<p><strong>2.</strong> ' . esc_html__( 'Or upload an empty file named botvanguard-ddos (no extension) to the wp-content folder.', 'botvanguard' ) . '</p>';
		echo '<p>' . esc_html__( 'Optional, stricter: set how many requests a minute one address may make with', 'botvanguard' ) . ' <code>define( \'BOTVANGUARD_DDOS_RATE\', 30 );</code>. ' . esc_html__( 'When the attack is over, remove the line or delete the file.', 'botvanguard' ) . '</p>';
		echo '<p class="description">' . esc_html__( 'Honest limits: this protects your WordPress site from floods of web requests. It cannot stop an attack that fills your server’s internet connection. For that, put the site behind a CDN such as Cloudflare (turn on its “Under Attack” mode) or ask your host for DDoS protection.', 'botvanguard' ) . '</p></div>';
	}
}
