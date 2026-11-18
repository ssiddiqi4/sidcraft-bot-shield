<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

// phpcs:disable WordPress.Security.NonceVerification -- the login screens are verified by their own one-time token, not by a nonce.

/** Two-factor login: email code, authenticator app, text message (Twilio), passkey, and recovery codes. */
class Sidcraft_BotShield_TwoFa {
	private static $done = false;

	public static function init() {
		if ( defined( 'SIDCRAFT_BOTSHIELD_DISABLE_2FA' ) && SIDCRAFT_BOTSHIELD_DISABLE_2FA ) { return; }
		add_action( 'wp_login', array( __CLASS__, 'intercept' ), 1, 2 );
		add_filter( 'authenticate', array( __CLASS__, 'xmlrpc_gate' ), 100, 1 );
		add_action( 'login_form_sbs2fa', array( __CLASS__, 'challenge_request' ) );
		add_action( 'show_user_profile', array( __CLASS__, 'profile' ) );
		add_action( 'edit_user_profile', array( __CLASS__, 'profile' ) );
		add_action( 'admin_init', array( __CLASS__, 'profile_action' ), 1 );
		add_action( 'wp_ajax_sidcraft_botshield_pk_reg', array( __CLASS__, 'pk_register_ajax' ) );
		add_action( 'admin_init', array( __CLASS__, 'enforce' ) );
		add_action( 'admin_notices', array( __CLASS__, 'notice' ) );
	}

	// ---------- who needs it ----------
	public static function user_methods( $uid ) {
		$m = get_user_meta( $uid, 'sbs2fa_methods', true ); $m = is_array( $m ) ? $m : array();
		return array_values( array_intersect( $m, Sidcraft_BotShield_LoginSettings::methods_enabled() ) );
	}

	private static function required_for( $user ) {
		$s = Sidcraft_BotShield_LoginSettings::all();
		return $s['tfa_on'] && array_intersect( (array) $user->roles, (array) $s['tfa_roles'] );
	}

	/** XML-RPC has no second step, so users with two-factor login must use an application password there. */
	public static function xmlrpc_gate( $user ) {
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST && $user instanceof WP_User && Sidcraft_BotShield_LoginSettings::get( 'tfa_on' ) && self::user_methods( $user->ID ) && ! did_action( 'application_password_did_authenticate' ) ) {
			return new WP_Error( 'sbs_2fa_xmlrpc', __( 'This account uses two-factor login. Use an application password for XML-RPC.', 'sidcraft-bot-shield' ) );
		}
		return $user;
	}

	// ---------- login ----------
	/** Right after a correct password: take the login cookie back and ask for the second step. */
	public static function intercept( $login, $user ) {
		if ( self::$done || ! Sidcraft_BotShield_LoginSettings::get( 'tfa_on' ) || ! $user instanceof WP_User ) { return; }
		if ( ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) || wp_doing_cron() || 'cli' === PHP_SAPI ) { return; }
		$methods = self::user_methods( $user->ID );
		if ( ! $methods ) { return; }
		wp_clear_auth_cookie();
		$token = wp_generate_password( 32, false );
		$redirect = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : '';
		set_transient( 'sbs2fa_' . $token, array( 'uid' => $user->ID, 'remember' => ! empty( $_POST['rememberme'] ), 'redirect' => $redirect, 'tries' => 0, 'ip' => Sidcraft_BotShield_Guard::client_ip() ), 10 * MINUTE_IN_SECONDS );
		if ( 'email' === $methods[0] ) { self::send_email_code( $token, $user ); }
		if ( 'sms' === $methods[0] ) { self::send_sms_code( $token, $user ); }
		self::render( $token, $user, '' );
		exit;
	}

	private static function session( $token ) { $s = get_transient( 'sbs2fa_' . $token ); return is_array( $s ) ? $s : null; }
	private static function save( $token, $s ) { set_transient( 'sbs2fa_' . $token, $s, 10 * MINUTE_IN_SECONDS ); }

	private static function login_url( $args = array() ) { return add_query_arg( $args, site_url( 'wp-login.php', 'login' ) ); }

	/** Handles every request of the second step (wp-login.php?action=sbs2fa). */
	public static function challenge_request() {
		$token = isset( $_REQUEST['sbs_token'] ) ? preg_replace( '/[^A-Za-z0-9]/', '', sanitize_text_field( wp_unslash( $_REQUEST['sbs_token'] ) ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- the one-time token is the credential for this step
		$s = self::session( $token ); $user = $s ? get_userdata( $s['uid'] ) : null;
		$op = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		if ( ! $s || ! $user ) { if ( 'pk_begin' === $op || 'pk_finish' === $op ) { wp_send_json_error( array( 'message' => __( 'This login expired. Please sign in again.', 'sidcraft-bot-shield' ) ) ); } wp_safe_redirect( add_query_arg( 'sbs2fa', 'expired', self::login_url() ) ); exit; }
		if ( 'post' !== ( isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '' ) ) { self::render( $token, $user, '' ); exit; }
		$methods = self::user_methods( $user->ID ); $msg = '';
		if ( 'send_email' === $op && in_array( 'email', $methods, true ) ) { $msg = self::send_email_code( $token, $user ) ? __( 'We emailed you a code.', 'sidcraft-bot-shield' ) : __( 'Please wait a minute before asking for another code.', 'sidcraft-bot-shield' ); self::render( $token, $user, '', $msg, 'email' ); exit; }
		if ( 'send_sms' === $op && in_array( 'sms', $methods, true ) ) { $r = self::send_sms_code( $token, $user ); self::render( $token, $user, is_wp_error( $r ) ? $r->get_error_message() : '', is_wp_error( $r ) ? '' : __( 'We sent you a text message.', 'sidcraft-bot-shield' ), 'sms' ); exit; }
		if ( 'pk_begin' === $op && in_array( 'passkey', $methods, true ) ) {
			$ch = random_bytes( 32 ); $s['pk'] = Sidcraft_BotShield_WebAuthn::b64u( $ch ); self::save( $token, $s );
			wp_send_json_success( Sidcraft_BotShield_WebAuthn::request_options( $ch, (array) get_user_meta( $user->ID, 'sbs2fa_passkeys', true ) ) );
		}
		if ( 'pk_finish' === $op && in_array( 'passkey', $methods, true ) && ! empty( $s['pk'] ) ) {
			$in = json_decode( isset( $_POST['assertion'] ) ? (string) wp_unslash( $_POST['assertion'] ) : '', true ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- JSON from the browser; every field is verified cryptographically
			 $creds = (array) get_user_meta( $user->ID, 'sbs2fa_passkeys', true );
			$res = is_array( $in ) ? Sidcraft_BotShield_WebAuthn::verify_assertion( $in, Sidcraft_BotShield_WebAuthn::unb64u( $s['pk'] ), $creds ) : new WP_Error( 'sbs_pk', 'Bad response.' );
			unset( $s['pk'] ); self::save( $token, $s );
			if ( is_wp_error( $res ) ) { self::fail( $token, $s, $user ); wp_send_json_error( array( 'message' => $res->get_error_message() ) ); }
			update_user_meta( $user->ID, 'sbs2fa_passkeys', $res );
			wp_send_json_success( array( 'redirect' => self::finish( $token, $s, $user, true ) ) );
		}
		if ( 'verify' === $op ) {
			$code = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : ''; $method = isset( $_POST['method'] ) ? sanitize_key( wp_unslash( $_POST['method'] ) ) : '';
			if ( self::check_code( $user, $method, $code, $s, $token ) ) { self::finish( $token, $s, $user ); }
			$left = self::fail( $token, $s, $user );
			self::render( $token, $user, $left > 0 ? __( 'That code is not right. Try again.', 'sidcraft-bot-shield' ) : '', '', $method );
			exit;
		}
		$m = isset( $_POST['method'] ) ? sanitize_key( wp_unslash( $_POST['method'] ) ) : '';
		self::render( $token, $user, '', '', $m ); exit;
	}

	/** Count a failed second step; too many and the login is cancelled. Returns the attempts left. */
	private static function fail( $token, $s, $user ) {
		$s['tries']++; do_action( 'wp_login_failed', // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core hook
			 $user->user_login, new WP_Error( 'sbs_2fa', 'Wrong second step' ) );
		if ( $s['tries'] >= 5 ) { delete_transient( 'sbs2fa_' . $token ); wp_safe_redirect( add_query_arg( 'sbs2fa', 'toomany', self::login_url() ) ); exit; }
		self::save( $token, $s ); return 5 - $s['tries'];
	}

	private static function check_code( $user, $method, $code, &$s, $token ) {
		$code = trim( $code ); if ( '' === $code ) { return false; }
		$methods = self::user_methods( $user->ID );
		if ( 'recovery' === $method ) {
			$h = (array) get_user_meta( $user->ID, 'sbs2fa_recovery', true ); $norm = strtolower( preg_replace( '/[^a-z0-9]/i', '', $code ) );
			foreach ( $h as $i => $hash ) { if ( wp_check_password( $norm, $hash ) ) { unset( $h[ $i ] ); update_user_meta( $user->ID, 'sbs2fa_recovery', array_values( $h ) ); return true; } }
			return false;
		}
		if ( ! in_array( $method, $methods, true ) ) { return false; }
		if ( 'totp' === $method ) {
			$secret = (string) get_user_meta( $user->ID, 'sbs2fa_totp', true ); $step = $secret ? Sidcraft_BotShield_Totp::verify( $secret, $code ) : 0;
			if ( $step && $step > (int) get_user_meta( $user->ID, 'sbs2fa_totp_last', true ) ) { update_user_meta( $user->ID, 'sbs2fa_totp_last', $step ); return true; }
			return false;
		}
		$key = 'email' === $method ? 'email' : 'sms';
		if ( 'email' === $method || 'sms' === $method ) {
			$c = $s[ $key ] ?? null; $code = preg_replace( '/\s+/', '', $code );
			if ( is_array( $c ) && $c['exp'] > time() && hash_equals( $c['hash'], hash_hmac( 'sha256', $code, wp_salt( 'auth' ) ) ) ) { unset( $s[ $key ] ); self::save( $token, $s ); return true; }
		}
		return false;
	}

	private static function finish( $token, $s, $user, $return_url = false ) {
		delete_transient( 'sbs2fa_' . $token ); self::$done = true;
		wp_set_current_user( $user->ID ); wp_set_auth_cookie( $user->ID, $s['remember'] );
		do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core hook, fired so other plugins see a normal login
		$to = '' !== $s['redirect'] ? $s['redirect'] : admin_url();
		$to = apply_filters( 'login_redirect', $to, $s['redirect'], $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core hook, fired so other plugins see a normal login
		$to = wp_validate_redirect( $to, admin_url() );
		if ( $return_url ) { return $to; }
		wp_safe_redirect( $to ); exit;
	}

	// ---------- sending codes ----------
	private static function new_code( $token, $s, $key ) {
		$code = (string) wp_rand( 100000, 999999 );
		$s[ $key ] = array( 'hash' => hash_hmac( 'sha256', $code, wp_salt( 'auth' ) ), 'exp' => time() + 10 * MINUTE_IN_SECONDS, 'sent' => time() );
		self::save( $token, $s ); return $code;
	}

	public static function send_email_code( $token, $user ) {
		$s = self::session( $token ); if ( ! $s || ( ! empty( $s['email']['sent'] ) && time() - $s['email']['sent'] < 60 ) ) { return false; }
		$code = self::new_code( $token, $s, 'email' ); $site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		/* translators: %s: site name */
		return wp_mail( $user->user_email, sprintf( __( '[%s] Your login code', 'sidcraft-bot-shield' ), $site ), sprintf( /* translators: 1: code 2: IP address */ __( "Your login code is %1\$s\n\nIt works for 10 minutes. It was asked for from the address %2\$s. If this was not you, change your password.", 'sidcraft-bot-shield' ), $code, Sidcraft_BotShield_Guard::client_ip() ) );
	}

	public static function send_sms_code( $token, $user ) {
		$s = self::session( $token ); if ( ! $s ) { return new WP_Error( 'sbs', __( 'Expired.', 'sidcraft-bot-shield' ) ); }
		if ( ! empty( $s['sms']['sent'] ) && time() - $s['sms']['sent'] < 60 ) { return new WP_Error( 'sbs', __( 'Please wait a minute before asking for another text message.', 'sidcraft-bot-shield' ) ); }
		$phone = (string) get_user_meta( $user->ID, 'sbs2fa_sms', true ); $code = self::new_code( $token, $s, 'sms' );
		return self::sms( $phone, sprintf( /* translators: 1: site 2: code */ __( '%1$s login code: %2$s', 'sidcraft-bot-shield' ), wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ), $code ) );
	}

	/** Send a text message through Twilio. Returns true or WP_Error. */
	public static function sms( $to, $body ) {
		$o = Sidcraft_BotShield_LoginSettings::all();
		if ( '' === $o['twilio_sid'] || '' === $o['twilio_token'] || '' === $o['twilio_from'] || ! preg_match( '/^\+[1-9]\d{6,14}$/', $to ) ) { return new WP_Error( 'sbs', __( 'Text messages are not set up.', 'sidcraft-bot-shield' ) ); }
		$r = wp_safe_remote_post( 'https://api.twilio.com/2010-04-01/Accounts/' . rawurlencode( $o['twilio_sid'] ) . '/Messages.json', array( 'timeout' => 10, 'headers' => array( 'Authorization' => 'Basic ' . base64_encode( $o['twilio_sid'] . ':' . $o['twilio_token'] ) ), 'body' => array( 'To' => $to, 'From' => $o['twilio_from'], 'Body' => $body ) ) );
		if ( is_wp_error( $r ) ) { return new WP_Error( 'sbs', __( 'The text message could not be sent.', 'sidcraft-bot-shield' ) ); }
		$code = (int) wp_remote_retrieve_response_code( $r );
		return ( $code >= 200 && $code < 300 ) ? true : new WP_Error( 'sbs', __( 'The text message could not be sent. Check the SMS settings.', 'sidcraft-bot-shield' ) );
	}

	// ---------- the second-step page ----------
	private static function render( $token, $user, $error, $notice = '', $active = '' ) {
		$methods = self::user_methods( $user->ID ); $active = in_array( $active, $methods, true ) || 'recovery' === $active ? $active : $methods[0];
		$names = array( 'email' => __( 'Email code', 'sidcraft-bot-shield' ), 'totp' => __( 'Authenticator app', 'sidcraft-bot-shield' ), 'sms' => __( 'Text message', 'sidcraft-bot-shield' ), 'passkey' => __( 'Passkey', 'sidcraft-bot-shield' ), 'recovery' => __( 'Recovery code', 'sidcraft-bot-shield' ) );
		$all = $methods; if ( get_user_meta( $user->ID, 'sbs2fa_recovery', true ) ) { $all[] = 'recovery'; }
		$action = esc_url( site_url( 'wp-login.php?action=sbs2fa', 'login_post' ) );
		nocache_headers(); header( 'Content-Type: text/html; charset=UTF-8' ); header( 'X-Robots-Tag: noindex' );
		echo '<!DOCTYPE html><html lang="' . esc_attr( get_bloginfo( 'language' ) ) . '"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>' . esc_html__( 'Two-step login', 'sidcraft-bot-shield' ) . '</title><style>body{background:#f0f0f1;font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:#3c434a;margin:0}.c{max-width:360px;margin:8vh auto;background:#fff;border:1px solid #c3c4c7;box-shadow:0 1px 3px rgba(0,0,0,.04);padding:26px 24px}h1{font-size:20px;margin:0 0 6px}p{margin:8px 0}.e{border-left:4px solid #d63638;background:#fcf0f1;padding:8px 12px;margin:12px 0}.n{border-left:4px solid #00a32a;background:#edfaef;padding:8px 12px;margin:12px 0}input[type=text]{width:100%;box-sizing:border-box;font-size:22px;letter-spacing:.2em;text-align:center;padding:8px;border:1px solid #8c8f94;border-radius:4px}button{font:inherit;background:#2271b1;color:#fff;border:1px solid #2271b1;border-radius:3px;padding:8px 14px;cursor:pointer;margin-top:10px}button.s{background:#f6f7f7;color:#2271b1;border-color:#2271b1}.t{margin-top:16px;font-size:13px}.t a{color:#2271b1;text-decoration:none;margin-right:10px;white-space:nowrap;display:inline-block}.t a.on{font-weight:600;color:#1d2327}</style></head><body><div class="c"><h1>' . esc_html__( 'Check your second step', 'sidcraft-bot-shield' ) . '</h1><p>' . esc_html( sprintf( /* translators: %s: user name */ __( 'Hello %s. Confirm that it is you.', 'sidcraft-bot-shield' ), $user->display_name ) ) . '</p>';
		if ( '' !== $error ) { echo '<div class="e">' . esc_html( $error ) . '</div>'; }
		if ( '' !== $notice ) { echo '<div class="n">' . esc_html( $notice ) . '</div>'; }
		echo '<form method="post" action="' . $action . '" id="sbs-f">'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped above.
		echo '<input type="hidden" name="sbs_token" value="' . esc_attr( $token ) . '"><input type="hidden" name="op" value="verify"><input type="hidden" name="method" value="' . esc_attr( $active ) . '">';
		if ( 'passkey' === $active ) {
			echo '<p>' . esc_html__( 'Use your passkey or security key.', 'sidcraft-bot-shield' ) . '</p><button type="button" id="sbs-pk">' . esc_html__( 'Use passkey', 'sidcraft-bot-shield' ) . '</button><p id="sbs-pk-msg" class="e" style="display:none"></p>';
		} else {
			$hint = array( 'email' => __( 'Enter the 6-digit code we emailed you.', 'sidcraft-bot-shield' ), 'totp' => __( 'Enter the 6-digit code from your authenticator app.', 'sidcraft-bot-shield' ), 'sms' => __( 'Enter the 6-digit code from the text message.', 'sidcraft-bot-shield' ), 'recovery' => __( 'Enter one of your recovery codes. Each works once.', 'sidcraft-bot-shield' ) );
			echo '<p>' . esc_html( $hint[ $active ] ) . '</p><input type="text" name="code" autocomplete="one-time-code" inputmode="' . ( 'recovery' === $active ? 'text' : 'numeric' ) . '" autofocus required><button type="submit">' . esc_html__( 'Log in', 'sidcraft-bot-shield' ) . '</button>';
			if ( 'email' === $active || 'sms' === $active ) { echo ' <button type="submit" class="s" formnovalidate onclick="this.form.op.value=\'send_' . esc_attr( $active ) . '\'">' . esc_html__( 'Send a new code', 'sidcraft-bot-shield' ) . '</button>'; }
		}
		echo '</form>';
		if ( count( $all ) > 1 ) { echo '<div class="t">'; foreach ( $all as $m ) { echo '<a class="' . ( $m === $active ? 'on' : '' ) . '" href="#" onclick="var f=document.getElementById(\'sbs-f\');f.op.value=\'' . ( in_array( $m, array( 'email', 'sms' ), true ) ? 'send_' . esc_attr( $m ) : 'switch' ) . '\';f.method.value=\'' . esc_attr( $m ) . '\';f.submit();return false">' . esc_html( $names[ $m ] ) . '</a>'; } echo '</div>'; }
		echo '<p class="t"><a href="' . esc_url( self::login_url() ) . '">&larr; ' . esc_html__( 'Back to login', 'sidcraft-bot-shield' ) . '</a></p></div>';
		if ( 'passkey' === $active ) { self::passkey_login_js( $token ); }
		echo '</body></html>';
	}

	private static function passkey_login_js( $token ) {
		$cfg = wp_json_encode( array( 'url' => site_url( 'wp-login.php?action=sbs2fa', 'login_post' ), 'token' => $token ) );
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $cfg is wp_json_encode() output and the rest is a fixed script.
		echo '<script>(function(){var C=' . $cfg . ';function d(s){s=s.replace(/-/g,"+").replace(/_/g,"/");while(s.length%4)s+="=";var b=atob(s),a=new Uint8Array(b.length);for(var i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a.buffer}function e(b){var a=new Uint8Array(b),s="";for(var i=0;i<a.length;i++)s+=String.fromCharCode(a[i]);return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"")}' .
			'var m=document.getElementById("sbs-pk-msg");function err(t){m.style.display="block";m.textContent=t}function post(op,x){var p=new URLSearchParams();p.set("sbs_token",C.token);p.set("op",op);for(var k in x||{})p.set(k,x[k]);return fetch(C.url,{method:"POST",credentials:"same-origin",body:p}).then(function(r){return r.json()})}' .
			'function go(){if(!window.PublicKeyCredential){err("This browser does not support passkeys.");return}post("pk_begin").then(function(r){if(!r.success)throw new Error(r.data.message);var o=r.data;o.challenge=d(o.challenge);o.allowCredentials=o.allowCredentials.map(function(c){return{type:c.type,id:d(c.id)}});return navigator.credentials.get({publicKey:o})}).then(function(c){var x=c.response;return post("pk_finish",{assertion:JSON.stringify({id:e(c.rawId),clientDataJSON:e(x.clientDataJSON),authenticatorData:e(x.authenticatorData),signature:e(x.signature)})})}).then(function(r){if(!r.success)throw new Error(r.data.message);location.href=r.data.redirect}).catch(function(x){err(x.message||"Passkey failed")})}' .
			'document.getElementById("sbs-pk").addEventListener("click",go);setTimeout(go,300)})();</script>';
	}

	// ---------- required roles ----------
	public static function enforce() {
		if ( wp_doing_ajax() || defined( 'DOING_CRON' ) || ! is_user_logged_in() ) { return; }
		$u = wp_get_current_user(); $s = Sidcraft_BotShield_LoginSettings::all();
		if ( ! self::required_for( $u ) || self::user_methods( $u->ID ) || ! Sidcraft_BotShield_LoginSettings::methods_enabled() ) { return; }
		$deadline = (int) $s['tfa_since'] + (int) $s['tfa_grace'] * DAY_IN_SECONDS;
		global $pagenow; if ( time() < $deadline || in_array( $pagenow, array( 'profile.php', 'admin-post.php', 'admin-ajax.php', 'async-upload.php' ), true ) ) { return; }
		wp_safe_redirect( admin_url( 'profile.php#sbs2fa' ) ); exit;
	}

	public static function notice() {
		if ( ! is_user_logged_in() ) { return; }
		$u = wp_get_current_user();
		if ( self::required_for( $u ) && ! self::user_methods( $u->ID ) && Sidcraft_BotShield_LoginSettings::methods_enabled() ) {
			$left = (int) Sidcraft_BotShield_LoginSettings::get( 'tfa_since' ) + (int) Sidcraft_BotShield_LoginSettings::get( 'tfa_grace' ) * DAY_IN_SECONDS - time();
			echo '<div class="notice notice-warning"><p><strong>' . esc_html__( 'Set up two-factor login.', 'sidcraft-bot-shield' ) . '</strong> ' . esc_html( $left > 0 ? sprintf( /* translators: %s: time */ __( 'Your role must use a second login step. You have %s left.', 'sidcraft-bot-shield' ), human_time_diff( time(), time() + $left ) ) : __( 'Your role must use a second login step before you can continue.', 'sidcraft-bot-shield' ) ) . ' <a href="' . esc_url( admin_url( 'profile.php#sbs2fa' ) ) . '">' . esc_html__( 'Set it up now', 'sidcraft-bot-shield' ) . '</a></p></div>';
		}
		$codes = get_transient( 'sbs2fa_codes_' . $u->ID );
		if ( is_array( $codes ) ) { echo '<div class="notice notice-success"><p><strong>' . esc_html__( 'Your recovery codes. Save them now; they are shown only once and each works one time:', 'sidcraft-bot-shield' ) . '</strong></p><p style="font:14px/1.9 monospace;column-count:2;max-width:360px">' . esc_html( implode( "\n", $codes ) ) . '</p></div>'; delete_transient( 'sbs2fa_codes_' . $u->ID ); }
		if ( isset( $_GET['sbs2fa_msg'] ) ) { echo '<div class="notice notice-info is-dismissible"><p>' . esc_html( sanitize_text_field( wp_unslash( $_GET['sbs2fa_msg'] ) ) ) . '</p></div>'; }
	}

	// ---------- profile ----------
	public static function profile( $user ) {
		$s = Sidcraft_BotShield_LoginSettings::all(); $all = Sidcraft_BotShield_LoginSettings::methods_enabled();
		if ( ! $s['tfa_on'] || ! $all ) { return; }
		$own = get_current_user_id() === $user->ID; $admin = current_user_can( 'manage_options' );
		if ( ! $own && ! $admin ) { return; }
		$have = (array) get_user_meta( $user->ID, 'sbs2fa_methods', true );
		echo '<h2 id="sbs2fa">' . esc_html__( 'Two-factor login', 'sidcraft-bot-shield' ) . '</h2><table class="form-table" role="presentation"><tbody>';
		// The profile page is one big form, and forms cannot be nested: every button here sends the page's own form to this same page, where profile_action() picks it up before WordPress saves the profile.
		$self = $own ? admin_url( 'profile.php' ) : admin_url( 'user-edit.php?user_id=' . (int) $user->ID );
		echo '<input type="hidden" name="sbs_uid" value="' . (int) $user->ID . '">'; wp_nonce_field( 'sbs2fa_' . $user->ID, 'sbs_nonce', false );
		$act = function ( $op, $label, $extra = '', $cls = 'button' ) use ( $self ) { return $extra . '<button type="submit" formnovalidate formaction="' . esc_url( $self ) . '" name="sbs_op" value="' . esc_attr( $op ) . '" class="' . esc_attr( $cls ) . '" style="margin:0 6px 6px 0">' . esc_html( $label ) . '</button>'; };
		$allowed = array( 'form' => array( 'method' => array(), 'action' => array(), 'style' => array() ), 'input' => array( 'type' => array(), 'name' => array(), 'value' => array(), 'id' => array(), 'placeholder' => array(), 'class' => array(), 'autocomplete' => array(), 'inputmode' => array(), 'style' => array(), 'required' => array() ), 'button' => array( 'class' => array(), 'type' => array(), 'id' => array(), 'name' => array(), 'value' => array(), 'formaction' => array(), 'formnovalidate' => array(), 'style' => array() ), 'svg' => array( 'xmlns' => array(), 'width' => array(), 'height' => array(), 'viewbox' => array(), 'role' => array(), 'aria-label' => array() ), 'rect' => array( 'width' => array(), 'height' => array(), 'fill' => array() ), 'path' => array( 'd' => array(), 'fill' => array() ), 'code' => array(), 'p' => array( 'class' => array() ), 'br' => array(), 'strong' => array(), 'span' => array( 'class' => array(), 'style' => array(), 'id' => array() ) );
		$row = function ( $label, $html ) use ( $allowed ) { echo '<tr><th>' . esc_html( $label ) . '</th><td>' . wp_kses( $html, $allowed ) . '</td></tr>'; };
		if ( in_array( 'email', $all, true ) ) { $row( __( 'Email code', 'sidcraft-bot-shield' ), in_array( 'email', $have, true ) ? '<strong>' . esc_html__( 'On', 'sidcraft-bot-shield' ) . '</strong> — ' . esc_html( $user->user_email ) . '<br>' . $act( 'email_off', __( 'Turn off', 'sidcraft-bot-shield' ) ) : esc_html( sprintf( /* translators: %s: email address */ __( 'A code is sent to %s at login.', 'sidcraft-bot-shield' ), $user->user_email ) ) . '<br>' . $act( 'email_on', __( 'Turn on', 'sidcraft-bot-shield' ), '', 'button button-primary' ) ); }
		if ( in_array( 'totp', $all, true ) ) {
			if ( in_array( 'totp', $have, true ) ) { $h = '<strong>' . esc_html__( 'On', 'sidcraft-bot-shield' ) . '</strong><br>' . $act( 'totp_off', __( 'Remove', 'sidcraft-bot-shield' ) ); }
			elseif ( $own ) {
				$pending = get_user_meta( $user->ID, 'sbs2fa_totp_pending', true );
				if ( $pending ) { $uri = Sidcraft_BotShield_Totp::uri( $pending, $user->user_email ); $h = Sidcraft_BotShield_Qr::svg( $uri, 4 ) . '<p>' . esc_html__( 'Scan the code with Google Authenticator, Microsoft Authenticator, Authy or 1Password. Or type this key:', 'sidcraft-bot-shield' ) . '<br><code>' . esc_html( trim( chunk_split( $pending, 4, ' ' ) ) ) . '</code></p>' . $act( 'totp_confirm', __( 'Turn on', 'sidcraft-bot-shield' ), '<input type="text" name="sbs_code" placeholder="123456" inputmode="numeric" autocomplete="one-time-code" style="width:110px"> ', 'button button-primary' ) . $act( 'totp_off', __( 'Cancel', 'sidcraft-bot-shield' ) ); }
				else { $h = esc_html__( 'Use an app that makes a new 6-digit code every 30 seconds.', 'sidcraft-bot-shield' ) . '<br>' . $act( 'totp_start', __( 'Set up', 'sidcraft-bot-shield' ), '', 'button button-primary' ); }
			} else { $h = esc_html__( 'Not set up.', 'sidcraft-bot-shield' ); }
			$row( __( 'Authenticator app', 'sidcraft-bot-shield' ), $h );
		}
		if ( in_array( 'sms', $all, true ) ) {
			$phone = (string) get_user_meta( $user->ID, 'sbs2fa_sms', true ); $pend = get_user_meta( $user->ID, 'sbs2fa_sms_pending', true );
			if ( $phone ) { $h = '<strong>' . esc_html__( 'On', 'sidcraft-bot-shield' ) . '</strong> — ' . esc_html( substr( $phone, 0, 3 ) . str_repeat( '•', max( 0, strlen( $phone ) - 6 ) ) . substr( $phone, -3 ) ) . '<br>' . $act( 'sms_off', __( 'Remove', 'sidcraft-bot-shield' ) ); }
			elseif ( $own && is_array( $pend ) ) { $h = esc_html__( 'Enter the code we texted you.', 'sidcraft-bot-shield' ) . '<br>' . $act( 'sms_confirm', __( 'Turn on', 'sidcraft-bot-shield' ), '<input type="text" name="sbs_code" inputmode="numeric" placeholder="123456" style="width:110px"> ', 'button button-primary' ) . $act( 'sms_off', __( 'Cancel', 'sidcraft-bot-shield' ) ); }
			elseif ( $own ) { $h = esc_html__( 'Your mobile number, with the country code:', 'sidcraft-bot-shield' ) . '<br>' . $act( 'sms_start', __( 'Send me a code', 'sidcraft-bot-shield' ), '<input type="text" name="sbs_phone" placeholder="+15551234567" style="width:170px"> ', 'button button-primary' ); }
			else { $h = esc_html__( 'Not set up.', 'sidcraft-bot-shield' ); }
			$row( __( 'Text message', 'sidcraft-bot-shield' ), $h );
		}
		if ( in_array( 'passkey', $all, true ) ) {
			$keys = (array) get_user_meta( $user->ID, 'sbs2fa_passkeys', true ); $h = '';
			foreach ( $keys as $i => $k ) { $h .= '<p style="margin:2px 0">' . esc_html( ( $k['name'] ?? 'Passkey' ) . ' — ' . wp_date( get_option( 'date_format' ), $k['created'] ?? time() ) ) . ' ' . $act( 'pk_remove:' . (int) $i, __( 'Remove', 'sidcraft-bot-shield' ) ) . '</p>'; }
			if ( $own ) { $h .= '<p><input type="text" id="sbs-pk-name" placeholder="' . esc_attr__( 'Name, e.g. MacBook', 'sidcraft-bot-shield' ) . '" style="width:160px"> <button type="button" class="button button-primary" id="sbs-pk-add">' . esc_html__( 'Add a passkey', 'sidcraft-bot-shield' ) . '</button> <span id="sbs-pk-status" class="description"></span></p>'; self::profile_js(); }
			elseif ( ! $keys ) { $h = esc_html__( 'None.', 'sidcraft-bot-shield' ); }
			$row( __( 'Passkeys', 'sidcraft-bot-shield' ), $h );
		}
		$n = count( (array) get_user_meta( $user->ID, 'sbs2fa_recovery', true ) );
		if ( $own ) { $row( __( 'Recovery codes', 'sidcraft-bot-shield' ), esc_html( sprintf( /* translators: %d: number */ _n( '%d code left.', '%d codes left.', $n, 'sidcraft-bot-shield' ), $n ) ) . ' ' . esc_html__( 'Use one if you lose your phone or key.', 'sidcraft-bot-shield' ) . '<br>' . $act( 'codes', $n ? __( 'Make new codes', 'sidcraft-bot-shield' ) : __( 'Make recovery codes', 'sidcraft-bot-shield' ) ) ); }
		if ( ! $own && $admin ) { $row( __( 'Reset', 'sidcraft-bot-shield' ), esc_html__( 'If this user lost every second step, remove them so that they can log in with a password only and set up again.', 'sidcraft-bot-shield' ) . '<br>' . $act( 'reset', __( 'Remove all two-factor methods for this user', 'sidcraft-bot-shield' ) ) ); }
		echo '</tbody></table>';
	}

	private static function profile_js() {
		wp_register_script( 'sidcraft-botshield-2fa', false, array(), SIDCRAFT_BOTSHIELD_VERSION, true ); wp_enqueue_script( 'sidcraft-botshield-2fa' );
		$cfg = wp_json_encode( array( 'ajax' => admin_url( 'admin-ajax.php' ), 'nonce' => wp_create_nonce( 'sbs2fa_pk' ), 'ok' => __( 'Passkey added.', 'sidcraft-bot-shield' ) ) );
		wp_add_inline_script( 'sidcraft-botshield-2fa', '(function(){var C=' . $cfg . ',b=document.getElementById("sbs-pk-add");if(!b)return;var st=document.getElementById("sbs-pk-status");function d(s){s=s.replace(/-/g,"+").replace(/_/g,"/");while(s.length%4)s+="=";var x=atob(s),a=new Uint8Array(x.length);for(var i=0;i<x.length;i++)a[i]=x.charCodeAt(i);return a.buffer}function e(b){var a=new Uint8Array(b),s="";for(var i=0;i<a.length;i++)s+=String.fromCharCode(a[i]);return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"")}' .
			'function post(step,x){var p=new URLSearchParams();p.set("action","sidcraft_botshield_pk_reg");p.set("step",step);p.set("_ajax_nonce",C.nonce);for(var k in x||{})p.set(k,x[k]);return fetch(C.ajax,{method:"POST",credentials:"same-origin",body:p}).then(function(r){return r.json()})}' .
			'b.addEventListener("click",function(){if(!window.PublicKeyCredential){st.textContent="This browser does not support passkeys.";return}st.textContent="…";post("begin").then(function(r){if(!r.success)throw new Error(r.data.message);var o=r.data;o.challenge=d(o.challenge);o.user.id=d(o.user.id);o.excludeCredentials=(o.excludeCredentials||[]).map(function(c){return{type:c.type,id:d(c.id)}});return navigator.credentials.create({publicKey:o})}).then(function(c){var x=c.response;return post("finish",{name:document.getElementById("sbs-pk-name").value,clientDataJSON:e(x.clientDataJSON),attestationObject:e(x.attestationObject)})}).then(function(r){if(!r.success)throw new Error(r.data.message);st.textContent=C.ok;location.reload()}).catch(function(x){st.textContent=x.message||"Failed"})});})();' );
	}

	public static function pk_register_ajax() {
		check_ajax_referer( 'sbs2fa_pk' ); $uid = get_current_user_id(); $user = get_userdata( $uid );
		if ( ! $user || ! in_array( 'passkey', Sidcraft_BotShield_LoginSettings::methods_enabled(), true ) ) { wp_send_json_error( array( 'message' => 'Not allowed.' ) ); }
		$step = isset( $_POST['step'] ) ? sanitize_key( wp_unslash( $_POST['step'] ) ) : '';
		$keys = (array) get_user_meta( $uid, 'sbs2fa_passkeys', true ); $keys = array_filter( $keys );
		if ( 'begin' === $step ) { $ch = random_bytes( 32 ); set_transient( 'sbs2fa_pkreg_' . $uid, Sidcraft_BotShield_WebAuthn::b64u( $ch ), 5 * MINUTE_IN_SECONDS ); wp_send_json_success( Sidcraft_BotShield_WebAuthn::creation_options( $user, $ch, $keys ) ); }
		$ch = get_transient( 'sbs2fa_pkreg_' . $uid ); if ( ! $ch ) { wp_send_json_error( array( 'message' => 'Expired. Try again.' ) ); }
		delete_transient( 'sbs2fa_pkreg_' . $uid );
		$cred = Sidcraft_BotShield_WebAuthn::verify_registration( isset( $_POST['clientDataJSON'] ) ? sanitize_text_field( wp_unslash( $_POST['clientDataJSON'] ) ) : '', isset( $_POST['attestationObject'] ) ? sanitize_text_field( wp_unslash( $_POST['attestationObject'] ) ) : '', Sidcraft_BotShield_WebAuthn::unb64u( $ch ) );
		if ( is_wp_error( $cred ) ) { wp_send_json_error( array( 'message' => $cred->get_error_message() ) ); }
		$cred['name'] = isset( $_POST['name'] ) ? substr( sanitize_text_field( wp_unslash( $_POST['name'] ) ), 0, 40 ) : ''; if ( '' === $cred['name'] ) { $cred['name'] = 'Passkey ' . ( count( $keys ) + 1 ); }
		$keys[] = $cred; update_user_meta( $uid, 'sbs2fa_passkeys', array_values( $keys ) ); self::add_method( $uid, 'passkey' );
		wp_send_json_success();
	}

	private static function add_method( $uid, $m ) { $a = (array) get_user_meta( $uid, 'sbs2fa_methods', true ); if ( ! in_array( $m, $a, true ) ) { $a[] = $m; } update_user_meta( $uid, 'sbs2fa_methods', array_values( array_filter( $a ) ) ); }
	private static function drop_method( $uid, $m ) { $a = array_diff( (array) get_user_meta( $uid, 'sbs2fa_methods', true ), array( $m ) ); update_user_meta( $uid, 'sbs2fa_methods', array_values( $a ) ); }

	public static function profile_action() {
		if ( ! isset( $_POST['sbs_op'] ) ) { return; }
		$uid = isset( $_POST['sbs_uid'] ) ? (int) $_POST['sbs_uid'] : 0; $op = sanitize_text_field( wp_unslash( $_POST['sbs_op'] ) ); $idx = -1;
		if ( 0 === strpos( $op, 'pk_remove:' ) ) { $idx = (int) substr( $op, 10 ); $op = 'pk_remove'; } else { $op = sanitize_key( $op ); }
		if ( ! isset( $_POST['sbs_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['sbs_nonce'] ) ), 'sbs2fa_' . $uid ) ) { wp_die( esc_html__( 'The link expired. Go back and try again.', 'sidcraft-bot-shield' ), 403 ); }
		$own = get_current_user_id() === $uid;
		if ( ! $uid || ( ! $own && ! current_user_can( 'manage_options' ) ) ) { wp_die( esc_html__( 'Not allowed.', 'sidcraft-bot-shield' ), 403 ); }
		$user = get_userdata( $uid ); $msg = '';
		switch ( $op ) {
			case 'email_on': if ( $own ) { self::add_method( $uid, 'email' ); } break;
			case 'email_off': self::drop_method( $uid, 'email' ); break;
			case 'totp_start': if ( $own ) { update_user_meta( $uid, 'sbs2fa_totp_pending', Sidcraft_BotShield_Totp::secret() ); } break;
			case 'totp_confirm':
				$p = (string) get_user_meta( $uid, 'sbs2fa_totp_pending', true ); $step = $own && $p ? Sidcraft_BotShield_Totp::verify( $p, isset( $_POST['sbs_code'] ) ? sanitize_text_field( wp_unslash( $_POST['sbs_code'] ) ) : '' ) : 0;
				if ( $step ) { update_user_meta( $uid, 'sbs2fa_totp', $p ); update_user_meta( $uid, 'sbs2fa_totp_last', $step ); delete_user_meta( $uid, 'sbs2fa_totp_pending' ); self::add_method( $uid, 'totp' ); } else { $msg = __( 'That code is not right. Try again.', 'sidcraft-bot-shield' ); }
				break;
			case 'totp_off': delete_user_meta( $uid, 'sbs2fa_totp' ); delete_user_meta( $uid, 'sbs2fa_totp_pending' ); self::drop_method( $uid, 'totp' ); break;
			case 'sms_start':
				$ph = isset( $_POST['sbs_phone'] ) ? preg_replace( '/[^0-9+]/', '', sanitize_text_field( wp_unslash( $_POST['sbs_phone'] ) ) ) : '';
				if ( $own && preg_match( '/^\+[1-9]\d{6,14}$/', $ph ) ) { $code = (string) wp_rand( 100000, 999999 ); $r = self::sms( $ph, sprintf( /* translators: 1: site 2: code */ __( '%1$s confirmation code: %2$s', 'sidcraft-bot-shield' ), wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ), $code ) ); if ( is_wp_error( $r ) ) { $msg = $r->get_error_message(); } else { update_user_meta( $uid, 'sbs2fa_sms_pending', array( 'phone' => $ph, 'hash' => hash_hmac( 'sha256', $code, wp_salt( 'auth' ) ), 'exp' => time() + 600 ) ); } }
				else { $msg = __( 'Enter the number with the country code, like +15551234567.', 'sidcraft-bot-shield' ); }
				break;
			case 'sms_confirm':
				$p = get_user_meta( $uid, 'sbs2fa_sms_pending', true ); $c = isset( $_POST['sbs_code'] ) ? preg_replace( '/\s+/', '', sanitize_text_field( wp_unslash( $_POST['sbs_code'] ) ) ) : '';
				if ( $own && is_array( $p ) && $p['exp'] > time() && hash_equals( $p['hash'], hash_hmac( 'sha256', $c, wp_salt( 'auth' ) ) ) ) { update_user_meta( $uid, 'sbs2fa_sms', $p['phone'] ); delete_user_meta( $uid, 'sbs2fa_sms_pending' ); self::add_method( $uid, 'sms' ); } else { $msg = __( 'That code is not right. Try again.', 'sidcraft-bot-shield' ); }
				break;
			case 'sms_off': delete_user_meta( $uid, 'sbs2fa_sms' ); delete_user_meta( $uid, 'sbs2fa_sms_pending' ); self::drop_method( $uid, 'sms' ); break;
			case 'pk_remove': $k = (array) get_user_meta( $uid, 'sbs2fa_passkeys', true ); unset( $k[ $idx ] ); $k = array_values( $k ); update_user_meta( $uid, 'sbs2fa_passkeys', $k ); if ( ! $k ) { self::drop_method( $uid, 'passkey' ); } break;
			case 'codes': if ( $own ) { $codes = array(); $hash = array(); for ( $i = 0; $i < 10; $i++ ) { $c = strtolower( wp_generate_password( 10, false ) ); $codes[] = substr( $c, 0, 5 ) . '-' . substr( $c, 5 ); $hash[] = wp_hash_password( $c ); } update_user_meta( $uid, 'sbs2fa_recovery', $hash ); set_transient( 'sbs2fa_codes_' . $uid, $codes, 120 ); } break;
			case 'reset': if ( current_user_can( 'manage_options' ) ) { foreach ( array( 'sbs2fa_methods', 'sbs2fa_totp', 'sbs2fa_totp_pending', 'sbs2fa_totp_last', 'sbs2fa_sms', 'sbs2fa_sms_pending', 'sbs2fa_passkeys', 'sbs2fa_recovery' ) as $k ) { delete_user_meta( $uid, $k ); } } break;
		}
		$url = ( $own ? admin_url( 'profile.php' ) : admin_url( 'user-edit.php?user_id=' . $uid ) ); if ( '' !== $msg ) { $url = add_query_arg( 'sbs2fa_msg', rawurlencode( $msg ), $url ); }
		wp_safe_redirect( $url . '#sbs2fa' ); exit;
	}
}
