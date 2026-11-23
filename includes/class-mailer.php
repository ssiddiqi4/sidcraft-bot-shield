<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Where BotVaguard's emails (login codes, alerts) are sent from: WordPress's own PHP mailer, or an SMTP server you configure.
 * Settings live in the Login tab under Two-factor login.
 */
class Botvaguard_Mailer {

	/** True while one of BotVaguard's own emails is being sent. */
	private static $mine = false;
	private static $log = '';
	private static $error = '';

	public static function init() {
		add_action( 'phpmailer_init', array( __CLASS__, 'configure' ), 99 );
		add_filter( 'wp_mail_from', array( __CLASS__, 'from_email' ), 99 );
		add_filter( 'wp_mail_from_name', array( __CLASS__, 'from_name' ), 99 );
		add_action( 'wp_mail_failed', array( __CLASS__, 'failed' ) );
		add_action( 'admin_post_sidcraft_botshield_mail_test', array( __CLASS__, 'test_action' ) );
	}

	/** Send one of BotVaguard's emails. */
	public static function send( $to, $subject, $body, $headers = '' ) {
		self::$mine = true; self::$error = '';
		$ok = wp_mail( $to, $subject, $body, $headers );
		self::$mine = false;
		$s = Botvaguard_LoginSettings::all();
		update_option( 'sidcraft_botshield_mail_last', array( 'time' => time(), 'to' => (string) $to, 'subject' => (string) $subject, 'ok' => (bool) $ok, 'error' => self::$error, 'via' => self::smtp_on( $s ) ? 'smtp ' . $s['smtp_host'] . ':' . (int) $s['smtp_port'] : 'php' ), false );
		return $ok;
	}

	/** Why the last email could not be sent ('' when it could). */
	public static function last_error() { return self::$error; }

	private static function settings( $override = null ) { return is_array( $override ) ? $override : Botvaguard_LoginSettings::all(); }
	private static $override = null;

	private static function applies() {
		$s = self::settings( self::$override );
		return ( 'all' === $s['mail_scope'] || self::$mine );
	}

	private static function smtp_on( $s ) { return 'smtp' === $s['mail_mode'] && '' !== $s['smtp_host']; }

	public static function from_email( $email ) {
		$s = self::settings( self::$override );
		return self::applies() && is_email( $s['mail_from'] ) ? $s['mail_from'] : $email;
	}

	public static function from_name( $name ) {
		$s = self::settings( self::$override );
		return self::applies() && '' !== $s['mail_from_name'] ? $s['mail_from_name'] : $name;
	}

	public static function configure( $m ) {
		$s = self::settings( self::$override );
		if ( ! self::applies() ) { return; }
		if ( is_email( $s['mail_from'] ) ) { try { $m->setFrom( $s['mail_from'], '' !== $s['mail_from_name'] ? $s['mail_from_name'] : '', false ); } catch ( \Exception $e ) { self::$error = $e->getMessage(); } }
		if ( ! self::smtp_on( $s ) ) { return; }
		$m->isSMTP();
		$m->Host = $s['smtp_host']; $m->Port = (int) $s['smtp_port']; $m->Timeout = 15;
		$m->SMTPSecure = 'none' === $s['smtp_secure'] ? '' : $s['smtp_secure'];
		$m->SMTPAutoTLS = 'none' !== $s['smtp_secure'];
		$m->SMTPAuth = ! empty( $s['smtp_auth'] );
		if ( $m->SMTPAuth ) { $m->Username = $s['smtp_user']; $m->Password = self::password( $s ); }
		if ( null !== self::$override ) { $m->SMTPDebug = 2; $m->Debugoutput = function ( $str ) { self::$log .= preg_replace( '/^(.*AUTH (?:PLAIN|LOGIN) ).*$/m', '$1[hidden]', trim( $str ) ) . "\n"; }; }
	}

	public static function failed( $err ) { if ( $err instanceof WP_Error ) { self::$error = $err->get_error_message(); } }

	/* ----------------------------------------------------------- password */

	/** The stored password, or the SIDCRAFT_BOTSHIELD_SMTP_PASS constant when that is defined in wp-config.php. */
	public static function password( $s ) {
		if ( defined( 'SIDCRAFT_BOTSHIELD_SMTP_PASS' ) && '' !== SIDCRAFT_BOTSHIELD_SMTP_PASS ) { return (string) SIDCRAFT_BOTSHIELD_SMTP_PASS; }
		$v = (string) $s['smtp_pass'];
		if ( 0 === strpos( $v, 'enc:' ) && function_exists( 'openssl_decrypt' ) ) {
			$raw = base64_decode( substr( $v, 4 ), true ); if ( false === $raw || strlen( $raw ) < 17 ) { return ''; }
			$p = openssl_decrypt( substr( $raw, 16 ), 'aes-256-cbc', hash( 'sha256', wp_salt( 'auth' ), true ), OPENSSL_RAW_DATA, substr( $raw, 0, 16 ) );
			return false === $p ? '' : $p;
		}
		return 0 === strpos( $v, 'b64:' ) ? (string) base64_decode( substr( $v, 4 ) ) : '';
	}

	/** Is this value an already-encrypted password (so it must not be encrypted a second time)? */
	public static function is_protected( $v ) {
		$v = (string) $v;
		if ( 0 === strpos( $v, 'b64:' ) ) { return true; }
		return 0 === strpos( $v, 'enc:' ) && '' !== self::password( array( 'smtp_pass' => $v ) );
	}

	public static function protect( $plain ) {
		if ( function_exists( 'openssl_encrypt' ) ) {
			$iv = random_bytes( 16 );
			$c  = openssl_encrypt( $plain, 'aes-256-cbc', hash( 'sha256', wp_salt( 'auth' ), true ), OPENSSL_RAW_DATA, $iv );
			if ( false !== $c ) { return 'enc:' . base64_encode( $iv . $c ); }
		}
		return 'b64:' . base64_encode( $plain );
	}

	/* ---------------------------------------------------------------- test */

	/** Save the values on the screen, send a test email with them and keep the server conversation for the result box. */
	public static function test_action() {
		if ( ! current_user_can( 'manage_options' ) ) { wp_die( esc_html__( 'You do not have permission to do this.', 'botvaguard' ), 403 ); }
		check_admin_referer( 'sidcraft_botshield_mail_test', 'sbs_mail_nonce' );
		$O  = Botvaguard_LoginSettings::OPTION;
		$in = isset( $_POST[ $O ] ) && is_array( $_POST[ $O ] ) ? wp_unslash( $_POST[ $O ] ) : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- every key is cleaned in Botvaguard_LoginSettings::sanitize().
		$s  = Botvaguard_LoginSettings::sanitize( $in );
		update_option( Botvaguard_LoginSettings::OPTION, array_merge( Botvaguard_LoginSettings::all(), $s ) ); // the test saves what you typed, so nothing is lost when the page reloads.
		$u  = wp_get_current_user(); $to = $u->user_email;
		self::$override = $s; self::$log = ''; self::$error = '';
		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		/* translators: %s: site name */
		$ok = self::send( $to, sprintf( __( '[%s] BotVaguard test email', 'botvaguard' ), $site ), __( "This is a test email from BotVaguard.\n\nIf you can read it, login codes and alerts can reach you.", 'botvaguard' ) );
		self::$override = null;
		set_transient( 'sidcraft_botshield_mail_test_' . get_current_user_id(), array( 'ok' => (bool) $ok, 'to' => $to, 'error' => self::$error, 'log' => substr( self::$log, -3000 ), 'mode' => $s['mail_mode'] ), 300 );
		wp_safe_redirect( admin_url( 'admin.php?page=botvaguard&tab=login#sbs-mail' ) );
		exit;
	}

	public static function last_test() {
		$k = 'sidcraft_botshield_mail_test_' . get_current_user_id(); $r = get_transient( $k ); if ( $r ) { delete_transient( $k ); }
		return is_array( $r ) ? $r : null;
	}
}
