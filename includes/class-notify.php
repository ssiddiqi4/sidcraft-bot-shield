<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/** Emails to the admin when an address is blocked, and the "unlock me" link for an administrator who locked themselves out. */
class Sidcraft_BotShield_Notify {
	const HOOK = 'sidcraft_botshield_notify';

	public static function init() { add_action( self::HOOK, array( __CLASS__, 'send' ), 10, 4 ); }

	public static function to() { $e = (string) Sidcraft_BotShield_FwSettings::get( 'notify_email' ); return is_email( $e ) ? $e : (string) get_option( 'admin_email' ); }

	public static function sign( $data ) { return hash_hmac( 'sha256', $data, wp_salt( 'auth' ) ); }

	/** Queue an email (the host name lookup can be slow, so it happens in the background). */
	public static function schedule( $ip, $reason, $seconds, $kind ) {
		$mode = Sidcraft_BotShield_FwSettings::get( 'notify_mode' );
		if ( 'off' === $mode || ( 'nf' === $mode && ! in_array( $kind, array( 'nf', 'url' ), true ) ) ) { return; }
		$cap = (int) Sidcraft_BotShield_FwSettings::get( 'notify_cap' ); $k = 'sbs_mailcap_' . gmdate( 'YmdH' ); $n = (int) get_transient( $k );
		if ( $cap > 0 && $n >= $cap ) { set_transient( 'sbs_mailskip', (int) get_transient( 'sbs_mailskip' ) + 1, DAY_IN_SECONDS ); return; }
		set_transient( $k, $n + 1, HOUR_IN_SECONDS );
		$args = array( $ip, $reason, (int) $seconds, time() );
		if ( ! wp_next_scheduled( self::HOOK, $args ) ) { wp_schedule_single_event( time() + 5, self::HOOK, $args ); }
	}

	/** Reverse DNS name of an address, or ''. */
	public static function host( $ip ) {
		$h = apply_filters( 'sidcraft_botshield_host', null, $ip ); if ( is_string( $h ) ) { return $h; }
		$h = @gethostbyaddr( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		return ( is_string( $h ) && $h !== $ip && '' !== $h ) ? $h : '';
	}

	public static function send( $ip, $reason, $seconds, $time ) {
		$host = self::host( $ip ); if ( '' !== $host ) { Sidcraft_BotShield_Bans::set_host( $ip, $host ); }
		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$until = $seconds > 0 ? sprintf( /* translators: %s: date */ __( 'until %s', 'botvaguard' ), wp_date( 'Y-m-d H:i', $time + $seconds ) ) : __( 'permanently', 'botvaguard' );
		$unblock = add_query_arg( array( 'action' => 'sidcraft_botshield_unban_mail', 'ip' => rawurlencode( $ip ), 'sig' => self::sign( 'unban|' . $ip ) ), admin_url( 'admin-post.php' ) );
		$skip = (int) get_transient( 'sbs_mailskip' ); if ( $skip ) { delete_transient( 'sbs_mailskip' ); }
		$body = sprintf( /* translators: %s: site */ __( "BotVaguard blocked a visitor on %s.", 'botvaguard' ), $site ) . "\n\n"
			. __( 'IP address:', 'botvaguard' ) . ' ' . $ip . "\n"
			. __( 'Host name:', 'botvaguard' ) . ' ' . ( '' !== $host ? $host : __( '(none found)', 'botvaguard' ) ) . "\n"
			. __( 'Reason:', 'botvaguard' ) . ' ' . $reason . "\n"
			. __( 'Blocked:', 'botvaguard' ) . ' ' . $until . "\n"
			. __( 'Time:', 'botvaguard' ) . ' ' . wp_date( 'Y-m-d H:i:s', $time ) . "\n\n"
			. __( 'Blocked by mistake? Unblock this address (you must be logged in as an administrator):', 'botvaguard' ) . "\n" . $unblock . "\n\n"
			. __( 'All blocked addresses:', 'botvaguard' ) . "\n" . admin_url( 'admin.php?page=botvaguard&tab=firewall' ) . "\n"
			. ( $skip ? "\n" . sprintf( /* translators: %d: number */ __( '%d other block(s) were not emailed because of the hourly limit.', 'botvaguard' ), $skip ) . "\n" : '' );
		Sidcraft_BotShield_Mailer::send( self::to(), sprintf( /* translators: 1: site 2: IP */ __( '[%1$s] Blocked %2$s', 'botvaguard' ), $site, $ip ), $body );
	}

	// ---------- unlock links ----------
	public static function unlock_link( $ip ) {
		$exp = time() + HOUR_IN_SECONDS; $t = rtrim( strtr( base64_encode( $ip . '|' . $exp ), '+/', '-_' ), '=' );
		return add_query_arg( 'sbs_unlock', $t . '.' . self::sign( 'unlock|' . $ip . '|' . $exp ), home_url( '/' ) );
	}

	/** Check an unlock token. Returns the IP or ''. */
	public static function check_unlock( $token ) {
		$p = explode( '.', (string) $token ); if ( 2 !== count( $p ) ) { return ''; }
		$raw = (string) base64_decode( strtr( $p[0], '-_', '+/' ) . str_repeat( '=', ( 4 - strlen( $p[0] ) % 4 ) % 4 ) ); $q = explode( '|', $raw ); if ( 2 !== count( $q ) ) { return ''; }
		return ( (int) $q[1] > time() && hash_equals( self::sign( 'unlock|' . $q[0] . '|' . $q[1] ), $p[1] ) ) ? $q[0] : '';
	}

	/** A blocked visitor asks for an unlock email for the site owner. Always answers the same, so that it reveals nothing. */
	public static function request_unlock( $ip ) {
		$k = 'sbs_unlockreq_' . md5( $ip ); if ( get_transient( $k ) ) { return; }
		set_transient( $k, 1, 10 * MINUTE_IN_SECONDS );
		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		Sidcraft_BotShield_Mailer::send( self::to(), sprintf( /* translators: %s: site */ __( '[%s] Someone asked to be unblocked', 'botvaguard' ), $site ), sprintf( /* translators: 1: IP 2: link */ __( "The address %1\$s is blocked on your site and asked for an unlock link.\n\nIf this is you or someone you trust, open this link within an hour to unblock the address and keep it unblocked for a week:\n%2\$s\n\nIf you do not know who this is, ignore this email.", 'botvaguard' ), $ip, self::unlock_link( $ip ) ) );
	}
}
