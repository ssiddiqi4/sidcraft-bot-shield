<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/** Optional: ask proxycheck.io whether an address is a VPN or proxy. Off by default; the owner supplies a key. */
class Sidcraft_BotShield_Api {
	/** Answers are cached for a week (a failed lookup for ten minutes) so each address is sent at most once. */
	public static function is_proxy( $ip, $key ) {
		if ( '' === Sidcraft_BotShield_Ranges::pack( $ip ) || ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) { return false; }
		$k = 'sbs_api_' . md5( $ip );
		$c = get_transient( $k );
		if ( false !== $c ) { return 'yes' === $c; }
		$res = wp_safe_remote_get( 'https://proxycheck.io/v2/' . rawurlencode( $ip ) . '?vpn=1&key=' . rawurlencode( $key ), array( 'timeout' => 2 ) );
		if ( is_wp_error( $res ) || 200 !== (int) wp_remote_retrieve_response_code( $res ) ) { set_transient( $k, 'err', 10 * MINUTE_IN_SECONDS ); return false; }
		$j = json_decode( (string) wp_remote_retrieve_body( $res ), true );
		if ( ! is_array( $j ) || 'ok' !== ( $j['status'] ?? '' ) || ! isset( $j[ $ip ] ) ) { set_transient( $k, 'err', 10 * MINUTE_IN_SECONDS ); return false; }
		$yes = 'yes' === ( $j[ $ip ]['proxy'] ?? 'no' );
		set_transient( $k, $yes ? 'yes' : 'no', 7 * DAY_IN_SECONDS );
		return $yes;
	}
}
