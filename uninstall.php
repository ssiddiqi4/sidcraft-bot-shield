<?php
/**
 * Removes Bot Shield data when the plugin is deleted (only if the owner ticked "delete all data").
 *
 * @package Sidcraft_BotShield
 */
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) { exit; }

/** Remove the pre-WordPress firewall lines from .htaccess and .user.ini. */
function sidcraft_botshield_remove_prepend() {
	require_once ABSPATH . 'wp-admin/includes/file.php';
	WP_Filesystem();
	global $wp_filesystem;
	if ( ! $wp_filesystem ) { return; }
	$mark = 'Sidcraft Bot Shield Firewall';
	foreach ( array( array( '.htaccess', '#' ), array( '.user.ini', ';' ) ) as $f ) {
		$path = trailingslashit( ABSPATH ) . $f[0];
		if ( ! $wp_filesystem->exists( $path ) ) { continue; }
		$t = (string) $wp_filesystem->get_contents( $path );
		if ( false === strpos( $t, $mark ) ) { continue; }
		$wp_filesystem->put_contents( $path, trim( (string) preg_replace( '/\R?' . preg_quote( $f[1] . ' BEGIN ' . $mark, '/' ) . '.*?' . preg_quote( $f[1] . ' END ' . $mark, '/' ) . '\R?/s', "\n", $t ) ) . "\n", 0644 );
	}
}

function sidcraft_botshield_uninstall() {
	sidcraft_botshield_remove_prepend();
	wp_clear_scheduled_hook( 'sidcraft_botshield_scan_start' );
	wp_clear_scheduled_hook( 'sidcraft_botshield_scan_tick' );
	$s = get_option( 'sidcraft_botshield_settings' );
	if ( is_array( $s ) && ! empty( $s['remove_data'] ) ) {
		foreach ( array( 'sidcraft_botshield_settings', 'sidcraft_botshield_log', 'sidcraft_botshield_stats', 'sidcraft_botshield_lists', 'sidcraft_botshield_fw', 'sidcraft_botshield_scan_opts', 'sidcraft_botshield_scan', 'sidcraft_botshield_findings', 'sidcraft_botshield_ignored', 'sidcraft_botshield_prev_findings', 'sidcraft_botshield_bans', 'sidcraft_botshield_perm', 'sidcraft_botshield_login', 'sidcraft_botshield_ext_on', 'sidcraft_botshield_ext_error', 'sidcraft_botshield_quarantine' ) as $o ) { delete_option( $o ); }
		foreach ( array( 'sbs2fa_methods', 'sbs2fa_totp', 'sbs2fa_totp_pending', 'sbs2fa_totp_last', 'sbs2fa_sms', 'sbs2fa_sms_pending', 'sbs2fa_passkeys', 'sbs2fa_recovery' ) as $k ) { delete_metadata( 'user', 0, $k, '', true ); }
		$u = wp_upload_dir( null, false ); $d = trailingslashit( $u['basedir'] ) . 'sidcraft-bot-shield/';
		if ( is_dir( $d ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
			WP_Filesystem();
			global $wp_filesystem;
			if ( $wp_filesystem ) { $wp_filesystem->rmdir( $d, true ); }
		}
	}
	wp_clear_scheduled_hook( 'sidcraft_botshield_update_lists' );
}
sidcraft_botshield_uninstall();
