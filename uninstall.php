<?php
/**
 * Removes Bot Shield data when the plugin is deleted (only if the owner ticked "delete all data").
 *
 * @package Sidcraft_BotShield
 */
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) { exit; }

function sidcraft_botshield_uninstall() {
	$s = get_option( 'sidcraft_botshield_settings' );
	if ( is_array( $s ) && ! empty( $s['remove_data'] ) ) {
		foreach ( array( 'sidcraft_botshield_settings', 'sidcraft_botshield_log', 'sidcraft_botshield_stats', 'sidcraft_botshield_lists' ) as $o ) { delete_option( $o ); }
		$u = wp_upload_dir( null, false ); $d = trailingslashit( $u['basedir'] ) . 'sidcraft-bot-shield/';
		if ( is_dir( $d ) ) { foreach ( (array) glob( $d . '{*,.htaccess}', GLOB_BRACE ) as $f ) { if ( is_file( $f ) ) { wp_delete_file( $f ); } } @rmdir( $d ); } // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.rmdir_rmdir
	}
	wp_clear_scheduled_hook( 'sidcraft_botshield_update_lists' );
}
sidcraft_botshield_uninstall();
