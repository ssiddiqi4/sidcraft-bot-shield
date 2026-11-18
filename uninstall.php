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
