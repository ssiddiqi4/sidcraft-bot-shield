<?php
/**
 * Plugin Name:       BotVaguard
 * Plugin URI:        https://github.com/ssiddiqi4/sidcraft-bot-shield
 * Description:       Lets search engines and AI assistants (Google, Bing, Apple, ChatGPT, Claude, Perplexity, Copilot and more) in, and blocks scrapers, scripts, scanners and fake bots. Also blocks countries, IP ranges, VPNs and Tor, with a web application firewall, two-factor login, a custom login address and a malware scanner.
 * Version:           1.6.0
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            Suhaib Siddiqi
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       botvaguard
 *
 * @package Sidcraft_BotShield
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

// Moving from the old "Sidcraft Bot Shield" plugin: BotVaguard keeps its settings. The old plugin can sit in any folder
// (sidcraft-bot-shield, sidcraft-bot-shield-main, ...), so it is found by its file name. Activating BotVaguard switches it off.
function botvaguard_old_plugins() {
	$found = array();
	foreach ( (array) get_option( 'active_plugins', array() ) as $f ) { if ( 'sidcraft-bot-shield.php' === basename( (string) $f ) ) { $found[ $f ] = false; } }
	if ( is_multisite() ) { foreach ( array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) ) as $f ) { if ( 'sidcraft-bot-shield.php' === basename( (string) $f ) ) { $found[ $f ] = true; } } }
	return $found; // plugin file => network wide.
}
register_activation_hook( __FILE__, function () {
	if ( ! function_exists( 'deactivate_plugins' ) ) { require_once ABSPATH . 'wp-admin/includes/plugin.php'; }
	foreach ( botvaguard_old_plugins() as $f => $network ) { deactivate_plugins( $f, true, $network ); } // silent: its protection lines in .htaccess stay for BotVaguard to use.
} );
if ( botvaguard_old_plugins() ) {
	// The old plugin is still on: stay dormant (nothing is loaded, so nothing can clash) and say so.
	add_action( 'admin_notices', function () {
		if ( current_user_can( 'activate_plugins' ) ) { echo '<div class="notice notice-warning"><p><strong>BotVaguard</strong> ' . esc_html__( 'is waiting: the old “Sidcraft Bot Shield” plugin is still active. Deactivate and delete it, then deactivate and activate BotVaguard once. Your settings are kept.', 'botvaguard' ) . '</p></div>'; }
	} );
	return;
}

define( 'BOTVAGUARD_VERSION', '1.6.0' );
define( 'BOTVAGUARD_FILE', __FILE__ );
define( 'BOTVAGUARD_DIR', plugin_dir_path( __FILE__ ) );

require_once __DIR__ . '/includes/class-catalog.php';
require_once __DIR__ . '/includes/class-countries.php';
require_once __DIR__ . '/includes/class-ranges.php';
require_once __DIR__ . '/includes/class-mmdb.php';
require_once __DIR__ . '/includes/class-lists.php';
require_once __DIR__ . '/includes/class-geo.php';
require_once __DIR__ . '/includes/class-api.php';
require_once __DIR__ . '/includes/class-settings.php';
require_once __DIR__ . '/includes/class-verify.php';
require_once __DIR__ . '/includes/class-log.php';
require_once __DIR__ . '/includes/class-qr.php';
require_once __DIR__ . '/includes/class-webauthn.php';
require_once __DIR__ . '/includes/class-loginsettings.php';
require_once __DIR__ . '/includes/class-notify.php';
require_once __DIR__ . '/includes/class-bans.php';
require_once __DIR__ . '/includes/class-waf.php';
require_once __DIR__ . '/includes/class-fwsettings.php';
require_once __DIR__ . '/includes/class-guard.php';
require_once __DIR__ . '/includes/class-firewall.php';
require_once __DIR__ . '/includes/class-ddos.php';
require_once __DIR__ . '/includes/class-scansettings.php';
require_once __DIR__ . '/includes/class-scanner.php';
require_once __DIR__ . '/includes/class-mailer.php';
require_once __DIR__ . '/includes/class-twofa.php';
require_once __DIR__ . '/includes/class-loginurl.php';

// Emergency switch: add define( 'SIDCRAFT_BOTSHIELD_OFF', true ); to wp-config.php to stop all blocking if you are locked out.
if ( ! ( defined( 'SIDCRAFT_BOTSHIELD_OFF' ) && SIDCRAFT_BOTSHIELD_OFF ) ) {
	Botvaguard_Guard::init();
	Botvaguard_Firewall::init();
	Botvaguard_Ddos::init();
}
Botvaguard_Scanner::init();
Botvaguard_Mailer::init();
Botvaguard_TwoFa::init();
if ( ! ( defined( 'SIDCRAFT_BOTSHIELD_OFF' ) && SIDCRAFT_BOTSHIELD_OFF ) ) { Botvaguard_LoginUrl::init(); }
add_action( 'admin_init', array( 'Botvaguard_Firewall', 'ext_refresh' ) );
add_action( Botvaguard_Lists::CRON, array( 'Botvaguard_Lists', 'update' ) );
add_action( 'init', array( 'Botvaguard_Lists', 'schedule' ) );
register_deactivation_hook( __FILE__, function () { wp_clear_scheduled_hook( Botvaguard_Lists::CRON ); Botvaguard_Firewall::ext_disable( true ); Botvaguard_Firewall::core_remove(); } );
register_activation_hook( __FILE__, function () { if ( Botvaguard_Firewall::ext_on() ) { Botvaguard_Firewall::ext_enable(); } if ( Botvaguard_Firewall::core_files() ) { Botvaguard_Firewall::core_sync(); } } );
if ( is_admin() ) {
	require_once __DIR__ . '/includes/class-secure-admin.php';
	require_once __DIR__ . '/includes/class-admin.php';
	Botvaguard_Admin::init();
}
