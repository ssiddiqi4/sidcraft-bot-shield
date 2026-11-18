<?php
/**
 * Plugin Name:       Sidcraft Bot Shield
 * Plugin URI:        https://github.com/ssiddiqi4/sidcraft-bot-shield
 * Description:       Lets search engines and AI assistants (Google, Bing, Apple, ChatGPT, Claude, Perplexity, Copilot and more) in, and blocks scrapers, scripts, scanners and fake bots. Also blocks countries, IP ranges, VPNs and Tor, with a web application firewall, two-factor login, a custom login address and a malware scanner.
 * Version:           1.3.3
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            Suhaib Siddiqi
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       sidcraft-bot-shield
 *
 * @package Sidcraft_BotShield
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

define( 'SIDCRAFT_BOTSHIELD_VERSION', '1.3.3' );
define( 'SIDCRAFT_BOTSHIELD_FILE', __FILE__ );
define( 'SIDCRAFT_BOTSHIELD_DIR', plugin_dir_path( __FILE__ ) );

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
require_once __DIR__ . '/includes/class-scansettings.php';
require_once __DIR__ . '/includes/class-scanner.php';
require_once __DIR__ . '/includes/class-twofa.php';
require_once __DIR__ . '/includes/class-loginurl.php';

Sidcraft_BotShield_Guard::init();
Sidcraft_BotShield_Firewall::init();
Sidcraft_BotShield_Scanner::init();
Sidcraft_BotShield_TwoFa::init();
Sidcraft_BotShield_LoginUrl::init();
add_action( Sidcraft_BotShield_Lists::CRON, array( 'Sidcraft_BotShield_Lists', 'update' ) );
add_action( 'init', array( 'Sidcraft_BotShield_Lists', 'schedule' ) );
register_deactivation_hook( __FILE__, function () { wp_clear_scheduled_hook( Sidcraft_BotShield_Lists::CRON ); Sidcraft_BotShield_Firewall::ext_disable( true ); } );
register_activation_hook( __FILE__, function () { if ( Sidcraft_BotShield_FwSettings::get( 'extended' ) ) { Sidcraft_BotShield_Firewall::ext_enable(); } } );
if ( is_admin() ) {
	require_once __DIR__ . '/includes/class-secure-admin.php';
	require_once __DIR__ . '/includes/class-admin.php';
	Sidcraft_BotShield_Admin::init();
}
