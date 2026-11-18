<?php
/**
 * Plugin Name:       Sidcraft Bot Shield
 * Plugin URI:        https://github.com/ssiddiqi4/sidcraft-bot-shield
 * Description:       Lets search engines and AI assistants (Google, Bing, Apple, ChatGPT, Claude, Perplexity, Copilot and more) in, and blocks scrapers, scripts, scanners and fake bots. Also blocks or allows countries, IP ranges, VPNs, proxies and Tor.
 * Version:           1.1.0
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

define( 'SIDCRAFT_BOTSHIELD_VERSION', '1.1.0' );
define( 'SIDCRAFT_BOTSHIELD_FILE', __FILE__ );

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
require_once __DIR__ . '/includes/class-guard.php';

Sidcraft_BotShield_Guard::init();
add_action( Sidcraft_BotShield_Lists::CRON, array( 'Sidcraft_BotShield_Lists', 'update' ) );
add_action( 'init', array( 'Sidcraft_BotShield_Lists', 'schedule' ) );
register_deactivation_hook( __FILE__, function () { wp_clear_scheduled_hook( Sidcraft_BotShield_Lists::CRON ); } );
if ( is_admin() ) {
	require_once __DIR__ . '/includes/class-admin.php';
	Sidcraft_BotShield_Admin::init();
}
