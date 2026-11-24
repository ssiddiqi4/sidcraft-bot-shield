<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

class Botvanguard_Admin {
	/** Tags allowed in the row action links. */
	private static $allowed = array( 'a' => array( 'href' => array() ), 'em' => array(), 'br' => array() );

	public static function init() {
		Botvanguard_SecureAdmin::init();
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_init', array( __CLASS__, 'register' ) );
		add_action( 'admin_post_sidcraft_botshield_test', array( __CLASS__, 'test' ) );
		add_action( 'admin_post_sidcraft_botshield_backup', array( __CLASS__, 'backup' ) );
		add_action( 'admin_post_sidcraft_botshield_act', array( __CLASS__, 'act' ) );
		add_action( 'wp_dashboard_setup', array( __CLASS__, 'dash_setup' ) );
		add_action( 'admin_post_sidcraft_botshield_allow', array( __CLASS__, 'allow_save' ) );
		add_action( 'admin_post_sidcraft_botshield_csv', array( __CLASS__, 'csv' ) );
		add_action( 'admin_post_sidcraft_botshield_clear', array( __CLASS__, 'clear' ) );
		add_action( 'admin_post_sidcraft_botshield_lists', array( __CLASS__, 'lists_now' ) );
		add_action( 'admin_post_sidcraft_botshield_geodb', array( __CLASS__, 'geodb' ) );
		add_action( 'update_option_' . Botvanguard_Settings::OPTION, array( __CLASS__, 'saved' ) );
		add_action( 'admin_notices', array( __CLASS__, 'notice' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( BOTVANGUARD_FILE ), array( __CLASS__, 'links' ) );
	}

	public static function links( $l ) { array_unshift( $l, '<a href="' . esc_url( admin_url( 'admin.php?page=botvanguard-settings' ) ) . '">' . esc_html__( 'Settings', 'botvanguard' ) . '</a>', '<a href="' . esc_url( admin_url( 'admin.php?page=botvanguard' ) ) . '">' . esc_html__( 'Dashboard', 'botvanguard' ) . '</a>' ); return $l; }

	const TABS = array( 'dashboard', 'settings', 'firewall', 'ddos', 'login', 'scan', 'log' );

	/** Own menu in the WordPress dashboard, with one entry per screen. */
	public static function menu() {
		$labels = array( 'dashboard' => __( 'Dashboard', 'botvanguard' ), 'settings' => __( 'Bots', 'botvanguard' ), 'firewall' => __( 'Firewall', 'botvanguard' ), 'ddos' => __( 'DDoS', 'botvanguard' ), 'login' => __( 'Login', 'botvanguard' ), 'scan' => __( 'Scan', 'botvanguard' ), 'log' => __( 'Blocked log', 'botvanguard' ) );
		add_menu_page( 'Sidcraft BotVanguard', 'Sidcraft BotVanguard', 'manage_options', 'botvanguard', array( __CLASS__, 'page' ), 'dashicons-shield', 81 );
		foreach ( $labels as $tab => $label ) {
			add_submenu_page( 'botvanguard', 'Sidcraft BotVanguard: ' . $label, $label, 'manage_options', 'dashboard' === $tab ? 'botvanguard' : 'botvanguard-' . $tab, array( __CLASS__, 'page' ) );
		}
	}

	/** Which screen is open: ?tab= wins, otherwise the page name decides. */
	private static function current_tab() {
		$tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only tab switch.
		if ( in_array( $tab, self::TABS, true ) ) { return $tab; }
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only.
		$tab  = 0 === strpos( $page, 'botvanguard-' ) ? substr( $page, strlen( 'botvanguard-' ) ) : 'dashboard';
		return in_array( $tab, self::TABS, true ) ? $tab : 'dashboard';
	}

	public static function register() {
		register_setting( 'sidcraft_botshield_group', Botvanguard_Settings::OPTION, array( 'type' => 'array', 'sanitize_callback' => array( 'Botvanguard_Settings', 'sanitize' ), 'default' => Botvanguard_Settings::defaults() ) );
	}

	public static function notice() {
		if ( isset( $_GET['sbs_done'] ) && current_user_can( 'manage_options' ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only.
			$m = array( 'allow' => __( 'Address allowed: it will never be blocked, and any ban was lifted.', 'botvanguard' ), 'block' => __( 'Address blocked permanently.', 'botvanguard' ), 'allow_ua' => __( 'Browser name allowed.', 'botvanguard' ) );
			$k = sanitize_key( wp_unslash( $_GET['sbs_done'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			if ( isset( $m[ $k ] ) ) { echo '<div class="notice notice-success is-dismissible"><p>' . esc_html( $m[ $k ] ) . '</p></div>'; }
		}
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only screen check.
		if ( 0 !== strpos( $page, 'botvanguard' ) || ! current_user_can( 'manage_options' ) ) { return; }
		if ( 'monitor' === Botvanguard_Settings::get( 'mode' ) ) {
			echo '<div class="notice notice-warning"><p><strong>' . esc_html__( 'Monitor mode:', 'botvanguard' ) . '</strong> ' . esc_html__( 'nothing is blocked yet. The list below shows what would be blocked. When it looks right, switch to “Block”.', 'botvanguard' ) . '</p></div>';
		}
	}

	private static function opt( $name ) { return esc_attr( Botvanguard_Settings::OPTION . $name ); }

	public static function page() {
		if ( ! current_user_can( 'manage_options' ) ) { return; }
		$s = Botvanguard_Settings::all(); $O = Botvanguard_Settings::OPTION;
		$tab = self::current_tab();
		$base = admin_url( 'admin.php?page=botvanguard' );
		echo '<div class="wrap"><h1>Sidcraft BotVanguard</h1>';
		if ( 'dashboard' === $tab ) { self::cards(); }
		$tabs = array( 'dashboard' => __( 'Dashboard', 'botvanguard' ), 'settings' => __( 'Bots', 'botvanguard' ), 'firewall' => __( 'Firewall', 'botvanguard' ), 'ddos' => __( 'DDoS', 'botvanguard' ), 'login' => __( 'Login', 'botvanguard' ), 'scan' => __( 'Scan', 'botvanguard' ), 'log' => __( 'Blocked log', 'botvanguard' ) );
		echo '<h2 class="nav-tab-wrapper">';
		foreach ( $tabs as $tk => $tl ) { echo '<a class="nav-tab ' . ( $tk === $tab ? 'nav-tab-active' : '' ) . '" href="' . esc_url( 'dashboard' === $tk ? $base : $base . '-' . $tk ) . '">' . esc_html( $tl ) . '</a>'; }
		echo '</h2>';
		if ( 'dashboard' === $tab ) { self::dashboard_tab( $base ); echo '</div>'; return; }
		if ( 'ddos' === $tab ) { Botvanguard_Ddos::tab( $base ); echo '</div>'; return; }
		if ( 'firewall' === $tab ) { Botvanguard_SecureAdmin::firewall_tab( $base ); echo '</div>'; return; }
		if ( 'login' === $tab ) { Botvanguard_SecureAdmin::login_tab( $base ); echo '</div>'; return; }
		if ( 'scan' === $tab ) { Botvanguard_SecureAdmin::scan_tab( $base ); echo '</div>'; return; }
		if ( 'log' === $tab ) { self::log_tab( $base ); echo '</div>'; return; }
		echo '<p>' . esc_html__( 'Lets search engines and AI assistants in, and keeps scrapers, scripts, scanners and fake bots out. Visitors who look like normal browsers are never blocked, and neither are logged-in users.', 'botvanguard' ) . '</p>';
		echo '<form method="post" action="options.php">'; settings_fields( 'sidcraft_botshield_group' );
		echo '<table class="form-table" role="presentation"><tbody>';
		echo '<tr><th><label for="sbs-ipallow">' . esc_html__( 'Never block these addresses', 'botvanguard' ) . '</label></th><td>' . self::allow_fields( $s['ip_allow'], $O . '[ip_allow]', 'sbs-ipallow' ) . '</td></tr>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- allow_fields() escapes every part it builds.
		echo '<tr><th>' . esc_html__( 'Mode', 'botvanguard' ) . '</th><td><label><input type="radio" name="' . esc_attr( $O ) . '[mode]" value="monitor" ' . checked( $s['mode'], 'monitor', false ) . '> ' . esc_html__( 'Monitor only: log what would be blocked (recommended for the first days)', 'botvanguard' ) . '</label><br><label><input type="radio" name="' . esc_attr( $O ) . '[mode]" value="block" ' . checked( $s['mode'], 'block', false ) . '> ' . esc_html__( 'Block: answer unwanted bots with “403 Access denied”', 'botvanguard' ) . '</label></td></tr>';
		echo '<tr><th>' . esc_html__( 'Always allow', 'botvanguard' ) . '</th><td>';
		foreach ( Botvanguard_Catalog::allowed() as $gk => $g ) {
			$names = array(); foreach ( $g['bots'] as $info ) { $names[ $info[0] ] = 1; }
			echo '<p><label><input type="checkbox" name="' . esc_attr( $O ) . '[allow][' . esc_attr( $gk ) . ']" value="1" ' . checked( ! empty( $s['allow'][ $gk ] ), true, false ) . '> <strong>' . esc_html( $g['label'] ) . '</strong></label><br><span class="description">' . esc_html( implode( ', ', array_keys( $names ) ) ) . '</span></p>';
		}
		echo '<p><label><input type="checkbox" name="' . esc_attr( $O ) . '[verify]" value="1" ' . checked( ! empty( $s['verify'] ), true, false ) . '> ' . esc_html__( 'Check that Google, Bing, Apple, Yahoo, Yandex and Baidu are genuine (their address must belong to them). Fake ones are blocked.', 'botvanguard' ) . '</label></p>';
		echo '<p class="description">' . esc_html__( 'AI crawlers are recognised by name only, because most AI companies do not publish a way to prove who they are. Anyone can claim such a name, so a determined scraper could pretend to be one.', 'botvanguard' ) . '</p></td></tr>';
		echo '<tr><th>' . esc_html__( 'Block', 'botvanguard' ) . '</th><td>';
		foreach ( Botvanguard_Catalog::blocked() as $gk => $g ) {
			echo '<p><label><input type="checkbox" name="' . esc_attr( $O ) . '[block][' . esc_attr( $gk ) . ']" value="1" ' . checked( ! empty( $s['block'][ $gk ] ), true, false ) . '> <strong>' . esc_html( $g['label'] ) . '</strong></label><br><span class="description">' . esc_html( implode( ', ', array_slice( $g['tokens'], 0, 14 ) ) ) . '…</span></p>';
		}
		echo '<p><label><input type="checkbox" name="' . esc_attr( $O ) . '[block_empty]" value="1" ' . checked( ! empty( $s['block_empty'] ), true, false ) . '> ' . esc_html__( 'Visitors that send no browser name at all', 'botvanguard' ) . '</label></p>';
		echo '<p><label><input type="checkbox" name="' . esc_attr( $O ) . '[block_scanners]" value="1" ' . checked( ! empty( $s['block_scanners'] ), true, false ) . '> ' . esc_html__( 'Attack probes (/shell, /.env, /phpmyadmin, wp-config backups…) and ban the address that sent them', 'botvanguard' ) . '</label></p>';
		echo '<p class="description">' . esc_html__( 'Only page requests are checked for browser names, so forms, payments, webhooks and apps keep working.', 'botvanguard' ) . '</p></td></tr>';
		echo '<tr><th><label for="sbs-ban">' . esc_html__( 'Ban length (hours)', 'botvanguard' ) . '</label></th><td><input id="sbs-ban" type="number" min="1" max="720" name="' . esc_attr( $O ) . '[ban_hours]" value="' . (int) $s['ban_hours'] . '" class="small-text"></td></tr>';
		echo '<tr><th>' . esc_html__( 'Extra options', 'botvanguard' ) . '</th><td>';
		echo '<p><label><input type="checkbox" name="' . esc_attr( $O ) . '[honeypot]" value="1" ' . checked( ! empty( $s['honeypot'] ), true, false ) . '> ' . esc_html__( 'Trap: add a hidden link that robots.txt forbids. Any robot that opens it is banned.', 'botvanguard' ) . '</label></p>';
		echo '<p><label><input type="checkbox" name="' . esc_attr( $O ) . '[rate_limit]" value="1" ' . checked( ! empty( $s['rate_limit'] ), true, false ) . '> ' . esc_html__( 'Speed limit: no more than', 'botvanguard' ) . '</label> <input type="number" min="5" max="5000" name="' . esc_attr( $O ) . '[rate_per_min]" value="' . (int) $s['rate_per_min'] . '" class="small-text"> ' . esc_html__( 'page requests a minute from one address (uses a little database writing on every visit)', 'botvanguard' ) . '</p>';
		echo '<p><label>' . esc_html__( 'Is your site behind Cloudflare or another proxy?', 'botvanguard' ) . ' <select name="' . esc_attr( $O ) . '[proxy]"><option value="none" ' . selected( $s['proxy'], 'none', false ) . '>' . esc_html__( 'No', 'botvanguard' ) . '</option><option value="cloudflare" ' . selected( $s['proxy'], 'cloudflare', false ) . '>Cloudflare</option><option value="xff" ' . selected( $s['proxy'], 'xff', false ) . '>' . esc_html__( 'Other proxy (X-Forwarded-For)', 'botvanguard' ) . '</option></select></label></p></td></tr>';
		// Countries, addresses, VPN / Tor.
		$name_geo = esc_attr( $O ) . '[geo_countries][]';
		echo '<tr><th>' . esc_html__( 'Countries', 'botvanguard' ) . '</th><td>';
		echo '<p><label><input type="radio" name="' . esc_attr( $O ) . '[geo_mode]" value="off" ' . checked( $s['geo_mode'], 'off', false ) . '> ' . esc_html__( 'Do not use countries', 'botvanguard' ) . '</label><br>';
		echo '<label><input type="radio" name="' . esc_attr( $O ) . '[geo_mode]" value="block" ' . checked( $s['geo_mode'], 'block', false ) . '> ' . esc_html__( 'Block the countries I select', 'botvanguard' ) . '</label><br>';
		echo '<label><input type="radio" name="' . esc_attr( $O ) . '[geo_mode]" value="allow_only" ' . checked( $s['geo_mode'], 'allow_only', false ) . '> ' . esc_html__( 'Only allow the countries I select (everyone else is blocked)', 'botvanguard' ) . '</label></p>';
		echo '<select name="' . $name_geo . '" multiple size="10" style="min-width:320px">'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped above.
		foreach ( Botvanguard_Countries::all() as $code => $cn ) { echo '<option value="' . esc_attr( $code ) . '" ' . selected( in_array( $code, $s['geo_countries'], true ), true, false ) . '>' . esc_html( $cn . ' (' . $code . ')' ) . '</option>'; }
		echo '</select><p class="description">' . esc_html__( 'Hold Ctrl (Windows) or Cmd (Mac) to select several.', 'botvanguard' ) . '</p>';
		echo '<p><label>' . esc_html__( 'If the country cannot be found:', 'botvanguard' ) . ' <select name="' . esc_attr( $O ) . '[geo_unknown]"><option value="allow" ' . selected( $s['geo_unknown'], 'allow', false ) . '>' . esc_html__( 'let the visitor in', 'botvanguard' ) . '</option><option value="block" ' . selected( $s['geo_unknown'], 'block', false ) . '>' . esc_html__( 'block the visitor', 'botvanguard' ) . '</option></select></label></p>';
		echo '<p><label><input type="checkbox" name="' . esc_attr( $O ) . '[geo_bots_exempt]" value="1" ' . checked( ! empty( $s['geo_bots_exempt'] ), true, false ) . '> ' . esc_html__( 'Welcome bots (search engines, AI assistants) ignore the country, VPN and Tor rules. Recommended: Google crawls from the USA.', 'botvanguard' ) . '</label></p>';
		$geo = Botvanguard_Geo::detect( Botvanguard_Guard::client_ip() );
		$src = '' !== $geo[0] ? sprintf( /* translators: 1: country code, 2: where it came from */ __( 'Your country right now: %1$s (from %2$s)', 'botvanguard' ), $geo[0], $geo[1] ) : __( 'No country source found yet. Ask your host or Cloudflare to send the visitor country, or upload a country database below. Until then every visitor counts as “country unknown”.', 'botvanguard' );
		echo '<p class="description"><strong>' . esc_html( $src ) . '</strong></p>';
		echo '<p class="description">' . esc_html__( 'Country is read from Cloudflare, CloudFront or your server when available, otherwise from the country database file below. Logged-in users are never blocked.', 'botvanguard' ) . '</p></td></tr>';

		echo '<tr><th><label for="sbs-ipb">' . esc_html__( 'Block addresses', 'botvanguard' ) . '</label></th><td><textarea id="sbs-ipb" name="' . esc_attr( $O ) . '[ip_block]" rows="5" cols="50" placeholder="203.0.113.7&#10;198.51.100.0/24&#10;192.0.2.10 - 192.0.2.99&#10;2001:db8::/32">' . esc_textarea( $s['ip_block'] ) . '</textarea><br><span class="description">' . esc_html__( 'One per line. IPv4 and IPv6. Single address, range with / (203.0.113.0/24), or from - to (192.0.2.10 - 192.0.2.99). Up to 2000 lines. Your “never block” list and logged-in users win over this list.', 'botvanguard' ) . '</span></td></tr>';

		$ls = Botvanguard_Lists::status();
		echo '<tr><th>' . esc_html__( 'VPN, proxies and Tor', 'botvanguard' ) . '</th><td>';
		$rows = array( 'block_tor' => array( 'tor', __( 'Block Tor (anonymising network)', 'botvanguard' ) ), 'block_vpn' => array( 'vpn', __( 'Block commercial VPN services (list of known VPN addresses)', 'botvanguard' ) ), 'block_datacenter' => array( 'datacenter', __( 'Block hosting / data-centre addresses (stricter: also blocks many proxies and bots; real visitors on company clouds may be caught)', 'botvanguard' ) ) );
		foreach ( $rows as $k => $info ) {
			$d = $ls['lists'][ $info[0] ] ?? null;
			$st = $d ? sprintf( /* translators: 1: ranges, 2: time ago */ __( ' — %1$s ranges, updated %2$s ago', 'botvanguard' ), number_format_i18n( $d['v4'] + $d['v6'] ), human_time_diff( $d['time'] ) ) : '';
			echo '<p><label><input type="checkbox" name="' . esc_attr( $O ) . '[' . esc_attr( $k ) . ']" value="1" ' . checked( ! empty( $s[ $k ] ), true, false ) . '> ' . esc_html( $info[1] ) . '</label><span class="description">' . esc_html( $st ) . '</span></p>';
		}
		echo '<p><label><input type="checkbox" name="' . esc_attr( $O ) . '[block_proxy_headers]" value="1" ' . checked( ! empty( $s['block_proxy_headers'] ), true, false ) . '> ' . esc_html__( 'Block visitors whose request carries proxy headers (Via, X-Forwarded-For). Only works when your site is NOT behind Cloudflare or another proxy (choose “No” above). Some company and school networks use such proxies.', 'botvanguard' ) . '</label></p>';
		echo '<p><label>' . esc_html__( 'Live check with proxycheck.io (optional):', 'botvanguard' ) . ' <select name="' . esc_attr( $O ) . '[vpn_api]"><option value="none" ' . selected( $s['vpn_api'], 'none', false ) . '>' . esc_html__( 'off', 'botvanguard' ) . '</option><option value="proxycheck" ' . selected( $s['vpn_api'], 'proxycheck', false ) . '>' . esc_html__( 'on', 'botvanguard' ) . '</option></select></label> <input type="text" name="' . esc_attr( $O ) . '[vpn_api_key]" value="' . esc_attr( $s['vpn_api_key'] ) . '" placeholder="' . esc_attr__( 'your API key', 'botvanguard' ) . '" autocomplete="off"><br><span class="description">' . esc_html__( 'Catches VPNs and proxies that are not on the lists. When on, the visitor’s IP address is sent to proxycheck.io (once a week per address). Needs your own key from proxycheck.io.', 'botvanguard' ) . '</span></p>';
		if ( ! empty( $ls['error'] ) ) { echo '<p class="description" style="color:#b32d2e">' . esc_html( $ls['error'] ) . '</p>'; }
		echo '<p class="description">' . esc_html__( 'The lists are downloaded once a day from the Tor Project and from the open X4BNet VPN list on GitHub, and kept on your server. Nothing about your visitors is sent for the lists.', 'botvanguard' ) . '</p></td></tr>';

		echo '<tr><th><label for="sbs-ca">' . esc_html__( 'Your own lists', 'botvanguard' ) . '</label></th><td>';
		echo '<p><strong>' . esc_html__( 'Also allow (names, one per line)', 'botvanguard' ) . '</strong><br><textarea id="sbs-ca" name="' . esc_attr( $O ) . '[custom_allow]" rows="3" cols="50">' . esc_textarea( $s['custom_allow'] ) . '</textarea></p>';
		echo '<p><strong>' . esc_html__( 'Also block (names, one per line; wins over the allow lists)', 'botvanguard' ) . '</strong><br><textarea name="' . esc_attr( $O ) . '[custom_block]" rows="3" cols="50">' . esc_textarea( $s['custom_block'] ) . '</textarea></p>';
		echo '<tr><th>' . esc_html__( 'Lock-out protection', 'botvanguard' ) . '</th><td><label><input type="checkbox" name="' . esc_attr( $O ) . '[remember_admin]" value="1" ' . checked( ! empty( $s['remember_admin'] ), true, false ) . '> ' . esc_html__( 'Never block an address that an administrator logged in from during the last 7 days (stops you locking yourself out)', 'botvanguard' ) . '</label></td></tr>';
		echo '<tr><th>' . esc_html__( 'Data', 'botvanguard' ) . '</th><td><label><input type="checkbox" name="' . esc_attr( $O ) . '[keep_log]" value="1" ' . checked( ! empty( $s['keep_log'] ), true, false ) . '> ' . esc_html__( 'Keep a list of the last 500 blocked requests for 30 days (address, browser name, page) — see the Blocked log tab', 'botvanguard' ) . '</label><br><label><input type="checkbox" name="' . esc_attr( $O ) . '[remove_data]" value="1" ' . checked( ! empty( $s['remove_data'] ), true, false ) . '> ' . esc_html__( 'Delete all Sidcraft BotVanguard data when the plugin is deleted', 'botvanguard' ) . '</label></td></tr>';
		echo '</tbody></table>'; submit_button(); echo '</form>';
		// Lists + country database.
		echo '<h2>' . esc_html__( 'Address lists and country database', 'botvanguard' ) . '</h2>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="margin-bottom:14px">'; wp_nonce_field( 'sidcraft_botshield_lists' ); echo '<input type="hidden" name="action" value="sidcraft_botshield_lists"><button class="button">' . esc_html__( 'Update Tor / VPN lists now', 'botvanguard' ) . '</button> <span class="description">' . esc_html__( 'Only the lists you ticked above are downloaded.', 'botvanguard' ) . '</span></form>';
		echo '<form method="post" enctype="multipart/form-data" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">'; wp_nonce_field( 'sidcraft_botshield_geodb' ); echo '<input type="hidden" name="action" value="sidcraft_botshield_geodb">';
		echo '<p><strong>' . esc_html__( 'Country database (optional)', 'botvanguard' ) . '</strong> — ' . esc_html( Botvanguard_Lists::mmdb_exists() ? __( 'installed', 'botvanguard' ) : __( 'none', 'botvanguard' ) ) . '<br><input type="file" name="mmdb" accept=".mmdb"> <button class="button" name="do" value="upload">' . esc_html__( 'Upload', 'botvanguard' ) . '</button>';
		if ( Botvanguard_Lists::mmdb_exists() ) { echo ' <button class="button" name="do" value="remove">' . esc_html__( 'Remove', 'botvanguard' ) . '</button>'; }
		echo '<br><span class="description">' . esc_html__( 'Not needed if your host or Cloudflare already sends the visitor country. Otherwise upload a free “Country” database in .mmdb format, for example GeoLite2-Country from MaxMind (free account) or the free IP-to-Country Lite from DB-IP. Download it yourself so that you accept its licence. Update it now and then.', 'botvanguard' ) . '</span></p></form>';
		// Tester.
		$res = get_transient( 'sidcraft_botshield_test_' . get_current_user_id() );
		echo '<h2>' . esc_html__( 'Test a browser name', 'botvanguard' ) . '</h2><form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		wp_nonce_field( 'sidcraft_botshield_test' ); echo '<input type="hidden" name="action" value="sidcraft_botshield_test">';
		echo '<input type="text" name="ua" class="large-text" placeholder="GPTBot/1.2 (+https://openai.com/gptbot)" style="max-width:420px"> <input type="text" name="ip" placeholder="' . esc_attr__( 'IP address (optional)', 'botvanguard' ) . '" style="width:190px"> <button class="button">' . esc_html__( 'Check', 'botvanguard' ) . '</button></form>';
		if ( is_array( $res ) ) { echo '<p><strong>' . esc_html( $res['ua'] ) . '</strong> → ' . esc_html( $res['text'] ) . '</p>'; delete_transient( 'sidcraft_botshield_test_' . get_current_user_id() ); }
		echo '</div>';
	}


		/** The never-block field: a text box, the visitor's own address, and a button that adds it. */
	public static function allow_fields( $value, $name, $id ) {
		$mine = Botvanguard_Guard::client_ip();
		$h = '<textarea id="' . esc_attr( $id ) . '" name="' . esc_attr( $name ) . '" rows="4" cols="50" placeholder="203.0.113.7&#10;198.51.100.0/24&#10;2001:db8::/32">' . esc_textarea( $value ) . '</textarea><br>';
		$h .= '<span class="description">' . esc_html__( 'One per line: single addresses, ranges like 203.0.113.0/24, or IPv6. These addresses are never blocked by any rule (bots, countries, VPN, address list, firewall, login, 404). Put your own office, home and server addresses here.', 'botvanguard' ) . '</span><br>';
		if ( '' !== $mine ) { $h .= '<span class="description">' . esc_html( sprintf( /* translators: %s: the visitor's IP address */ __( 'Your address right now: %s', 'botvanguard' ), $mine ) ) . '</span> <button type="button" class="button button-small" onclick="var t=document.getElementById(\'' . esc_js( $id ) . '\');if(t.value.split(/\\s+/).indexOf(\'' . esc_js( $mine ) . '\')<0){t.value=(t.value.trim()?t.value.trim()+\'\\n\':\'\')+\'' . esc_js( $mine ) . '\';}">' . esc_html__( 'Add my address', 'botvanguard' ) . '</button>'; }
		return $h;
	}

	public static function allow_save() {
		if ( ! current_user_can( 'manage_options' ) ) { wp_die( esc_html__( 'Not allowed.', 'botvanguard' ), 403 ); }
		check_admin_referer( 'sidcraft_botshield_allow' );
		Botvanguard_Settings::set_allow( isset( $_POST['ip_allow'] ) ? sanitize_textarea_field( wp_unslash( $_POST['ip_allow'] ) ) : '' );
		set_transient( 'sidcraft_botshield_notice_ok', __( 'The never-block list was saved.', 'botvanguard' ), 60 );
		wp_safe_redirect( admin_url( 'admin.php?page=botvanguard&tab=firewall' ) );
		exit;
	}

	/** Overview cards: how many were blocked, and what type. */
	private static function cards() {
		$periods = array( array( __( 'Today', 'botvanguard' ), 1 ), array( __( 'Last 7 days', 'botvanguard' ), 7 ), array( __( 'Last 30 days', 'botvanguard' ), 30 ) );
		$monitor = 'monitor' === Botvanguard_Settings::get( 'mode' );
		$types = Botvanguard_Log::types();
		echo '<div style="display:flex;flex-wrap:wrap;gap:14px;margin:14px 0">';
		foreach ( $periods as $p ) {
			$sm = Botvanguard_Log::summary( $p[1] ); $n = $monitor ? $sm['blocked'] + $sm['monitored'] : $sm['blocked']; $tot = max( 1, array_sum( $sm['by_type'] ) );
			echo '<div style="background:#fff;border:1px solid #c3c4c7;border-radius:6px;padding:14px 18px;min-width:240px;flex:1;max-width:380px">';
			echo '<div style="color:#646970;font-size:12px;text-transform:uppercase;letter-spacing:.04em">' . esc_html( $p[0] ) . '</div>';
			echo '<div style="font-size:34px;font-weight:600;line-height:1.2">' . esc_html( number_format_i18n( $n ) ) . '</div>';
			echo '<div style="color:#646970;margin-bottom:8px">' . esc_html( $monitor ? __( 'would be blocked (monitor mode)', 'botvanguard' ) : __( 'blocked', 'botvanguard' ) );
			if ( ! $monitor && $sm['monitored'] ) { echo ' · ' . esc_html( sprintf( /* translators: %s: number */ __( '%s more were only flagged in monitor mode', 'botvanguard' ), number_format_i18n( $sm['monitored'] ) ) ); }
			echo '</div>';
			if ( ! $sm['by_type'] ) { echo '<div class="description">' . esc_html__( 'Nothing yet.', 'botvanguard' ) . '</div>'; }
			foreach ( $types as $k => $t ) {
				$c = $sm['by_type'][ $k ] ?? 0; if ( ! $c ) { continue; }
				echo '<div style="display:flex;align-items:center;gap:8px;margin:3px 0"><span style="width:140px;flex:none;color:#50575e;font-size:12px;white-space:nowrap">' . esc_html( $t[0] ) . '</span><span style="flex:1;background:#f0f0f1;border-radius:3px;height:10px"><span style="display:block;height:10px;border-radius:3px;background:' . esc_attr( $t[1] ) . ';width:' . (int) max( 3, round( 100 * $c / $tot ) ) . '%"></span></span><strong style="min-width:28px;text-align:right">' . esc_html( number_format_i18n( $c ) ) . '</strong></div>';
			}
			echo '</div>';
		}
		echo '</div>';
	}

	private static function log_rows( $type ) {
		$rows = Botvanguard_Log::entries();
		if ( '' === $type ) { return $rows; }
		return array_values( array_filter( $rows, function ( $r ) use ( $type ) { return Botvanguard_Log::type_of( $r['r'] ) === $type; } ) );
	}

	private static function log_tab( $base ) {
		$types = Botvanguard_Log::types();
		$type  = isset( $_GET['type'] ) ? sanitize_key( wp_unslash( $_GET['type'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only filter.
		if ( ! isset( $types[ $type ] ) ) { $type = ''; }
		$all  = Botvanguard_Log::entries(); $rows = self::log_rows( $type );
		echo '<p>' . esc_html__( 'Who was blocked: the last 500 events from the past 30 days (address, country when known, why, page, browser name).', 'botvanguard' ) . '</p>';
		if ( ! Botvanguard_Settings::get( 'keep_log' ) ) { echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'The list is switched off in Settings → Data. Only the counters above are kept.', 'botvanguard' ) . '</p></div>'; }
		echo '<p><a href="' . esc_url( $base . '&tab=log' ) . '" class="button' . ( '' === $type ? ' button-primary' : '' ) . '">' . esc_html( sprintf( /* translators: %d: number */ __( 'All (%d)', 'botvanguard' ), count( $all ) ) ) . '</a> ';
		foreach ( $types as $k => $t ) { $n = count( self::log_rows( $k ) ); echo '<a href="' . esc_url( $base . '&tab=log&type=' . $k ) . '" class="button' . ( $k === $type ? ' button-primary' : '' ) . '">' . esc_html( $t[0] . ' (' . $n . ')' ) . '</a> '; }
		echo '</p>';
		if ( ! $rows ) { echo '<p>' . esc_html__( 'Nothing to show.', 'botvanguard' ) . '</p>'; return; }
		// Top addresses.
		$by = array(); foreach ( $rows as $r ) { $by[ $r['ip'] ] = ( $by[ $r['ip'] ] ?? 0 ) + 1; } arsort( $by );
		$top = array_slice( $by, 0, 8, true ); $parts = array();
		foreach ( $top as $ip => $n ) { $parts[] = '<code>' . esc_html( '' === $ip ? '?' : $ip ) . '</code> × ' . (int) $n; }
		echo '<p><strong>' . esc_html__( 'Most blocked addresses:', 'botvanguard' ) . '</strong> ' . wp_kses( implode( ' &nbsp; ', $parts ), array( 'code' => array() ) ) . '</p>';
		echo '<table class="widefat striped"><thead><tr><th>' . esc_html__( 'When', 'botvanguard' ) . '</th><th>' . esc_html__( 'What', 'botvanguard' ) . '</th><th>' . esc_html__( 'Type', 'botvanguard' ) . '</th><th>' . esc_html__( 'Why', 'botvanguard' ) . '</th><th>' . esc_html__( 'Address', 'botvanguard' ) . '</th><th>' . esc_html__( 'Country', 'botvanguard' ) . '</th><th>' . esc_html__( 'Page', 'botvanguard' ) . '</th><th>' . esc_html__( 'Browser name', 'botvanguard' ) . '</th><th>' . esc_html__( 'Action', 'botvanguard' ) . '</th></tr></thead><tbody>';
		$back = $base . '&tab=log' . ( '' !== $type ? '&type=' . $type : '' );
		foreach ( $rows as $r ) {
			$tk = Botvanguard_Log::type_of( $r['r'] );
			echo '<tr><td title="' . esc_attr( wp_date( 'Y-m-d H:i:s', $r['t'] ) ) . '">' . esc_html( human_time_diff( $r['t'] ) ) . '</td><td>' . esc_html( 'block' === $r['a'] ? __( 'Blocked', 'botvanguard' ) : __( 'Would block', 'botvanguard' ) ) . '</td><td><span style="color:' . esc_attr( $types[ $tk ][1] ) . '">●</span> ' . esc_html( $types[ $tk ][0] ) . '</td><td>' . esc_html( self::reason_label( $r['r'] ) ) . '</td><td>' . esc_html( $r['ip'] ) . '</td><td>' . esc_html( $r['c'] ?? '' ) . '</td><td style="word-break:break-all">' . esc_html( $r['p'] ) . '</td><td style="word-break:break-all">' . esc_html( $r['ua'] ) . '</td><td style="white-space:nowrap">' . wp_kses( self::row_actions( $r, $back ), self::$allowed ) . '</td></tr>';
		}
		echo '</tbody></table><p style="margin-top:10px"><a class="button" href="' . esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=sidcraft_botshield_csv&type=' . $type ), 'sidcraft_botshield_csv' ) ) . '">' . esc_html__( 'Download as CSV', 'botvanguard' ) . '</a> ';
		echo '</p><form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">'; wp_nonce_field( 'sidcraft_botshield_clear' ); echo '<input type="hidden" name="action" value="sidcraft_botshield_clear"><button class="button">' . esc_html__( 'Clear list and counters', 'botvanguard' ) . '</button></form>';
	}

	/** Never-block / block-forever links for one log row (already escaped). */
	public static function row_actions( $r, $back ) {
		$ip = (string) $r['ip']; $out = array();
		$link = function ( $act, $label, $extra = array() ) use ( $back ) {
			$u = add_query_arg( array_merge( array( 'action' => 'sidcraft_botshield_act', 'act' => $act, 'back' => rawurlencode( $back ) ), $extra ), admin_url( 'admin-post.php' ) );
			return '<a href="' . esc_url( wp_nonce_url( $u, 'sidcraft_botshield_act' ) ) . '">' . esc_html( $label ) . '</a>';
		};
		if ( '' !== $ip ) {
			if ( Botvanguard_Ranges::in_list( $ip, Botvanguard_Settings::lines( 'ip_allow' ) ) ) { $out[] = '<em>' . esc_html__( 'Allowed', 'botvanguard' ) . '</em> · ' . $link( 'block', __( 'Block', 'botvanguard' ), array( 'ip' => $ip ) ); }
			elseif ( Botvanguard_Ranges::in_list( $ip, Botvanguard_Settings::lines( 'ip_block' ) ) ) { $out[] = '<em>' . esc_html__( 'Blocked for good', 'botvanguard' ) . '</em> · ' . $link( 'allow', __( 'Unblock', 'botvanguard' ), array( 'ip' => $ip ) ); }
			else { $out[] = $link( 'allow', __( 'Unblock', 'botvanguard' ), array( 'ip' => $ip ) ) . ' · ' . $link( 'block', __( 'Block for good', 'botvanguard' ), array( 'ip' => $ip ) ); }
		}
		$tok = self::ua_token( (string) $r['ua'] );
		if ( '' !== $tok && 'bots' === Botvanguard_Log::type_of( $r['r'] ) && 'fake_bot' !== $r['r'] && ! in_array( $tok, Botvanguard_Settings::lines( 'custom_allow' ), true ) ) { $out[] = $link( 'allow_ua', sprintf( /* translators: %s: browser name token */ __( 'Allow “%s”', 'botvanguard' ), $tok ), array( 'tok' => $tok ) ); }
		return implode( '<br>', $out );
	}

	/** The bot's own name inside a browser string, e.g. “AhrefsBot” from “Mozilla/5.0 (compatible; AhrefsBot/7.0)”. */
	private static function ua_token( $ua ) {
		if ( preg_match_all( '/([A-Za-z][A-Za-z0-9._-]{2,})\/[0-9]/', $ua, $m ) ) { foreach ( $m[1] as $t ) { if ( ! in_array( strtolower( $t ), array( 'mozilla', 'applewebkit', 'safari', 'chrome', 'gecko', 'khtml' ), true ) ) { return strtolower( $t ); } } }
		return '';
	}

	public static function act() {
		if ( ! current_user_can( 'manage_options' ) ) { wp_die( esc_html__( 'Not allowed.', 'botvanguard' ), 403 ); }
		check_admin_referer( 'sidcraft_botshield_act' );
		$act = isset( $_GET['act'] ) ? sanitize_key( wp_unslash( $_GET['act'] ) ) : '';
		$ip  = isset( $_GET['ip'] ) ? sanitize_text_field( wp_unslash( $_GET['ip'] ) ) : '';
		$tok = isset( $_GET['tok'] ) ? strtolower( preg_replace( '/[^A-Za-z0-9._-]/', '', wp_unslash( $_GET['tok'] ) ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- stripped by preg_replace.
		$valid = '' !== Botvanguard_Ranges::pack( $ip );
		if ( 'allow' === $act && $valid ) {
			Botvanguard_Settings::remove_line( 'ip_block', $ip ); Botvanguard_Settings::add_line( 'ip_allow', $ip );
			Botvanguard_Bans::remove( $ip ); delete_transient( 'sbs_rate_' . md5( $ip ) );
		} elseif ( 'block' === $act && $valid ) {
			Botvanguard_Settings::remove_line( 'ip_allow', $ip ); Botvanguard_Settings::add_line( 'ip_block', $ip );
		} elseif ( 'allow_ua' === $act && strlen( $tok ) >= 3 ) {
			Botvanguard_Settings::add_line( 'custom_allow', $tok );
		} else { $act = ''; }
		$back = isset( $_GET['back'] ) ? esc_url_raw( rawurldecode( wp_unslash( $_GET['back'] ) ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		if ( 0 !== strpos( $back, admin_url() ) ) { $back = admin_url( 'admin.php?page=botvanguard&tab=log' ); }
		wp_safe_redirect( add_query_arg( 'sbs_done', $act, $back ) );
		exit;
	}


	/** The overview screen: what is switched on, and the latest blocks. */
	private static function dashboard_tab( $base ) {
		$bots = Botvanguard_Settings::all(); $fw = Botvanguard_FwSettings::all(); $lg = Botvanguard_LoginSettings::all();
		$mode = Botvanguard_FwSettings::effective_mode(); $scan = Botvanguard_Scanner::state();
		$on  = '<span style="color:#00a32a">●</span> '; $off = '<span style="color:#b32d2e">●</span> '; $mid = '<span style="color:#dba617">●</span> ';
		$rest = array( 'allow' => $off . esc_html__( 'Open to everyone', 'botvanguard' ), 'monitor' => $mid . esc_html__( 'Watching only (logs, no blocking)', 'botvanguard' ), 'login' => $on . esc_html__( 'Closed to visitors (except the allow list)', 'botvanguard' ) );
		$rows = array(
			array( __( 'Bot blocking', 'botvanguard' ), 'monitor' === $bots['mode'] ? $mid . esc_html__( 'Monitor only: nothing is blocked yet', 'botvanguard' ) : $on . esc_html__( 'On', 'botvanguard' ), $base . '-settings' ),
			array( __( 'Web application firewall', 'botvanguard' ), 'disabled' === $mode ? $off . esc_html__( 'Off', 'botvanguard' ) : ( 'learning' === $mode ? $mid . esc_html__( 'Learning (logs only)', 'botvanguard' ) : $on . esc_html__( 'On', 'botvanguard' ) ), $base . '-firewall' ),
			array( __( 'Login brute-force protection', 'botvanguard' ), $fw['bf_on'] ? $on . esc_html__( 'On', 'botvanguard' ) : $off . esc_html__( 'Off', 'botvanguard' ), $base . '-firewall' ),
			array( __( 'REST API (/wp-json/)', 'botvanguard' ), $rest[ $fw['rest_mode'] ] ?? $rest['allow'], $base . '-firewall' ),
			array( __( 'DDoS protection', 'botvanguard' ), '' !== Botvanguard_Ddos::status() ? $mid . esc_html__( 'ATTACK MODE ON', 'botvanguard' ) : ( 'off' === Botvanguard_Ddos::all()['mode'] ? $off . esc_html__( 'Off', 'botvanguard' ) : $on . esc_html__( 'Watching (starts by itself)', 'botvanguard' ) ), $base . '-ddos' ),
			array( __( 'XML-RPC', 'botvanguard' ), ( $fw['core_xmlrpc'] || 'all' === $fw['xmlrpc'] ) ? $on . esc_html__( 'Blocked', 'botvanguard' ) : ( 'multicall' === $fw['xmlrpc'] ? $mid . esc_html__( 'Open, multicall blocked', 'botvanguard' ) : $off . esc_html__( 'Open', 'botvanguard' ) ), $base . '-firewall' ),
			array( __( 'Two-factor login', 'botvanguard' ), $lg['tfa_on'] ? $on . esc_html__( 'On', 'botvanguard' ) : $off . esc_html__( 'Off', 'botvanguard' ), $base . '-login' ),
			array( __( 'Custom login address', 'botvanguard' ), $lg['url_on'] ? $on . esc_html__( 'On', 'botvanguard' ) : $off . esc_html__( 'Off', 'botvanguard' ), $base . '-login' ),
			array( __( 'Malware scan', 'botvanguard' ), ! empty( $scan['finished'] ) ? $on . esc_html( sprintf( /* translators: %s: time ago */ __( 'Last scan %s ago', 'botvanguard' ), human_time_diff( (int) $scan['finished'] ) ) ) : $off . esc_html__( 'Never run', 'botvanguard' ), $base . '-scan' ),
		);
		echo '<h2>' . esc_html__( 'Protection status', 'botvanguard' ) . '</h2><table class="widefat striped" style="max-width:760px"><tbody>';
		foreach ( $rows as $r ) { echo '<tr><td style="width:240px"><strong>' . esc_html( $r[0] ) . '</strong></td><td>' . wp_kses( $r[1], array( 'span' => array( 'style' => array() ) ) ) . '</td><td style="text-align:right"><a href="' . esc_url( $r[2] ) . '">' . esc_html__( 'Change', 'botvanguard' ) . '</a></td></tr>'; }
		echo '</tbody></table>';
		echo '<h2>' . esc_html__( 'Back up before you change anything', 'botvanguard' ) . '</h2>';
		echo '<p class="description" style="max-width:760px">' . esc_html__( 'Download a copy of these files and keep it somewhere safe. If a change ever locks you out, you can upload the copy again over FTP. wp-config.php contains your database password and secret keys: keep the copy private and never send it to anyone.', 'botvanguard' ) . '</p><p>';
		foreach ( array( 'htaccess' => __( 'Back up .htaccess', 'botvanguard' ), 'config' => __( 'Back up wp-config.php', 'botvanguard' ), 'phpini' => __( 'Back up php.ini', 'botvanguard' ), 'userini' => __( 'Back up .user.ini', 'botvanguard' ) ) as $k => $l ) {
			echo '<a class="button" href="' . esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=sidcraft_botshield_backup&file=' . $k ), 'sidcraft_botshield_backup' ) ) . '">' . esc_html( $l ) . '</a> ';
		}
		echo '</p>';
		echo '<h2>' . esc_html__( 'Latest blocks', 'botvanguard' ) . '</h2>';
		$entries = array_slice( Botvanguard_Log::entries(), 0, 10 );
		if ( ! $entries ) { echo '<p>' . esc_html__( 'Nothing blocked yet.', 'botvanguard' ) . '</p>'; }
		else {
			echo '<table class="widefat striped" style="max-width:760px"><tbody>';
			foreach ( $entries as $r ) { echo '<tr><td><code>' . esc_html( $r['ip'] ) . '</code></td><td>' . esc_html( human_time_diff( $r['t'] ) . ' · ' . self::reason_label( $r['r'] ) ) . '</td></tr>'; }
			echo '</tbody></table><p><a href="' . esc_url( $base . '-log' ) . '">' . esc_html__( 'Full blocked log', 'botvanguard' ) . '</a></p>';
		}
	}

	// ---- WordPress dashboard widget ----
	public static function dash_setup() {
		if ( current_user_can( 'manage_options' ) ) { wp_add_dashboard_widget( 'sidcraft_botshield_widget', 'Sidcraft BotVanguard', array( __CLASS__, 'dash_widget' ) ); }
	}

	public static function dash_widget() {
		$base = admin_url( 'admin.php?page=botvanguard' );
		$types = Botvanguard_Log::types(); $monitor = 'monitor' === Botvanguard_Settings::get( 'mode' );
		$t = Botvanguard_Log::summary( 1 ); $w = Botvanguard_Log::summary( 7 );
		$n = function ( $s ) use ( $monitor ) { return number_format_i18n( $monitor ? $s['blocked'] + $s['monitored'] : $s['blocked'] ); };
		echo '<p style="margin-top:0"><strong style="font-size:22px">' . esc_html( $n( $t ) ) . '</strong> ' . esc_html( $monitor ? __( 'would be blocked today', 'botvanguard' ) : __( 'blocked today', 'botvanguard' ) ) . ' &nbsp;·&nbsp; <strong>' . esc_html( $n( $w ) ) . '</strong> ' . esc_html__( 'in 7 days', 'botvanguard' ) . '</p>';
		$bits = array(); foreach ( $types as $k => $ty ) { if ( ! empty( $w['by_type'][ $k ] ) ) { $bits[] = '<span style="color:' . esc_attr( $ty[1] ) . '">●</span> ' . esc_html( $ty[0] . ' ' . $w['by_type'][ $k ] ); } }
		if ( $bits ) { echo '<p class="description">' . wp_kses( implode( ' &nbsp; ', $bits ), array( 'span' => array( 'style' => array() ) ) ) . '</p>'; }
		$rows = array_slice( Botvanguard_Log::entries(), 0, 8 );
		if ( ! $rows ) { echo '<p>' . esc_html__( 'Nothing blocked yet.', 'botvanguard' ) . '</p>'; }
		else {
			echo '<table class="widefat striped" style="margin-bottom:8px"><tbody>';
			foreach ( $rows as $r ) { echo '<tr><td><code>' . esc_html( $r['ip'] ) . '</code><br><span class="description">' . esc_html( human_time_diff( $r['t'] ) . ' · ' . self::reason_label( $r['r'] ) ) . '</span></td><td style="text-align:right;font-size:12px">' . wp_kses( self::row_actions( $r, admin_url( 'index.php' ) ), self::$allowed ) . '</td></tr>'; }
			echo '</tbody></table>';
		}
		echo '<p><a href="' . esc_url( $base . '&tab=log' ) . '">' . esc_html__( 'Full blocked log', 'botvanguard' ) . '</a> · <a href="' . esc_url( $base ) . '">' . esc_html__( 'Settings', 'botvanguard' ) . '</a></p>';
	}

	public static function csv() {
		if ( ! current_user_can( 'manage_options' ) ) { wp_die( esc_html__( 'Not allowed.', 'botvanguard' ), 403 ); }
		check_admin_referer( 'sidcraft_botshield_csv' );
		$type = isset( $_GET['type'] ) ? sanitize_key( wp_unslash( $_GET['type'] ) ) : '';
		$types = Botvanguard_Log::types(); if ( ! isset( $types[ $type ] ) ) { $type = ''; }
		nocache_headers();
		header( 'Content-Type: text/csv; charset=UTF-8' );
		header( 'Content-Disposition: attachment; filename="bot-shield-blocked-' . gmdate( 'Y-m-d' ) . '.csv"' );
		$out = fopen( 'php://output', 'w' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
		fputcsv( $out, array( 'time_utc', 'action', 'type', 'reason', 'ip', 'country', 'page', 'user_agent' ) );
		foreach ( self::log_rows( $type ) as $r ) {
			$cell = function ( $v ) { $v = (string) $v; return ( '' !== $v && in_array( $v[0], array( '=', '+', '-', '@' ), true ) ) ? "'" . $v : $v; }; // stop spreadsheet formula injection.
			fputcsv( $out, array( gmdate( 'Y-m-d H:i:s', $r['t'] ), $r['a'], Botvanguard_Log::type_of( $r['r'] ), $r['r'], $r['ip'], $r['c'] ?? '', $cell( $r['p'] ), $cell( $r['ua'] ) ) );
		}
		fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose
		exit;
	}

	public static function reason_label( $r ) {
		if ( 0 === strpos( $r, 'waf_' ) ) { $rules = Botvanguard_Waf::rules(); $id = substr( $r, 4 ); return isset( $rules[ $id ] ) ? $rules[ $id ][1] : $r; }
		$m = array( 'ddos_start' => __( 'DDoS attack mode started by a surge of requests', 'botvanguard' ), 'ddos_rate' => __( 'DDoS: too many requests from one address', 'botvanguard' ), 'rest_login' => __( 'REST API request from a visitor who is not logged in', 'botvanguard' ), 'rest_blocked' => __( 'REST API route closed to visitors', 'botvanguard' ), 'rest_rate' => __( 'Too many REST API requests', 'botvanguard' ), 'brute_probe' => __( 'Kept opening login or register pages', 'botvanguard' ), 'brute_invalid' => __( 'Logged in with user names that do not exist', 'botvanguard' ), 'banned' => __( 'Address banned earlier', 'botvanguard' ), 'trap' => __( 'Opened the hidden trap link', 'botvanguard' ), 'scanner_path' => __( 'Attack probe', 'botvanguard' ), 'fake_bot' => __( 'Fake search-engine bot', 'botvanguard' ), 'empty_ua' => __( 'No browser name', 'botvanguard' ), 'rate_limit' => __( 'Too many requests', 'botvanguard' ), 'custom_block' => __( 'On your block list', 'botvanguard' ), 'bad_bot_seo' => __( 'SEO / data-mining crawler', 'botvanguard' ), 'bad_bot_tools' => __( 'Script or headless browser', 'botvanguard' ), 'bad_bot_attack' => __( 'Attack tool', 'botvanguard' ), 'enum_author' => __( 'User enumeration attempt', 'botvanguard' ), 'blank_post' => __( 'POST without browser name and referrer', 'botvanguard' ), 'brute_login' => __( 'Too many failed logins', 'botvanguard' ), 'brute_invalid' => __( 'Login with a user that does not exist', 'botvanguard' ), 'brute_reset' => __( 'Too many password reset requests', 'botvanguard' ), 'login_url' => __( 'Wrong login address', 'botvanguard' ), 'rate_crawler' => __( 'Crawler too fast', 'botvanguard' ), 'rate_404' => __( 'Too many missing pages (404)', 'botvanguard' ), 'forbidden_name' => __( 'Asked for a forbidden file name or word', 'botvanguard' ), 'ip_blocked' => __( 'On your blocked addresses', 'botvanguard' ), 'geo_blocked' => __( 'Blocked country', 'botvanguard' ), 'geo_not_allowed' => __( 'Country not on your allowed list', 'botvanguard' ), 'geo_unknown' => __( 'Country unknown', 'botvanguard' ), 'tor' => __( 'Tor', 'botvanguard' ), 'vpn' => __( 'VPN', 'botvanguard' ), 'datacenter' => __( 'Hosting / data-centre address', 'botvanguard' ), 'proxy_header' => __( 'Proxy', 'botvanguard' ), 'vpn_api' => __( 'VPN / proxy (live check)', 'botvanguard' ) );
		return $m[ $r ] ?? $r;
	}


	/** After saving: fetch lists that are switched on but missing, and (un)schedule the daily update. */
	public static function saved() {
		Botvanguard_Lists::schedule();
		$s = Botvanguard_Settings::all(); $st = Botvanguard_Lists::status();
		foreach ( array( 'tor' => 'block_tor', 'vpn' => 'block_vpn', 'datacenter' => 'block_datacenter' ) as $k => $opt ) {
			if ( ! empty( $s[ $opt ] ) && empty( $st['lists'][ $k ] ) ) { wp_schedule_single_event( time() + 5, Botvanguard_Lists::CRON ); break; }
		}
	}

	public static function lists_now() {
		if ( ! current_user_can( 'manage_options' ) ) { wp_die( esc_html__( 'Not allowed.', 'botvanguard' ), 403 ); }
		check_admin_referer( 'sidcraft_botshield_lists' );
		Botvanguard_Lists::update();
		wp_safe_redirect( admin_url( 'admin.php?page=botvanguard' ) );
		exit;
	}

	public static function geodb() {
		if ( ! current_user_can( 'manage_options' ) ) { wp_die( esc_html__( 'Not allowed.', 'botvanguard' ), 403 ); }
		check_admin_referer( 'sidcraft_botshield_geodb' );
		$do = isset( $_POST['do'] ) ? sanitize_key( wp_unslash( $_POST['do'] ) ) : '';
		if ( 'remove' === $do ) { if ( Botvanguard_Lists::mmdb_exists() ) { wp_delete_file( Botvanguard_Lists::mmdb_path() ); } }
		elseif ( 'upload' === $do && ! empty( $_FILES['mmdb']['tmp_name'] ) && Botvanguard_Lists::ensure_dir() ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
			$d = Botvanguard_Lists::dir(); // computed before the filter, which would otherwise call itself.
			$to_dir = function ( $u ) use ( $d ) { $u['path'] = untrailingslashit( $d ); $u['subdir'] = ''; return $u; };
			add_filter( 'upload_dir', $to_dir );
			$res = wp_handle_upload( $_FILES['mmdb'], array( 'test_form' => false, 'test_type' => false, 'mimes' => array( 'mmdb' => 'application/octet-stream' ), 'unique_filename_callback' => function () { return 'upload-' . wp_generate_password( 8, false ) . '.mmdb'; } ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- handled by wp_handle_upload.
			remove_filter( 'upload_dir', $to_dir );
			if ( is_array( $res ) && ! empty( $res['file'] ) ) {
				$ok = '.mmdb' === strtolower( substr( $res['file'], -5 ) ) && Botvanguard_Mmdb::open( $res['file'] );
				if ( $ok ) { WP_Filesystem(); global $wp_filesystem; $wp_filesystem->move( $res['file'], Botvanguard_Lists::mmdb_path(), true ); Botvanguard_Geo::reset(); }
				else { wp_delete_file( $res['file'] ); }
			}
		}
		wp_safe_redirect( admin_url( 'admin.php?page=botvanguard' ) );
		exit;
	}


	/** Download a copy of .htaccess, wp-config.php, php.ini or .user.ini (administrators only, with a nonce). */
	public static function backup() {
		if ( ! current_user_can( 'manage_options' ) || ( is_multisite() && ! is_super_admin() ) ) { wp_die( esc_html__( 'Not allowed.', 'botvanguard' ), 403 ); }
		check_admin_referer( 'sidcraft_botshield_backup' );
		$which = isset( $_GET['file'] ) ? sanitize_key( wp_unslash( $_GET['file'] ) ) : '';
		$root  = trailingslashit( ABSPATH );
		if ( 'htaccess' === $which ) { $path = $root . '.htaccess'; $name = 'htaccess-backup'; }
		elseif ( 'config' === $which ) {
			$path = file_exists( $root . 'wp-config.php' ) ? $root . 'wp-config.php' : trailingslashit( dirname( untrailingslashit( $root ) ) ) . 'wp-config.php'; $name = 'wp-config-backup';
		} elseif ( 'phpini' === $which || 'userini' === $which ) {
			// php.ini or .user.ini: both live in the site's main folder (which one a host uses differs).
			$fname = 'phpini' === $which ? 'php.ini' : '.user.ini'; $path = $root . $fname; $name = 'phpini' === $which ? 'php-ini-backup' : 'user-ini-backup';
			if ( ! is_file( $path ) ) { /* translators: %s: file name */ wp_die( esc_html( sprintf( __( '%s was not found in the main folder of this site. Some hosts keep it elsewhere or manage it for you; ask your host for a copy.', 'botvanguard' ), $fname ) ), 404 ); }
		} else { wp_die( esc_html__( 'Unknown file.', 'botvanguard' ), 400 ); }
		if ( ! is_file( $path ) || ! is_readable( $path ) ) { wp_die( esc_html__( 'That file was not found or cannot be read on this server.', 'botvanguard' ), 404 ); }
		// The copy ends in .txt, so it can never run as PHP if someone stores it on a web server by mistake.
		nocache_headers();
		header( 'Content-Type: text/plain; charset=utf-8' );
		header( 'X-Content-Type-Options: nosniff' );
		header( 'Content-Disposition: attachment; filename="' . $name . '-' . gmdate( 'Ymd-His' ) . ( 'config' === $which ? '.php' : '' ) . '.txt"' );
		header( 'Content-Length: ' . (int) filesize( $path ) );
		readfile( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_readfile -- streams the file the administrator asked to download.
		exit;
	}

	public static function test() {
		if ( ! current_user_can( 'manage_options' ) ) { wp_die( esc_html__( 'Not allowed.', 'botvanguard' ), 403 ); }
		check_admin_referer( 'sidcraft_botshield_test' );
		$ua = isset( $_POST['ua'] ) ? sanitize_text_field( wp_unslash( $_POST['ua'] ) ) : '';
		$ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
		$ip = '' === Botvanguard_Ranges::pack( $ip ) ? '' : $ip;
		add_filter( 'sidcraft_botshield_trust_loopback', '__return_false' );
		$d = Botvanguard_Guard::decide( array( 'ip' => $ip, 'ua' => $ua, 'path' => '/', 'method' => 'GET', 'logged_in' => false, 'special' => false, 'country' => '' === $ip ? '' : Botvanguard_Geo::from_db( $ip ), 'proxy_headers' => false ) );
		$text = 'block' === $d['action'] ? sprintf( /* translators: %s: reason */ __( 'would be blocked (%s)', 'botvanguard' ), self::reason_label( $d['reason'] ) ) : __( 'allowed', 'botvanguard' );
		set_transient( 'sidcraft_botshield_test_' . get_current_user_id(), array( 'ua' => $ua . ( '' !== $ip ? ' @ ' . $ip : '' ), 'text' => $text ), 60 );
		wp_safe_redirect( admin_url( 'admin.php?page=botvanguard' ) );
		exit;
	}

	public static function clear() {
		if ( ! current_user_can( 'manage_options' ) ) { wp_die( esc_html__( 'Not allowed.', 'botvanguard' ), 403 ); }
		check_admin_referer( 'sidcraft_botshield_clear' );
		Botvanguard_Log::clear();
		wp_safe_redirect( admin_url( 'admin.php?page=botvanguard&tab=log' ) );
		exit;
	}
}
