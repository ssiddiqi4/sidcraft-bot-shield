<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

class Sidcraft_BotShield_Admin {
	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_init', array( __CLASS__, 'register' ) );
		add_action( 'admin_post_sidcraft_botshield_test', array( __CLASS__, 'test' ) );
		add_action( 'admin_post_sidcraft_botshield_clear', array( __CLASS__, 'clear' ) );
		add_action( 'admin_post_sidcraft_botshield_lists', array( __CLASS__, 'lists_now' ) );
		add_action( 'admin_post_sidcraft_botshield_geodb', array( __CLASS__, 'geodb' ) );
		add_action( 'update_option_' . Sidcraft_BotShield_Settings::OPTION, array( __CLASS__, 'saved' ) );
		add_action( 'admin_notices', array( __CLASS__, 'notice' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( SIDCRAFT_BOTSHIELD_FILE ), array( __CLASS__, 'links' ) );
	}

	public static function links( $l ) { array_unshift( $l, '<a href="' . esc_url( admin_url( 'options-general.php?page=sidcraft-bot-shield' ) ) . '">' . esc_html__( 'Settings', 'sidcraft-bot-shield' ) . '</a>' ); return $l; }

	public static function menu() { add_options_page( 'Sidcraft Bot Shield', 'Bot Shield', 'manage_options', 'sidcraft-bot-shield', array( __CLASS__, 'page' ) ); }

	public static function register() {
		register_setting( 'sidcraft_botshield_group', Sidcraft_BotShield_Settings::OPTION, array( 'type' => 'array', 'sanitize_callback' => array( 'Sidcraft_BotShield_Settings', 'sanitize' ), 'default' => Sidcraft_BotShield_Settings::defaults() ) );
	}

	public static function notice() {
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only screen check.
		if ( 'sidcraft-bot-shield' !== $page || ! current_user_can( 'manage_options' ) ) { return; }
		if ( 'monitor' === Sidcraft_BotShield_Settings::get( 'mode' ) ) {
			echo '<div class="notice notice-warning"><p><strong>' . esc_html__( 'Monitor mode:', 'sidcraft-bot-shield' ) . '</strong> ' . esc_html__( 'nothing is blocked yet. The list below shows what would be blocked. When it looks right, switch to “Block”.', 'sidcraft-bot-shield' ) . '</p></div>';
		}
	}

	private static function opt( $name ) { return esc_attr( Sidcraft_BotShield_Settings::OPTION . $name ); }

	public static function page() {
		if ( ! current_user_can( 'manage_options' ) ) { return; }
		$s = Sidcraft_BotShield_Settings::all(); $O = Sidcraft_BotShield_Settings::OPTION;
		echo '<div class="wrap"><h1>Sidcraft Bot Shield</h1>';
		echo '<p>' . esc_html__( 'Lets search engines and AI assistants in, and keeps scrapers, scripts, scanners and fake bots out. Visitors who look like normal browsers are never blocked, and neither are logged-in users.', 'sidcraft-bot-shield' ) . '</p>';
		// Stats.
		$st = Sidcraft_BotShield_Log::stats(); $today = $st[ gmdate( 'Ymd' ) ] ?? array( 'blocked' => 0, 'monitored' => 0, 'reasons' => array() );
		$tot_b = 0; $tot_m = 0; foreach ( $st as $d ) { $tot_b += $d['blocked']; $tot_m += $d['monitored']; }
		echo '<p><strong>' . esc_html__( 'Today:', 'sidcraft-bot-shield' ) . '</strong> ' . (int) $today['blocked'] . ' ' . esc_html__( 'blocked', 'sidcraft-bot-shield' ) . ', ' . (int) $today['monitored'] . ' ' . esc_html__( 'would be blocked (monitor mode)', 'sidcraft-bot-shield' ) . ' &nbsp;|&nbsp; <strong>' . esc_html__( 'Last 14 days:', 'sidcraft-bot-shield' ) . '</strong> ' . (int) $tot_b . ' / ' . (int) $tot_m . '</p>';
		echo '<form method="post" action="options.php">'; settings_fields( 'sidcraft_botshield_group' );
		echo '<table class="form-table" role="presentation"><tbody>';
		echo '<tr><th>' . esc_html__( 'Mode', 'sidcraft-bot-shield' ) . '</th><td><label><input type="radio" name="' . esc_attr( $O ) . '[mode]" value="monitor" ' . checked( $s['mode'], 'monitor', false ) . '> ' . esc_html__( 'Monitor only: log what would be blocked (recommended for the first days)', 'sidcraft-bot-shield' ) . '</label><br><label><input type="radio" name="' . esc_attr( $O ) . '[mode]" value="block" ' . checked( $s['mode'], 'block', false ) . '> ' . esc_html__( 'Block: answer unwanted bots with “403 Access denied”', 'sidcraft-bot-shield' ) . '</label></td></tr>';
		echo '<tr><th>' . esc_html__( 'Always allow', 'sidcraft-bot-shield' ) . '</th><td>';
		foreach ( Sidcraft_BotShield_Catalog::allowed() as $gk => $g ) {
			$names = array(); foreach ( $g['bots'] as $info ) { $names[ $info[0] ] = 1; }
			echo '<p><label><input type="checkbox" name="' . esc_attr( $O ) . '[allow][' . esc_attr( $gk ) . ']" value="1" ' . checked( ! empty( $s['allow'][ $gk ] ), true, false ) . '> <strong>' . esc_html( $g['label'] ) . '</strong></label><br><span class="description">' . esc_html( implode( ', ', array_keys( $names ) ) ) . '</span></p>';
		}
		echo '<p><label><input type="checkbox" name="' . esc_attr( $O ) . '[verify]" value="1" ' . checked( ! empty( $s['verify'] ), true, false ) . '> ' . esc_html__( 'Check that Google, Bing, Apple, Yahoo, Yandex and Baidu are genuine (their address must belong to them). Fake ones are blocked.', 'sidcraft-bot-shield' ) . '</label></p>';
		echo '<p class="description">' . esc_html__( 'AI crawlers are recognised by name only, because most AI companies do not publish a way to prove who they are. Anyone can claim such a name, so a determined scraper could pretend to be one.', 'sidcraft-bot-shield' ) . '</p></td></tr>';
		echo '<tr><th>' . esc_html__( 'Block', 'sidcraft-bot-shield' ) . '</th><td>';
		foreach ( Sidcraft_BotShield_Catalog::blocked() as $gk => $g ) {
			echo '<p><label><input type="checkbox" name="' . esc_attr( $O ) . '[block][' . esc_attr( $gk ) . ']" value="1" ' . checked( ! empty( $s['block'][ $gk ] ), true, false ) . '> <strong>' . esc_html( $g['label'] ) . '</strong></label><br><span class="description">' . esc_html( implode( ', ', array_slice( $g['tokens'], 0, 14 ) ) ) . '…</span></p>';
		}
		echo '<p><label><input type="checkbox" name="' . esc_attr( $O ) . '[block_empty]" value="1" ' . checked( ! empty( $s['block_empty'] ), true, false ) . '> ' . esc_html__( 'Visitors that send no browser name at all', 'sidcraft-bot-shield' ) . '</label></p>';
		echo '<p><label><input type="checkbox" name="' . esc_attr( $O ) . '[block_scanners]" value="1" ' . checked( ! empty( $s['block_scanners'] ), true, false ) . '> ' . esc_html__( 'Attack probes (/shell, /.env, /phpmyadmin, wp-config backups…) and ban the address that sent them', 'sidcraft-bot-shield' ) . '</label></p>';
		echo '<p class="description">' . esc_html__( 'Only page requests are checked for browser names, so forms, payments, webhooks and apps keep working.', 'sidcraft-bot-shield' ) . '</p></td></tr>';
		echo '<tr><th><label for="sbs-ban">' . esc_html__( 'Ban length (hours)', 'sidcraft-bot-shield' ) . '</label></th><td><input id="sbs-ban" type="number" min="1" max="720" name="' . esc_attr( $O ) . '[ban_hours]" value="' . (int) $s['ban_hours'] . '" class="small-text"></td></tr>';
		echo '<tr><th>' . esc_html__( 'Extra options', 'sidcraft-bot-shield' ) . '</th><td>';
		echo '<p><label><input type="checkbox" name="' . esc_attr( $O ) . '[honeypot]" value="1" ' . checked( ! empty( $s['honeypot'] ), true, false ) . '> ' . esc_html__( 'Trap: add a hidden link that robots.txt forbids. Any robot that opens it is banned.', 'sidcraft-bot-shield' ) . '</label></p>';
		echo '<p><label><input type="checkbox" name="' . esc_attr( $O ) . '[rate_limit]" value="1" ' . checked( ! empty( $s['rate_limit'] ), true, false ) . '> ' . esc_html__( 'Speed limit: no more than', 'sidcraft-bot-shield' ) . '</label> <input type="number" min="20" max="5000" name="' . esc_attr( $O ) . '[rate_per_min]" value="' . (int) $s['rate_per_min'] . '" class="small-text"> ' . esc_html__( 'page requests a minute from one address (uses a little database writing on every visit)', 'sidcraft-bot-shield' ) . '</p>';
		echo '<p><label>' . esc_html__( 'Is your site behind Cloudflare or another proxy?', 'sidcraft-bot-shield' ) . ' <select name="' . esc_attr( $O ) . '[proxy]"><option value="none" ' . selected( $s['proxy'], 'none', false ) . '>' . esc_html__( 'No', 'sidcraft-bot-shield' ) . '</option><option value="cloudflare" ' . selected( $s['proxy'], 'cloudflare', false ) . '>Cloudflare</option><option value="xff" ' . selected( $s['proxy'], 'xff', false ) . '>' . esc_html__( 'Other proxy (X-Forwarded-For)', 'sidcraft-bot-shield' ) . '</option></select></label></p></td></tr>';
		// Countries, addresses, VPN / Tor.
		$name_geo = esc_attr( $O ) . '[geo_countries][]';
		echo '<tr><th>' . esc_html__( 'Countries', 'sidcraft-bot-shield' ) . '</th><td>';
		echo '<p><label><input type="radio" name="' . esc_attr( $O ) . '[geo_mode]" value="off" ' . checked( $s['geo_mode'], 'off', false ) . '> ' . esc_html__( 'Do not use countries', 'sidcraft-bot-shield' ) . '</label><br>';
		echo '<label><input type="radio" name="' . esc_attr( $O ) . '[geo_mode]" value="block" ' . checked( $s['geo_mode'], 'block', false ) . '> ' . esc_html__( 'Block the countries I select', 'sidcraft-bot-shield' ) . '</label><br>';
		echo '<label><input type="radio" name="' . esc_attr( $O ) . '[geo_mode]" value="allow_only" ' . checked( $s['geo_mode'], 'allow_only', false ) . '> ' . esc_html__( 'Only allow the countries I select (everyone else is blocked)', 'sidcraft-bot-shield' ) . '</label></p>';
		echo '<select name="' . $name_geo . '" multiple size="10" style="min-width:320px">'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped above.
		foreach ( Sidcraft_BotShield_Countries::all() as $code => $cn ) { echo '<option value="' . esc_attr( $code ) . '" ' . selected( in_array( $code, $s['geo_countries'], true ), true, false ) . '>' . esc_html( $cn . ' (' . $code . ')' ) . '</option>'; }
		echo '</select><p class="description">' . esc_html__( 'Hold Ctrl (Windows) or Cmd (Mac) to select several.', 'sidcraft-bot-shield' ) . '</p>';
		echo '<p><label>' . esc_html__( 'If the country cannot be found:', 'sidcraft-bot-shield' ) . ' <select name="' . esc_attr( $O ) . '[geo_unknown]"><option value="allow" ' . selected( $s['geo_unknown'], 'allow', false ) . '>' . esc_html__( 'let the visitor in', 'sidcraft-bot-shield' ) . '</option><option value="block" ' . selected( $s['geo_unknown'], 'block', false ) . '>' . esc_html__( 'block the visitor', 'sidcraft-bot-shield' ) . '</option></select></label></p>';
		echo '<p><label><input type="checkbox" name="' . esc_attr( $O ) . '[geo_bots_exempt]" value="1" ' . checked( ! empty( $s['geo_bots_exempt'] ), true, false ) . '> ' . esc_html__( 'Welcome bots (search engines, AI assistants) ignore the country, VPN and Tor rules. Recommended: Google crawls from the USA.', 'sidcraft-bot-shield' ) . '</label></p>';
		$geo = Sidcraft_BotShield_Geo::detect( Sidcraft_BotShield_Guard::client_ip() );
		$src = '' !== $geo[0] ? sprintf( /* translators: 1: country code, 2: where it came from */ __( 'Your country right now: %1$s (from %2$s)', 'sidcraft-bot-shield' ), $geo[0], $geo[1] ) : __( 'No country source found yet. Ask your host or Cloudflare to send the visitor country, or upload a country database below. Until then every visitor counts as “country unknown”.', 'sidcraft-bot-shield' );
		echo '<p class="description"><strong>' . esc_html( $src ) . '</strong></p>';
		echo '<p class="description">' . esc_html__( 'Country is read from Cloudflare, CloudFront or your server when available, otherwise from the country database file below. Logged-in users are never blocked.', 'sidcraft-bot-shield' ) . '</p></td></tr>';

		echo '<tr><th><label for="sbs-ipb">' . esc_html__( 'Block addresses', 'sidcraft-bot-shield' ) . '</label></th><td><textarea id="sbs-ipb" name="' . esc_attr( $O ) . '[ip_block]" rows="5" cols="50" placeholder="203.0.113.7&#10;198.51.100.0/24&#10;192.0.2.10 - 192.0.2.99&#10;2001:db8::/32">' . esc_textarea( $s['ip_block'] ) . '</textarea><br><span class="description">' . esc_html__( 'One per line. IPv4 and IPv6. Single address, range with / (203.0.113.0/24), or from - to (192.0.2.10 - 192.0.2.99). Up to 2000 lines. Your “never block” list and logged-in users win over this list.', 'sidcraft-bot-shield' ) . '</span></td></tr>';

		$ls = Sidcraft_BotShield_Lists::status();
		echo '<tr><th>' . esc_html__( 'VPN, proxies and Tor', 'sidcraft-bot-shield' ) . '</th><td>';
		$rows = array( 'block_tor' => array( 'tor', __( 'Block Tor (anonymising network)', 'sidcraft-bot-shield' ) ), 'block_vpn' => array( 'vpn', __( 'Block commercial VPN services (list of known VPN addresses)', 'sidcraft-bot-shield' ) ), 'block_datacenter' => array( 'datacenter', __( 'Block hosting / data-centre addresses (stricter: also blocks many proxies and bots; real visitors on company clouds may be caught)', 'sidcraft-bot-shield' ) ) );
		foreach ( $rows as $k => $info ) {
			$d = $ls['lists'][ $info[0] ] ?? null;
			$st = $d ? sprintf( /* translators: 1: ranges, 2: time ago */ __( ' — %1$s ranges, updated %2$s ago', 'sidcraft-bot-shield' ), number_format_i18n( $d['v4'] + $d['v6'] ), human_time_diff( $d['time'] ) ) : '';
			echo '<p><label><input type="checkbox" name="' . esc_attr( $O ) . '[' . esc_attr( $k ) . ']" value="1" ' . checked( ! empty( $s[ $k ] ), true, false ) . '> ' . esc_html( $info[1] ) . '</label><span class="description">' . esc_html( $st ) . '</span></p>';
		}
		echo '<p><label><input type="checkbox" name="' . esc_attr( $O ) . '[block_proxy_headers]" value="1" ' . checked( ! empty( $s['block_proxy_headers'] ), true, false ) . '> ' . esc_html__( 'Block visitors whose request carries proxy headers (Via, X-Forwarded-For). Only works when your site is NOT behind Cloudflare or another proxy (choose “No” above). Some company and school networks use such proxies.', 'sidcraft-bot-shield' ) . '</label></p>';
		echo '<p><label>' . esc_html__( 'Live check with proxycheck.io (optional):', 'sidcraft-bot-shield' ) . ' <select name="' . esc_attr( $O ) . '[vpn_api]"><option value="none" ' . selected( $s['vpn_api'], 'none', false ) . '>' . esc_html__( 'off', 'sidcraft-bot-shield' ) . '</option><option value="proxycheck" ' . selected( $s['vpn_api'], 'proxycheck', false ) . '>' . esc_html__( 'on', 'sidcraft-bot-shield' ) . '</option></select></label> <input type="text" name="' . esc_attr( $O ) . '[vpn_api_key]" value="' . esc_attr( $s['vpn_api_key'] ) . '" placeholder="' . esc_attr__( 'your API key', 'sidcraft-bot-shield' ) . '" autocomplete="off"><br><span class="description">' . esc_html__( 'Catches VPNs and proxies that are not on the lists. When on, the visitor’s IP address is sent to proxycheck.io (once a week per address). Needs your own key from proxycheck.io.', 'sidcraft-bot-shield' ) . '</span></p>';
		if ( ! empty( $ls['error'] ) ) { echo '<p class="description" style="color:#b32d2e">' . esc_html( $ls['error'] ) . '</p>'; }
		echo '<p class="description">' . esc_html__( 'The lists are downloaded once a day from the Tor Project and from the open X4BNet VPN list on GitHub, and kept on your server. Nothing about your visitors is sent for the lists.', 'sidcraft-bot-shield' ) . '</p></td></tr>';

		echo '<tr><th><label for="sbs-ca">' . esc_html__( 'Your own lists', 'sidcraft-bot-shield' ) . '</label></th><td>';
		echo '<p><strong>' . esc_html__( 'Also allow (names, one per line)', 'sidcraft-bot-shield' ) . '</strong><br><textarea id="sbs-ca" name="' . esc_attr( $O ) . '[custom_allow]" rows="3" cols="50">' . esc_textarea( $s['custom_allow'] ) . '</textarea></p>';
		echo '<p><strong>' . esc_html__( 'Also block (names, one per line; wins over the allow lists)', 'sidcraft-bot-shield' ) . '</strong><br><textarea name="' . esc_attr( $O ) . '[custom_block]" rows="3" cols="50">' . esc_textarea( $s['custom_block'] ) . '</textarea></p>';
		echo '<p><strong>' . esc_html__( 'Never block these addresses (one per line, ranges like 203.0.113.0/24 allowed)', 'sidcraft-bot-shield' ) . '</strong><br><textarea name="' . esc_attr( $O ) . '[ip_allow]" rows="3" cols="50">' . esc_textarea( $s['ip_allow'] ) . '</textarea><br><span class="description">' . esc_html( sprintf( /* translators: %s: the visitor's IP address */ __( 'Your address right now: %s', 'sidcraft-bot-shield' ), Sidcraft_BotShield_Guard::client_ip() ) ) . '</span></p></td></tr>';
		echo '<tr><th>' . esc_html__( 'Data', 'sidcraft-bot-shield' ) . '</th><td><label><input type="checkbox" name="' . esc_attr( $O ) . '[keep_log]" value="1" ' . checked( ! empty( $s['keep_log'] ), true, false ) . '> ' . esc_html__( 'Keep a list of the last 100 blocked requests for 7 days (address, browser name, page)', 'sidcraft-bot-shield' ) . '</label><br><label><input type="checkbox" name="' . esc_attr( $O ) . '[remove_data]" value="1" ' . checked( ! empty( $s['remove_data'] ), true, false ) . '> ' . esc_html__( 'Delete all Bot Shield data when the plugin is deleted', 'sidcraft-bot-shield' ) . '</label></td></tr>';
		echo '</tbody></table>'; submit_button(); echo '</form>';
		// Lists + country database.
		echo '<h2>' . esc_html__( 'Address lists and country database', 'sidcraft-bot-shield' ) . '</h2>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="margin-bottom:14px">'; wp_nonce_field( 'sidcraft_botshield_lists' ); echo '<input type="hidden" name="action" value="sidcraft_botshield_lists"><button class="button">' . esc_html__( 'Update Tor / VPN lists now', 'sidcraft-bot-shield' ) . '</button> <span class="description">' . esc_html__( 'Only the lists you ticked above are downloaded.', 'sidcraft-bot-shield' ) . '</span></form>';
		echo '<form method="post" enctype="multipart/form-data" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">'; wp_nonce_field( 'sidcraft_botshield_geodb' ); echo '<input type="hidden" name="action" value="sidcraft_botshield_geodb">';
		echo '<p><strong>' . esc_html__( 'Country database (optional)', 'sidcraft-bot-shield' ) . '</strong> — ' . esc_html( Sidcraft_BotShield_Lists::mmdb_exists() ? __( 'installed', 'sidcraft-bot-shield' ) : __( 'none', 'sidcraft-bot-shield' ) ) . '<br><input type="file" name="mmdb" accept=".mmdb"> <button class="button" name="do" value="upload">' . esc_html__( 'Upload', 'sidcraft-bot-shield' ) . '</button>';
		if ( Sidcraft_BotShield_Lists::mmdb_exists() ) { echo ' <button class="button" name="do" value="remove">' . esc_html__( 'Remove', 'sidcraft-bot-shield' ) . '</button>'; }
		echo '<br><span class="description">' . esc_html__( 'Not needed if your host or Cloudflare already sends the visitor country. Otherwise upload a free “Country” database in .mmdb format, for example GeoLite2-Country from MaxMind (free account) or the free IP-to-Country Lite from DB-IP. Download it yourself so that you accept its licence. Update it now and then.', 'sidcraft-bot-shield' ) . '</span></p></form>';
		// Tester.
		$res = get_transient( 'sidcraft_botshield_test_' . get_current_user_id() );
		echo '<h2>' . esc_html__( 'Test a browser name', 'sidcraft-bot-shield' ) . '</h2><form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		wp_nonce_field( 'sidcraft_botshield_test' ); echo '<input type="hidden" name="action" value="sidcraft_botshield_test">';
		echo '<input type="text" name="ua" class="large-text" placeholder="GPTBot/1.2 (+https://openai.com/gptbot)" style="max-width:420px"> <input type="text" name="ip" placeholder="' . esc_attr__( 'IP address (optional)', 'sidcraft-bot-shield' ) . '" style="width:190px"> <button class="button">' . esc_html__( 'Check', 'sidcraft-bot-shield' ) . '</button></form>';
		if ( is_array( $res ) ) { echo '<p><strong>' . esc_html( $res['ua'] ) . '</strong> → ' . esc_html( $res['text'] ) . '</p>'; delete_transient( 'sidcraft_botshield_test_' . get_current_user_id() ); }
		// Log.
		$log = Sidcraft_BotShield_Log::entries();
		echo '<h2>' . esc_html__( 'Recent activity', 'sidcraft-bot-shield' ) . '</h2>';
		if ( ! $log ) { echo '<p>' . esc_html__( 'Nothing yet.', 'sidcraft-bot-shield' ) . '</p>'; }
		else {
			echo '<table class="widefat striped"><thead><tr><th>' . esc_html__( 'When', 'sidcraft-bot-shield' ) . '</th><th>' . esc_html__( 'What', 'sidcraft-bot-shield' ) . '</th><th>' . esc_html__( 'Why', 'sidcraft-bot-shield' ) . '</th><th>' . esc_html__( 'Address', 'sidcraft-bot-shield' ) . '</th><th>' . esc_html__( 'Page', 'sidcraft-bot-shield' ) . '</th><th>' . esc_html__( 'Browser name', 'sidcraft-bot-shield' ) . '</th></tr></thead><tbody>';
			foreach ( $log as $r ) { echo '<tr><td>' . esc_html( human_time_diff( $r['t'] ) ) . '</td><td>' . esc_html( 'block' === $r['a'] ? __( 'Blocked', 'sidcraft-bot-shield' ) : __( 'Would block', 'sidcraft-bot-shield' ) ) . '</td><td>' . esc_html( self::reason_label( $r['r'] ) ) . '</td><td>' . esc_html( $r['ip'] ) . '</td><td style="word-break:break-all">' . esc_html( $r['p'] ) . '</td><td style="word-break:break-all">' . esc_html( $r['ua'] ) . '</td></tr>'; }
			echo '</tbody></table><form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="margin-top:10px">'; wp_nonce_field( 'sidcraft_botshield_clear' ); echo '<input type="hidden" name="action" value="sidcraft_botshield_clear"><button class="button">' . esc_html__( 'Clear list', 'sidcraft-bot-shield' ) . '</button></form>';
		}
		echo '</div>';
	}

	public static function reason_label( $r ) {
		$m = array( 'banned' => __( 'Address banned earlier', 'sidcraft-bot-shield' ), 'trap' => __( 'Opened the hidden trap link', 'sidcraft-bot-shield' ), 'scanner_path' => __( 'Attack probe', 'sidcraft-bot-shield' ), 'fake_bot' => __( 'Fake search-engine bot', 'sidcraft-bot-shield' ), 'empty_ua' => __( 'No browser name', 'sidcraft-bot-shield' ), 'rate_limit' => __( 'Too many requests', 'sidcraft-bot-shield' ), 'custom_block' => __( 'On your block list', 'sidcraft-bot-shield' ), 'bad_bot_seo' => __( 'SEO / data-mining crawler', 'sidcraft-bot-shield' ), 'bad_bot_tools' => __( 'Script or headless browser', 'sidcraft-bot-shield' ), 'bad_bot_attack' => __( 'Attack tool', 'sidcraft-bot-shield' ), 'ip_blocked' => __( 'On your blocked addresses', 'sidcraft-bot-shield' ), 'geo_blocked' => __( 'Blocked country', 'sidcraft-bot-shield' ), 'geo_not_allowed' => __( 'Country not on your allowed list', 'sidcraft-bot-shield' ), 'geo_unknown' => __( 'Country unknown', 'sidcraft-bot-shield' ), 'tor' => __( 'Tor', 'sidcraft-bot-shield' ), 'vpn' => __( 'VPN', 'sidcraft-bot-shield' ), 'datacenter' => __( 'Hosting / data-centre address', 'sidcraft-bot-shield' ), 'proxy_header' => __( 'Proxy', 'sidcraft-bot-shield' ), 'vpn_api' => __( 'VPN / proxy (live check)', 'sidcraft-bot-shield' ) );
		return $m[ $r ] ?? $r;
	}


	/** After saving: fetch lists that are switched on but missing, and (un)schedule the daily update. */
	public static function saved() {
		Sidcraft_BotShield_Lists::schedule();
		$s = Sidcraft_BotShield_Settings::all(); $st = Sidcraft_BotShield_Lists::status();
		foreach ( array( 'tor' => 'block_tor', 'vpn' => 'block_vpn', 'datacenter' => 'block_datacenter' ) as $k => $opt ) {
			if ( ! empty( $s[ $opt ] ) && empty( $st['lists'][ $k ] ) ) { wp_schedule_single_event( time() + 5, Sidcraft_BotShield_Lists::CRON ); break; }
		}
	}

	public static function lists_now() {
		if ( ! current_user_can( 'manage_options' ) ) { wp_die( esc_html__( 'Not allowed.', 'sidcraft-bot-shield' ), 403 ); }
		check_admin_referer( 'sidcraft_botshield_lists' );
		Sidcraft_BotShield_Lists::update();
		wp_safe_redirect( admin_url( 'options-general.php?page=sidcraft-bot-shield' ) );
		exit;
	}

	public static function geodb() {
		if ( ! current_user_can( 'manage_options' ) ) { wp_die( esc_html__( 'Not allowed.', 'sidcraft-bot-shield' ), 403 ); }
		check_admin_referer( 'sidcraft_botshield_geodb' );
		$do = isset( $_POST['do'] ) ? sanitize_key( wp_unslash( $_POST['do'] ) ) : '';
		if ( 'remove' === $do ) { if ( Sidcraft_BotShield_Lists::mmdb_exists() ) { wp_delete_file( Sidcraft_BotShield_Lists::mmdb_path() ); } }
		elseif ( 'upload' === $do && ! empty( $_FILES['mmdb']['tmp_name'] ) && is_uploaded_file( $_FILES['mmdb']['tmp_name'] ) && Sidcraft_BotShield_Lists::ensure_dir() ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- temp path from PHP.
			$name = isset( $_FILES['mmdb']['name'] ) ? sanitize_file_name( wp_unslash( $_FILES['mmdb']['name'] ) ) : '';
			$tmp  = $_FILES['mmdb']['tmp_name']; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			$test = Sidcraft_BotShield_Mmdb::open( $tmp );
			if ( '.mmdb' === strtolower( substr( $name, -5 ) ) && $test && '' !== $test->country( '8.8.8.8' ) . 'x' ) { move_uploaded_file( $tmp, Sidcraft_BotShield_Lists::mmdb_path() ); } // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		}
		wp_safe_redirect( admin_url( 'options-general.php?page=sidcraft-bot-shield' ) );
		exit;
	}

	public static function test() {
		if ( ! current_user_can( 'manage_options' ) ) { wp_die( esc_html__( 'Not allowed.', 'sidcraft-bot-shield' ), 403 ); }
		check_admin_referer( 'sidcraft_botshield_test' );
		$ua = isset( $_POST['ua'] ) ? sanitize_text_field( wp_unslash( $_POST['ua'] ) ) : '';
		$ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
		$ip = '' === Sidcraft_BotShield_Ranges::pack( $ip ) ? '' : $ip;
		add_filter( 'sidcraft_botshield_trust_loopback', '__return_false' );
		$d = Sidcraft_BotShield_Guard::decide( array( 'ip' => $ip, 'ua' => $ua, 'path' => '/', 'method' => 'GET', 'logged_in' => false, 'special' => false, 'country' => '' === $ip ? '' : Sidcraft_BotShield_Geo::from_db( $ip ), 'proxy_headers' => false ) );
		$text = 'block' === $d['action'] ? sprintf( /* translators: %s: reason */ __( 'would be blocked (%s)', 'sidcraft-bot-shield' ), self::reason_label( $d['reason'] ) ) : __( 'allowed', 'sidcraft-bot-shield' );
		set_transient( 'sidcraft_botshield_test_' . get_current_user_id(), array( 'ua' => $ua . ( '' !== $ip ? ' @ ' . $ip : '' ), 'text' => $text ), 60 );
		wp_safe_redirect( admin_url( 'options-general.php?page=sidcraft-bot-shield' ) );
		exit;
	}

	public static function clear() {
		if ( ! current_user_can( 'manage_options' ) ) { wp_die( esc_html__( 'Not allowed.', 'sidcraft-bot-shield' ), 403 ); }
		check_admin_referer( 'sidcraft_botshield_clear' );
		Sidcraft_BotShield_Log::clear();
		wp_safe_redirect( admin_url( 'options-general.php?page=sidcraft-bot-shield' ) );
		exit;
	}
}
