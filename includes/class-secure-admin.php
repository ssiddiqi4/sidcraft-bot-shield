<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/** Admin screens for the Firewall and Scan tabs. */
class Sidcraft_BotShield_SecureAdmin {
	public static function init() {
		add_action( 'admin_init', array( __CLASS__, 'register' ) );
		add_action( 'wp_ajax_sidcraft_botshield_scan', array( __CLASS__, 'ajax' ) );
		add_action( 'admin_post_sidcraft_botshield_finding', array( __CLASS__, 'finding_action' ) );
		add_action( 'admin_post_sidcraft_botshield_ext', array( __CLASS__, 'ext_action' ) );
		add_action( 'admin_post_sidcraft_botshield_unban', array( __CLASS__, 'unban' ) );
		add_action( 'admin_post_sidcraft_botshield_unban_mail', array( __CLASS__, 'unban_mail' ) );
		add_action( 'update_option_' . Sidcraft_BotShield_LoginSettings::OPTION, array( __CLASS__, 'login_saved' ), 10, 2 );
		add_action( 'add_option_' . Sidcraft_BotShield_LoginSettings::OPTION, function ( $o, $v ) { Sidcraft_BotShield_SecureAdmin::login_saved( Sidcraft_BotShield_LoginSettings::defaults(), $v ); }, 10, 2 );
		add_action( 'update_option_' . Sidcraft_BotShield_FwSettings::OPTION, array( 'Sidcraft_BotShield_Firewall', 'ext_sync' ) );
		add_action( 'update_option_' . Sidcraft_BotShield_ScanSettings::OPTION, function () { Sidcraft_BotShield_Scanner::schedule( true ); } );
		add_action( 'add_option_' . Sidcraft_BotShield_ScanSettings::OPTION, function () { Sidcraft_BotShield_Scanner::schedule( true ); } );
	}

	public static function register() {
		register_setting( 'sidcraft_botshield_fw_group', Sidcraft_BotShield_FwSettings::OPTION, array( 'type' => 'array', 'sanitize_callback' => array( 'Sidcraft_BotShield_FwSettings', 'sanitize' ), 'default' => Sidcraft_BotShield_FwSettings::defaults() ) );
		register_setting( 'sidcraft_botshield_login_group', Sidcraft_BotShield_LoginSettings::OPTION, array( 'type' => 'array', 'sanitize_callback' => array( 'Sidcraft_BotShield_LoginSettings', 'sanitize' ), 'default' => Sidcraft_BotShield_LoginSettings::defaults() ) );
		register_setting( 'sidcraft_botshield_scan_group', Sidcraft_BotShield_ScanSettings::OPTION, array( 'type' => 'array', 'sanitize_callback' => array( 'Sidcraft_BotShield_ScanSettings', 'sanitize' ), 'default' => Sidcraft_BotShield_ScanSettings::defaults() ) );
	}

	private static function cap() { if ( ! current_user_can( 'manage_options' ) ) { wp_die( esc_html__( 'Not allowed.', 'sidcraft-bot-shield' ), 403 ); } }
	private static function back( $tab, $args = array() ) { wp_safe_redirect( add_query_arg( array_merge( array( 'page' => 'sidcraft-bot-shield', 'tab' => $tab ), $args ), admin_url( 'options-general.php' ) ) ); exit; }
	private static function box( $title, $body_cb ) { echo '<div style="background:#fff;border:1px solid #c3c4c7;border-radius:6px;padding:14px 18px;margin:14px 0"><h2 style="margin-top:0">' . esc_html( $title ) . '</h2>'; call_user_func( $body_cb ); echo '</div>'; }

	// =========================================================== Firewall tab
	public static function firewall_tab( $base ) {
		self::notice();
		$s = Sidcraft_BotShield_FwSettings::all(); $O = Sidcraft_BotShield_FwSettings::OPTION; $mode = Sidcraft_BotShield_FwSettings::effective_mode();
		$labels = array( 'disabled' => __( 'Disabled', 'sidcraft-bot-shield' ), 'learning' => __( 'Learning mode', 'sidcraft-bot-shield' ), 'enabled' => __( 'Enabled and protecting', 'sidcraft-bot-shield' ) );
		$col = array( 'disabled' => '#b32d2e', 'learning' => '#996800', 'enabled' => '#007a5a' );
		echo '<p>' . esc_html__( 'The firewall looks at every request before WordPress answers it, and stops SQL injection, cross-site scripting, file inclusion, code execution and malicious uploads. It also protects logins and limits fast crawlers.', 'sidcraft-bot-shield' ) . '</p>';
		echo '<p><strong>' . esc_html__( 'Firewall status:', 'sidcraft-bot-shield' ) . '</strong> <span style="color:' . esc_attr( $col[ $mode ] ) . ';font-weight:600">' . esc_html( $labels[ $mode ] ) . '</span>';
		if ( 'learning' === $mode && $s['waf_since'] ) { $left = max( 0, (int) $s['waf_since'] + 7 * DAY_IN_SECONDS - time() ); echo ' — ' . esc_html( sprintf( /* translators: %s: time */ __( 'turns on by itself in %s. Until then it only records what it would block and learns from what administrators do.', 'sidcraft-bot-shield' ), human_time_diff( time(), time() + $left ) ) ); }
		echo '</p>';
		self::box( __( 'Never block these addresses', 'sidcraft-bot-shield' ), function () {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">'; wp_nonce_field( 'sidcraft_botshield_allow' ); echo '<input type="hidden" name="action" value="sidcraft_botshield_allow">';
			echo Sidcraft_BotShield_Admin::allow_fields( Sidcraft_BotShield_Settings::get( 'ip_allow' ), 'ip_allow', 'sbs-ipallow-fw' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped inside.
			echo '<p><button class="button button-primary">' . esc_html__( 'Save list', 'sidcraft-bot-shield' ) . '</button></p></form>';
		} );
		echo '<form method="post" action="options.php">'; settings_fields( 'sidcraft_botshield_fw_group' );
		echo '<input type="hidden" name="' . esc_attr( $O ) . '[waf_rules_present]" value="1">';
		self::box( __( 'Web application firewall', 'sidcraft-bot-shield' ), function () use ( $s, $O ) {
			foreach ( array( 'enabled' => __( 'Enabled and protecting: block attacks', 'sidcraft-bot-shield' ), 'learning' => __( 'Learning mode: only record for 7 days, then switch on (recommended for a new install)', 'sidcraft-bot-shield' ), 'disabled' => __( 'Disabled', 'sidcraft-bot-shield' ) ) as $v => $l ) { echo '<p style="margin:4px 0"><label><input type="radio" name="' . esc_attr( $O ) . '[waf_mode]" value="' . esc_attr( $v ) . '" ' . checked( $s['waf_mode'], $v, false ) . '> ' . esc_html( $l ) . '</label></p>'; }
			echo '<h4>' . esc_html__( 'Rules', 'sidcraft-bot-shield' ) . '</h4>';
			$cats = Sidcraft_BotShield_Waf::categories();
			foreach ( $cats as $ck => $cl ) {
				echo '<p style="margin:10px 0 2px"><strong>' . esc_html( $cl ) . '</strong></p>';
				foreach ( Sidcraft_BotShield_Waf::rules() as $id => $r ) { if ( $r[0] !== $ck ) { continue; } echo '<label style="display:block;margin-left:12px"><input type="checkbox" name="' . esc_attr( $O ) . '[waf_rules][' . esc_attr( $id ) . ']" value="1" ' . checked( ! in_array( $id, $s['waf_disabled'], true ), true, false ) . '> ' . esc_html( $r[1] ) . '</label>'; }
			}
			echo '<h4>' . esc_html__( 'Allowed parameters', 'sidcraft-bot-shield' ) . '</h4><textarea name="' . esc_attr( $O ) . '[waf_allow]" rows="5" cols="60" placeholder="/contact/ message&#10;/shop/ note xss_script">' . esc_textarea( $s['waf_allow'] ) . '</textarea><br><span class="description">' . esc_html__( 'One per line: page address, field name, and optionally a rule id. Use * for any page. These requests are not checked. Learning mode adds lines here by itself when an administrator sends something the firewall would have blocked. Administrators are never blocked.', 'sidcraft-bot-shield' ) . '</span>';
			echo '<p><label><input type="checkbox" name="' . esc_attr( $O ) . '[waf_ban]" value="1" ' . checked( ! empty( $s['waf_ban'] ), true, false ) . '> ' . esc_html__( 'Ban an address that is blocked 5 times in 10 minutes', 'sidcraft-bot-shield' ) . '</label></p>';
		} );
		self::box( __( 'Login security (brute force protection)', 'sidcraft-bot-shield' ), function () use ( $s, $O ) {
			echo '<p><label><input type="checkbox" name="' . esc_attr( $O ) . '[bf_on]" value="1" ' . checked( ! empty( $s['bf_on'] ), true, false ) . '> ' . esc_html__( 'Lock out addresses that guess passwords', 'sidcraft-bot-shield' ) . '</label></p>';
			echo '<p>' . esc_html__( 'Lock out after', 'sidcraft-bot-shield' ) . ' <input type="number" class="small-text" min="2" max="500" name="' . esc_attr( $O ) . '[bf_max_login]" value="' . (int) $s['bf_max_login'] . '"> ' . esc_html__( 'failed logins, or after', 'sidcraft-bot-shield' ) . ' <input type="number" class="small-text" min="2" max="500" name="' . esc_attr( $O ) . '[bf_max_reset]" value="' . (int) $s['bf_max_reset'] . '"> ' . esc_html__( 'password reset requests, counted over', 'sidcraft-bot-shield' ) . ' <input type="number" class="small-text" min="5" max="1440" name="' . esc_attr( $O ) . '[bf_window_min]" value="' . (int) $s['bf_window_min'] . '"> ' . esc_html__( 'minutes. Lock out for', 'sidcraft-bot-shield' ) . ' <input type="number" class="small-text" min="1" max="720" name="' . esc_attr( $O ) . '[bf_lock_hours]" value="' . (int) $s['bf_lock_hours'] . '"> ' . esc_html__( 'hours.', 'sidcraft-bot-shield' ) . '</p>';
			self::limit_row( $O, 'user', $s, __( 'Block an address that logs in with user names that do not exist', 'sidcraft-bot-shield' ), __( 'user names that do not exist', 'sidcraft-bot-shield' ), __( 'Bots guess names such as admin, test or your site name. A real user who mistypes once or twice is fine; set the number to suit you.', 'sidcraft-bot-shield' ) );
			self::limit_row( $O, 'probe', $s, __( 'Block an address that keeps opening the login, dashboard or register pages without logging in', 'sidcraft-bot-shield' ), __( 'page visits (/wp-login.php, /wp-admin, /wp-register.php, /register)', 'sidcraft-bot-shield' ), __( 'A normal login does not count, only repeated visits to these pages. /register counts only if your site has no such page. If you use a custom login address, the option in the Login tab already counts /wp-login.php, /wp-admin and /wp-register.php, so only /register is counted here. Addresses on your never-block list are never blocked.', 'sidcraft-bot-shield' ) );
			echo '<label><input type="checkbox" name="' . esc_attr( $O ) . '[bf_generic]" value="1" ' . checked( ! empty( $s['bf_generic'] ), true, false ) . '> ' . esc_html__( 'Do not reveal whether the user name or the password was wrong', 'sidcraft-bot-shield' ) . '</label></p>';
			echo '<p>' . esc_html__( 'Strong passwords:', 'sidcraft-bot-shield' ) . ' <select name="' . esc_attr( $O ) . '[strong_pw]"><option value="off" ' . selected( $s['strong_pw'], 'off', false ) . '>' . esc_html__( 'not required', 'sidcraft-bot-shield' ) . '</option><option value="admins" ' . selected( $s['strong_pw'], 'admins', false ) . '>' . esc_html__( 'required for administrators and editors', 'sidcraft-bot-shield' ) . '</option><option value="all" ' . selected( $s['strong_pw'], 'all', false ) . '>' . esc_html__( 'required for everyone', 'sidcraft-bot-shield' ) . '</option></select> <span class="description">' . esc_html__( '12+ characters, mixed, not common, not your user name.', 'sidcraft-bot-shield' ) . '</span></p>';
			echo '<p><label><input type="checkbox" name="' . esc_attr( $O ) . '[breached_pw]" value="1" ' . checked( ! empty( $s['breached_pw'] ), true, false ) . '> ' . esc_html__( 'Block passwords that appeared in data breaches (administrators cannot log in with one until they reset it)', 'sidcraft-bot-shield' ) . '</label><br><span class="description">' . esc_html__( 'Uses the Pwned Passwords service. Only the first 5 characters of a hashed password are sent, never the password. Off by default.', 'sidcraft-bot-shield' ) . '</span></p>';
		} );
		self::box( __( 'Block bots that search for missing pages (404)', 'sidcraft-bot-shield' ), function () use ( $s, $O ) {
			echo '<p class="description">' . esc_html__( 'Bots look for hidden pages and weak spots by asking for hundreds of addresses that do not exist. This blocks them. Search engines and logged-in users are never counted.', 'sidcraft-bot-shield' ) . '</p>';
			echo '<p><label><input type="checkbox" name="' . esc_attr( $O ) . '[nf_on]" value="1" ' . checked( ! empty( $s['nf_on'] ), true, false ) . '> ' . esc_html__( 'Turn this on', 'sidcraft-bot-shield' ) . '</label></p>';
			echo '<p>' . esc_html__( 'Block an address that asks for', 'sidcraft-bot-shield' ) . ' <input type="number" class="small-text" min="3" max="1000" name="' . esc_attr( $O ) . '[nf_count]" value="' . (int) $s['nf_count'] . '"> ' . esc_html__( 'missing pages within', 'sidcraft-bot-shield' ) . ' <input type="number" class="small-text" min="1" max="1440" name="' . esc_attr( $O ) . '[nf_minutes]" value="' . (int) $s['nf_minutes'] . '"> ' . esc_html__( 'minutes, for', 'sidcraft-bot-shield' ) . ' <input type="number" class="small-text" min="0" max="3650" name="' . esc_attr( $O ) . '[nf_days]" value="' . (int) $s['nf_days'] . '"> ' . esc_html__( 'days (0 = block for good).', 'sidcraft-bot-shield' ) . '</p>';
			echo '<p><strong>' . esc_html__( 'Do not count addresses containing', 'sidcraft-bot-shield' ) . '</strong><br><textarea name="' . esc_attr( $O ) . '[nf_exempt]" rows="4" cols="40">' . esc_textarea( $s['nf_exempt'] ) . '</textarea><br><span class="description">' . esc_html__( 'One per line. Browsers ask for icons and similar files that many sites do not have.', 'sidcraft-bot-shield' ) . '</span></p>';
		} );
		self::box( __( 'Email when someone is blocked', 'sidcraft-bot-shield' ), function () use ( $s, $O ) {
			echo '<p><select name="' . esc_attr( $O ) . '[notify_mode]"><option value="nf" ' . selected( $s['notify_mode'], 'nf', false ) . '>' . esc_html__( 'when the missing-pages rule blocks an address', 'sidcraft-bot-shield' ) . '</option><option value="all" ' . selected( $s['notify_mode'], 'all', false ) . '>' . esc_html__( 'when any automatic rule bans an address (missing pages, logins, firewall, attack probes)', 'sidcraft-bot-shield' ) . '</option><option value="off" ' . selected( $s['notify_mode'], 'off', false ) . '>' . esc_html__( 'never', 'sidcraft-bot-shield' ) . '</option></select></p>';
			echo '<p>' . esc_html__( 'Send to', 'sidcraft-bot-shield' ) . ' <input type="email" name="' . esc_attr( $O ) . '[notify_email]" value="' . esc_attr( $s['notify_email'] ) . '" placeholder="' . esc_attr( get_option( 'admin_email' ) ) . '"> &nbsp; ' . esc_html__( 'at most', 'sidcraft-bot-shield' ) . ' <input type="number" class="small-text" min="0" max="500" name="' . esc_attr( $O ) . '[notify_cap]" value="' . (int) $s['notify_cap'] . '"> ' . esc_html__( 'emails an hour (0 = no limit)', 'sidcraft-bot-shield' ) . '</p>';
			echo '<p class="description">' . esc_html__( 'The email shows the IP address, its host name (for example badperson.example.com), the reason and how long it is blocked, and has a link to unblock it.', 'sidcraft-bot-shield' ) . '</p>';
		} );
		self::box( __( 'Rate limiting', 'sidcraft-bot-shield' ), function () use ( $s, $O ) {
			echo '<p class="description">' . esc_html__( '0 means off. Search engines such as Google and Bing are never limited. The “speed limit” for all visitors is on the Settings tab.', 'sidcraft-bot-shield' ) . '</p>';
			echo '<p>' . esc_html__( 'Crawlers and scripts: no more than', 'sidcraft-bot-shield' ) . ' <input type="number" class="small-text" min="0" max="5000" name="' . esc_attr( $O ) . '[crawler_per_min]" value="' . (int) $s['crawler_per_min'] . '"> ' . esc_html__( 'page requests a minute', 'sidcraft-bot-shield' ) . '</p>';
			echo '<p>' . esc_html__( 'When the limit is passed:', 'sidcraft-bot-shield' ) . ' <select name="' . esc_attr( $O ) . '[rate_action]"><option value="throttle" ' . selected( $s['rate_action'], 'throttle', false ) . '>' . esc_html__( 'slow them down (answer “too many requests” for a minute)', 'sidcraft-bot-shield' ) . '</option><option value="block" ' . selected( $s['rate_action'], 'block', false ) . '>' . esc_html__( 'block the address (ban length from the Settings tab)', 'sidcraft-bot-shield' ) . '</option></select></p>';
		} );
		self::box( __( 'Hardening', 'sidcraft-bot-shield' ), function () use ( $s, $O ) {
			foreach ( array( 'hide_version' => __( 'Hide the WordPress version', 'sidcraft-bot-shield' ), 'enum_block' => __( 'Block user name guessing through ?author=1 (not for logged-in users)', 'sidcraft-bot-shield' ), 'rest_users' => __( 'Hide the list of users in the REST API from visitors', 'sidcraft-bot-shield' ), 'blank_post' => __( 'Block POST requests that send no browser name and no referrer (can affect some webhooks)', 'sidcraft-bot-shield' ) ) as $k => $l ) { echo '<p style="margin:4px 0"><label><input type="checkbox" name="' . esc_attr( $O ) . '[' . esc_attr( $k ) . ']" value="1" ' . checked( ! empty( $s[ $k ] ), true, false ) . '> ' . esc_html( $l ) . '</label></p>'; }
			echo '<p>XML-RPC: <select name="' . esc_attr( $O ) . '[xmlrpc]"><option value="allow" ' . selected( $s['xmlrpc'], 'allow', false ) . '>' . esc_html__( 'allowed', 'sidcraft-bot-shield' ) . '</option><option value="multicall" ' . selected( $s['xmlrpc'], 'multicall', false ) . '>' . esc_html__( 'allowed, but block the multicall trick used for password guessing', 'sidcraft-bot-shield' ) . '</option><option value="all" ' . selected( $s['xmlrpc'], 'all', false ) . '>' . esc_html__( 'switched off completely', 'sidcraft-bot-shield' ) . '</option></select></p>';
		} );
		submit_button( __( 'Save firewall options', 'sidcraft-bot-shield' ) ); echo '</form>';
		self::extended_box();
		self::bans_box();
	}

	private static function extended_box() {
		list( $on, $seen ) = Sidcraft_BotShield_Firewall::ext_status(); $err = Sidcraft_BotShield_Firewall::ext_error();
		self::box( __( 'Extended protection', 'sidcraft-bot-shield' ), function () use ( $on, $seen, $err ) {
			echo '<p>' . esc_html__( 'Normally the firewall starts together with WordPress, so a request is checked after other plugins have loaded. Extended protection runs it first, before WordPress and every plugin, which also covers attacks on other plugins’ files.', 'sidcraft-bot-shield' ) . '</p>';
			$active = $seen && time() - $seen < 15 * MINUTE_IN_SECONDS;
			if ( $active ) { $status = __( 'active', 'sidcraft-bot-shield' ); }
			elseif ( $err ) { $status = __( 'not active', 'sidcraft-bot-shield' ); }
			elseif ( $on ) { $status = __( 'set up, waiting for the first visit (some hosts need up to 5 minutes to notice)', 'sidcraft-bot-shield' ); }
			else { $status = __( 'not set up', 'sidcraft-bot-shield' ); }
			echo '<p><strong>' . esc_html__( 'Status:', 'sidcraft-bot-shield' ) . '</strong> ' . esc_html( $status ) . '</p>';
			if ( $err ) {
				echo '<div class="notice notice-error inline" style="margin:8px 0"><p><strong>' . esc_html__( 'The last attempt did not work:', 'sidcraft-bot-shield' ) . '</strong> ' . esc_html( $err['msg'] ) . '</p></div>';
				if ( ! empty( $err['manual'] ) ) {
					$m = Sidcraft_BotShield_Firewall::manual_lines();
					echo '<p>' . esc_html__( 'You can add the lines yourself. Use the first block in .user.ini (PHP-FPM, CGI, most cPanel hosts; in cPanel: MultiPHP INI Editor, or File Manager) or the second in .htaccess (Apache with mod_php, LiteSpeed). One of them is enough. The firewall start file is already prepared.', 'sidcraft-bot-shield' ) . '</p>';
					echo '<p><strong>.user.ini</strong><br><textarea readonly rows="2" style="width:100%;font-family:monospace" onclick="this.select()">' . esc_textarea( $m[0] ) . '</textarea></p>';
					echo '<p><strong>.htaccess</strong><br><textarea readonly rows="8" style="width:100%;font-family:monospace" onclick="this.select()">' . esc_textarea( $m[1] ) . '</textarea></p>';
				}
			}
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">'; wp_nonce_field( 'sidcraft_botshield_ext' ); echo '<input type="hidden" name="action" value="sidcraft_botshield_ext">';
			echo '<button class="button button-primary" name="do" value="enable">' . esc_html( $on || $err ? __( 'Try again', 'sidcraft-bot-shield' ) : __( 'Turn on extended protection', 'sidcraft-bot-shield' ) ) . '</button> ';
			if ( $on || $err ) { echo '<button class="button" name="do" value="disable">' . esc_html__( 'Turn off', 'sidcraft-bot-shield' ) . '</button>'; }
			echo '</form><p class="description">' . esc_html__( 'This adds a marked block to .htaccess and .user.ini in your WordPress folder. It works on Apache (mod_php), LiteSpeed, and PHP-FPM / FastCGI hosts, including Nginx with PHP-FPM. It is removed when you turn it off or deactivate the plugin. Take a backup of those two files first. If the site shows an error afterwards, delete the block between the “BEGIN/END Sidcraft Bot Shield Firewall” lines in both files.', 'sidcraft-bot-shield' ) . '</p>';
		} );
	}

	private static function bans_box() {
		$bans = Sidcraft_BotShield_Bans::all();
		self::box( sprintf( /* translators: %d: number */ __( 'Blocked addresses right now (%d)', 'sidcraft-bot-shield' ), count( $bans ) ), function () use ( $bans ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="margin-bottom:12px">'; wp_nonce_field( 'sidcraft_botshield_unban' ); echo '<input type="hidden" name="action" value="sidcraft_botshield_unban"><label>' . esc_html__( 'Unblock an address:', 'sidcraft-bot-shield' ) . ' <input type="text" name="ip" placeholder="203.0.113.7" style="width:180px"></label> <button class="button">' . esc_html__( 'Unblock', 'sidcraft-bot-shield' ) . '</button> <span class="description">' . esc_html__( 'Use this if a real visitor, or you, got blocked by mistake.', 'sidcraft-bot-shield' ) . '</span></form>';
			if ( ! $bans ) { echo '<p>' . esc_html__( 'No address is blocked.', 'sidcraft-bot-shield' ) . '</p>'; return; }
			echo '<table class="widefat striped"><thead><tr><th>' . esc_html__( 'Address', 'sidcraft-bot-shield' ) . '</th><th>' . esc_html__( 'Host name', 'sidcraft-bot-shield' ) . '</th><th>' . esc_html__( 'Why', 'sidcraft-bot-shield' ) . '</th><th>' . esc_html__( 'Since', 'sidcraft-bot-shield' ) . '</th><th>' . esc_html__( 'Until', 'sidcraft-bot-shield' ) . '</th><th></th></tr></thead><tbody>';
			foreach ( $bans as $ip => $b ) { $u = wp_nonce_url( admin_url( 'admin-post.php?action=sidcraft_botshield_unban&ip=' . rawurlencode( $ip ) ), 'sidcraft_botshield_unban' ); echo '<tr><td><code>' . esc_html( $ip ) . '</code></td><td>' . esc_html( $b['host'] ?? '' ) . '</td><td>' . esc_html( $b['reason'] ) . '</td><td>' . esc_html( human_time_diff( $b['since'] ) ) . ' ' . esc_html__( 'ago', 'sidcraft-bot-shield' ) . '</td><td>' . esc_html( empty( $b['until'] ) ? __( 'for good', 'sidcraft-bot-shield' ) : human_time_diff( time(), $b['until'] ) ) . '</td><td><a href="' . esc_url( $u ) . '">' . esc_html__( 'Unblock', 'sidcraft-bot-shield' ) . '</a></td></tr>'; }
			echo '</tbody></table>';
		} );
	}

	public static function ext_action() {
		self::cap(); check_admin_referer( 'sidcraft_botshield_ext' );
		$do = isset( $_POST['do'] ) ? sanitize_key( wp_unslash( $_POST['do'] ) ) : '';
		if ( 'enable' === $do ) { $err = Sidcraft_BotShield_Firewall::ext_enable(); if ( '' !== $err ) { set_transient( 'sidcraft_botshield_notice', $err, 60 ); } }
		elseif ( 'disable' === $do ) { Sidcraft_BotShield_Firewall::ext_disable(); }
		self::back( 'firewall' );
	}

	public static function unban() {
		self::cap(); check_admin_referer( 'sidcraft_botshield_unban' );
		$ip = isset( $_REQUEST['ip'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['ip'] ) ) : '';
		if ( '' !== Sidcraft_BotShield_Ranges::pack( $ip ) ) { self::lift( $ip ); set_transient( 'sidcraft_botshield_notice_ok', sprintf( /* translators: %s: IP */ __( '%s is unblocked.', 'sidcraft-bot-shield' ), $ip ), 60 ); }
		else { set_transient( 'sidcraft_botshield_notice', __( 'That is not a valid IP address.', 'sidcraft-bot-shield' ), 60 ); }
		self::back( 'firewall' );
	}

	/** Remove every kind of block for one address. */
	public static function lift( $ip ) {
		Sidcraft_BotShield_Bans::remove( $ip );
		foreach ( array( 'sbs_lf_', 'sbs_fp_', 'sbs_wafn_', 'sbs_rc_', 'sbs_nf_', 'sbs_rate_' ) as $p ) { delete_transient( $p . md5( $ip ) ); }
	}

	/** The unblock link in the email: only works for a logged-in administrator and a valid signature. */
	public static function unban_mail() {
		if ( ! is_user_logged_in() ) { auth_redirect(); }
		self::cap();
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- an emailed link: it carries an HMAC signature instead of a nonce, and an administrator must be logged in
		$ip = isset( $_GET['ip'] ) ? rawurldecode( sanitize_text_field( wp_unslash( $_GET['ip'] ) ) ) : ''; $sig = isset( $_GET['sig'] ) ? sanitize_text_field( wp_unslash( $_GET['sig'] ) ) : '';
		// phpcs:enable WordPress.Security.NonceVerification.Recommended
		if ( '' !== Sidcraft_BotShield_Ranges::pack( $ip ) && hash_equals( Sidcraft_BotShield_Notify::sign( 'unban|' . $ip ), $sig ) ) { self::lift( $ip ); set_transient( 'sidcraft_botshield_notice_ok', sprintf( /* translators: %s: IP */ __( '%s is unblocked.', 'sidcraft-bot-shield' ), $ip ), 60 ); }
		else { set_transient( 'sidcraft_botshield_notice', __( 'This unblock link is not valid.', 'sidcraft-bot-shield' ), 60 ); }
		self::back( 'firewall' );
	}


	// =========================================================== Login tab
	/** After saving: email the new login address to the admin so that it is not lost. */
	public static function login_saved( $old, $new ) {
		$old = is_array( $old ) ? $old : array(); $new = is_array( $new ) ? $new : array();
		if ( ! empty( $new['url_on'] ) && ! empty( $new['url_slug'] ) && ( empty( $old['url_on'] ) || ( $old['url_slug'] ?? '' ) !== $new['url_slug'] ) ) {
			$url = home_url( '/' . $new['url_slug'] . '/' );
			Sidcraft_BotShield_Mailer::send( get_option( 'admin_email' ), sprintf( /* translators: %s: site */ __( '[%s] Your new login address', 'sidcraft-bot-shield' ), wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) ), sprintf( /* translators: %s: URL */ __( "Your WordPress login address is now:\n%s\n\nKeep this email. The old addresses (/wp-login.php and /wp-admin) no longer work for visitors.\n\nIf you ever forget it, add this line to wp-config.php to switch the custom address off:\ndefine( 'SIDCRAFT_BOTSHIELD_LOGIN_URL_OFF', true );", 'sidcraft-bot-shield' ), $url ) );
			set_transient( 'sidcraft_botshield_notice_ok', sprintf( /* translators: %s: URL */ __( 'Your login address is now %s. Bookmark it. It was also emailed to the site administrator.', 'sidcraft-bot-shield' ), $url ), 120 );
		}
	}

	public static function login_tab( $base ) {
		self::notice();
		$s = Sidcraft_BotShield_LoginSettings::all(); $O = Sidcraft_BotShield_LoginSettings::OPTION;
		echo '<form method="post" action="options.php">'; settings_fields( 'sidcraft_botshield_login_group' );
		self::box( __( 'Two-factor login', 'sidcraft-bot-shield' ), function () use ( $s, $O ) {
			echo '<p>' . esc_html__( 'After the password, users must also prove it is them: with a code by email, a code from an authenticator app, a text message, or a passkey (fingerprint, face or security key).', 'sidcraft-bot-shield' ) . '</p>';
			echo '<p><label><input type="checkbox" name="' . esc_attr( $O ) . '[tfa_on]" value="1" ' . checked( ! empty( $s['tfa_on'] ), true, false ) . '> <strong>' . esc_html__( 'Turn on two-factor login', 'sidcraft-bot-shield' ) . '</strong></label></p>';
			echo '<p><strong>' . esc_html__( 'Allowed methods', 'sidcraft-bot-shield' ) . '</strong></p>';
			foreach ( array( 'tfa_email' => __( 'Email code', 'sidcraft-bot-shield' ), 'tfa_totp' => __( 'Authenticator app (Google Authenticator, Microsoft Authenticator, Authy, 1Password…)', 'sidcraft-bot-shield' ), 'tfa_sms' => __( 'Text message (needs a Twilio account, below)', 'sidcraft-bot-shield' ), 'tfa_passkey' => __( 'Passkey or security key', 'sidcraft-bot-shield' ) ) as $k => $l ) { echo '<label style="display:block;margin:3px 0"><input type="checkbox" name="' . esc_attr( $O ) . '[' . esc_attr( $k ) . ']" value="1" ' . checked( ! empty( $s[ $k ] ), true, false ) . '> ' . esc_html( $l ) . '</label>'; }
			echo '<p style="margin-top:12px"><strong>' . esc_html__( 'These roles must set it up', 'sidcraft-bot-shield' ) . '</strong></p>';
			foreach ( wp_roles()->get_names() as $rk => $rn ) { echo '<label style="display:inline-block;margin:0 14px 4px 0"><input type="checkbox" name="' . esc_attr( $O ) . '[tfa_roles][]" value="' . esc_attr( $rk ) . '" ' . checked( in_array( $rk, (array) $s['tfa_roles'], true ), true, false ) . '> ' . esc_html( translate_user_role( $rn ) ) . '</label>'; }
			echo '<p>' . esc_html__( 'Grace period:', 'sidcraft-bot-shield' ) . ' <input type="number" class="small-text" min="0" max="90" name="' . esc_attr( $O ) . '[tfa_grace]" value="' . (int) $s['tfa_grace'] . '"> ' . esc_html__( 'days to set it up before they are made to. Anyone can also turn it on for themselves under Users → Profile.', 'sidcraft-bot-shield' ) . '</p>';
			echo '<p class="description">' . esc_html__( 'Passkeys need a secure (https) address. Recovery codes are made on each profile. If an administrator loses every second step, another administrator can reset them on the user’s profile; or add define( \'SIDCRAFT_BOTSHIELD_DISABLE_2FA\', true ); to wp-config.php to switch two-factor login off.', 'sidcraft-bot-shield' ) . '</p>';
			echo '<h4>' . esc_html__( 'Text messages (Twilio)', 'sidcraft-bot-shield' ) . '</h4><p class="description">' . esc_html__( 'Text messages are sent through your own Twilio account, which costs a little per message. Fill in all three fields to switch them on.', 'sidcraft-bot-shield' ) . '</p>';
			echo '<p><label>' . esc_html__( 'Account SID', 'sidcraft-bot-shield' ) . ' <input type="text" name="' . esc_attr( $O ) . '[twilio_sid]" value="' . esc_attr( $s['twilio_sid'] ) . '" class="regular-text" autocomplete="off"></label></p>';
			echo '<p><label>' . esc_html__( 'Auth token', 'sidcraft-bot-shield' ) . ' <input type="password" name="' . esc_attr( $O ) . '[twilio_token]" value="" class="regular-text" autocomplete="new-password" placeholder="' . esc_attr( '' !== $s['twilio_token'] ? __( '(saved; leave empty to keep)', 'sidcraft-bot-shield' ) : '' ) . '"></label></p>';
			echo '<p><label>' . esc_html__( 'Send from number', 'sidcraft-bot-shield' ) . ' <input type="text" name="' . esc_attr( $O ) . '[twilio_from]" value="' . esc_attr( $s['twilio_from'] ) . '" placeholder="+15551234567" autocomplete="off"></label></p>';
		} );
		self::box( __( 'Email delivery for login codes and alerts', 'sidcraft-bot-shield' ), function () use ( $s, $O ) {
			echo '<span id="sbs-mail"></span>';
			$t = Sidcraft_BotShield_Mailer::last_test();
			if ( $t ) {
				echo '<div class="notice notice-' . ( $t['ok'] ? 'success' : 'error' ) . ' inline" style="margin:0 0 12px"><p><strong>' . esc_html( $t['ok'] ? sprintf( /* translators: %s: email address */ __( 'Test email handed over to the mail system for %s. Check the inbox (and spam folder).', 'sidcraft-bot-shield' ), $t['to'] ) . ( 'php' === $t['mode'] ? ' ' . __( 'With the PHP mailer this only means the web server accepted the message, not that it was delivered. Gmail and other providers often drop or hide mail that comes straight from a web server. If it does not arrive, choose “Configure an SMTP server”.', 'sidcraft-bot-shield' ) : '' ) : __( 'The test email could not be sent.', 'sidcraft-bot-shield' ) ) . '</strong>' . ( $t['error'] ? '<br>' . esc_html( $t['error'] ) : '' ) . '</p>' . ( $t['log'] ? '<details><summary>' . esc_html__( 'Server conversation', 'sidcraft-bot-shield' ) . '</summary><pre style="white-space:pre-wrap;max-height:220px;overflow:auto">' . esc_html( $t['log'] ) . '</pre></details>' : '' ) . '</div>';
			}
			$last = get_option( 'sidcraft_botshield_mail_last' );
			if ( is_array( $last ) ) { echo '<p style="background:#f6f7f7;border-left:4px solid ' . ( $last['ok'] ? '#00a32a' : '#d63638' ) . ';padding:8px 12px">' . esc_html( sprintf( /* translators: 1: time ago 2: recipient 3: subject 4: result 5: sent through */ __( 'Last email Bot Shield sent: %1$s ago, to %2$s (“%3$s”), %4$s, through %5$s.', 'sidcraft-bot-shield' ), human_time_diff( (int) $last['time'] ), $last['to'], $last['subject'], $last['ok'] ? __( 'accepted by the mail system', 'sidcraft-bot-shield' ) : __( 'FAILED', 'sidcraft-bot-shield' ) . ( $last['error'] ? ': ' . $last['error'] : '' ), $last['via'] ) ) . '</p>'; }
			echo '<p>' . esc_html__( 'Login codes are sent by email. Choose how this site sends mail. If codes never arrive, your hosting probably blocks PHP mail: use an SMTP server instead (your host’s, Gmail, Brevo, Mailgun, Amazon SES…).', 'sidcraft-bot-shield' ) . '</p>';
			echo '<p><label><strong>' . esc_html__( 'Send login codes to', 'sidcraft-bot-shield' ) . '</strong> <input type="email" name="' . esc_attr( $O ) . '[tfa_email_to]" value="' . esc_attr( $s['tfa_email_to'] ) . '" class="regular-text" placeholder="' . esc_attr( wp_get_current_user()->user_email ) . '"></label><br><span class="description">' . esc_html__( 'Leave empty to send each user’s code to the email address on their own profile. Fill it in to send every email code to this one address instead (handy when several people share one login, or a profile address is wrong).', 'sidcraft-bot-shield' ) . '</span></p>';
			echo '<p><label><input type="radio" name="' . esc_attr( $O ) . '[mail_mode]" value="php" ' . checked( 'php', $s['mail_mode'], false ) . '> <strong>' . esc_html__( 'Use PHP mailer (WordPress default)', 'sidcraft-bot-shield' ) . '</strong></label><br><label><input type="radio" name="' . esc_attr( $O ) . '[mail_mode]" value="smtp" ' . checked( 'smtp', $s['mail_mode'], false ) . '> <strong>' . esc_html__( 'Configure an SMTP server', 'sidcraft-bot-shield' ) . '</strong></label></p>';
			echo '<table class="form-table" role="presentation" style="margin-top:0">';
			$row = function ( $label, $html ) { echo '<tr><th scope="row" style="width:190px">' . esc_html( $label ) . '</th><td>' . wp_kses( $html, array( 'input' => array( 'type' => array(), 'name' => array(), 'value' => array(), 'class' => array(), 'checked' => array(), 'autocomplete' => array(), 'placeholder' => array(), 'min' => array(), 'max' => array(), 'readonly' => array(), 'disabled' => array(), 'id' => array() ), 'button' => array( 'type' => array(), 'class' => array(), 'id' => array() ), 'span' => array( 'id' => array(), 'class' => array(), 'hidden' => array() ), 'select' => array( 'name' => array() ), 'option' => array( 'value' => array(), 'selected' => array() ), 'label' => array(), 'p' => array( 'class' => array() ), 'br' => array(), 'code' => array() ) ) . '</td></tr>'; };
			$row( __( 'SMTP server', 'sidcraft-bot-shield' ), '<input type="text" name="' . esc_attr( $O ) . '[smtp_host]" value="' . esc_attr( $s['smtp_host'] ) . '" class="regular-text" placeholder="smtp.example.com" autocomplete="off">' );
			$sec = ''; foreach ( array( 'tls' => __( 'TLS / STARTTLS (port 587)', 'sidcraft-bot-shield' ), 'ssl' => __( 'SSL (port 465)', 'sidcraft-bot-shield' ), 'none' => __( 'None (port 25, not recommended)', 'sidcraft-bot-shield' ) ) as $k => $l ) { $sec .= '<option value="' . esc_attr( $k ) . '"' . selected( $s['smtp_secure'], $k, false ) . '>' . esc_html( $l ) . '</option>'; }
			$row( __( 'Encryption and port', 'sidcraft-bot-shield' ), '<select name="' . esc_attr( $O ) . '[smtp_secure]">' . $sec . '</select> <input type="number" min="1" max="65535" name="' . esc_attr( $O ) . '[smtp_port]" value="' . (int) $s['smtp_port'] . '" class="small-text">' );
			$row( __( 'Authentication', 'sidcraft-bot-shield' ), '<label><input type="checkbox" name="' . esc_attr( $O ) . '[smtp_auth]" value="1" ' . checked( ! empty( $s['smtp_auth'] ), true, false ) . '> ' . esc_html__( 'The server needs a user name and password', 'sidcraft-bot-shield' ) . '</label>' );
			$row( __( 'User name', 'sidcraft-bot-shield' ), '<input type="text" name="' . esc_attr( $O ) . '[smtp_user]" value="' . esc_attr( $s['smtp_user'] ) . '" class="regular-text" autocomplete="off">' );
			$const = defined( 'SIDCRAFT_BOTSHIELD_SMTP_PASS' ) && '' !== SIDCRAFT_BOTSHIELD_SMTP_PASS;
			if ( $const ) { $pwh = '<input type="text" value="' . esc_attr( '••••••••' ) . '" class="regular-text" readonly disabled> <span class="description">' . esc_html__( 'Set in wp-config.php (SIDCRAFT_BOTSHIELD_SMTP_PASS).', 'sidcraft-bot-shield' ) . '</span>'; }
			elseif ( '' !== $s['smtp_pass'] ) {
				$pwh = '<span id="sbs-pw-saved"><input type="text" value="' . esc_attr( '••••••••••' ) . '" class="regular-text" readonly disabled> <button type="button" class="button" id="sbs-pw-change">' . esc_html__( 'Change password', 'sidcraft-bot-shield' ) . '</button> <label><input type="checkbox" name="' . esc_attr( $O ) . '[smtp_forget]" value="1"> ' . esc_html__( 'Forget it', 'sidcraft-bot-shield' ) . '</label><br><span class="description">' . esc_html__( 'A password is saved (encrypted). It stays until you change it.', 'sidcraft-bot-shield' ) . '</span></span>'
					. '<span id="sbs-pw-new" hidden><input type="password" name="' . esc_attr( $O ) . '[smtp_pass]" value="" class="regular-text" autocomplete="new-password" disabled> <input type="hidden" name="' . esc_attr( $O ) . '[smtp_pass_change]" value="1" disabled></span>';
			} else { $pwh = '<input type="password" name="' . esc_attr( $O ) . '[smtp_pass]" value="" class="regular-text" autocomplete="new-password" readonly id="sbs-pw-first">'; }
			wp_register_script( 'sidcraft-botshield-mailpw', false, array(), SIDCRAFT_BOTSHIELD_VERSION, true ); wp_enqueue_script( 'sidcraft-botshield-mailpw' );
			wp_add_inline_script( 'sidcraft-botshield-mailpw', "(function(){var b=document.getElementById('sbs-pw-change'),f=document.getElementById('sbs-pw-first');if(b){b.addEventListener('click',function(){document.getElementById('sbs-pw-saved').hidden=true;var n=document.getElementById('sbs-pw-new');n.hidden=false;n.querySelectorAll('input').forEach(function(i){i.disabled=false;});n.querySelector('input[type=password]').focus();});}if(f){f.addEventListener('focus',function(){f.removeAttribute('readonly');});}})();" );
			$row( __( 'Password', 'sidcraft-bot-shield' ), $pwh . '<p class="description">' . esc_html__( 'Or put define( \'SIDCRAFT_BOTSHIELD_SMTP_PASS\', \'your-password\' ); in wp-config.php and keep it out of the database.', 'sidcraft-bot-shield' ) . '</p>' );
			$row( __( 'From address and name', 'sidcraft-bot-shield' ), '<input type="text" name="' . esc_attr( $O ) . '[mail_from]" value="' . esc_attr( $s['mail_from'] ) . '" class="regular-text" placeholder="no-reply@yoursite.com"> <input type="text" name="' . esc_attr( $O ) . '[mail_from_name]" value="' . esc_attr( $s['mail_from_name'] ) . '" class="regular-text" placeholder="' . esc_attr( get_bloginfo( 'name' ) ) . '"><p class="description">' . esc_html__( 'Many SMTP servers only accept a From address on their own domain. Leave empty to keep WordPress’s default.', 'sidcraft-bot-shield' ) . '</p>' );
			$row( __( 'Used for', 'sidcraft-bot-shield' ), '<label><input type="radio" name="' . esc_attr( $O ) . '[mail_scope]" value="botshield" ' . checked( 'botshield', $s['mail_scope'], false ) . '> ' . esc_html__( 'Bot Shield emails only (login codes, alerts)', 'sidcraft-bot-shield' ) . '</label><br><label><input type="radio" name="' . esc_attr( $O ) . '[mail_scope]" value="all" ' . checked( 'all', $s['mail_scope'], false ) . '> ' . esc_html__( 'Every email this site sends', 'sidcraft-bot-shield' ) . '</label>' );
			echo '</table>';
			wp_nonce_field( 'sidcraft_botshield_mail_test', 'sbs_mail_nonce' );
			echo '<p><button type="submit" class="button" name="action" value="sidcraft_botshield_mail_test" formaction="' . esc_url( admin_url( 'admin-post.php' ) ) . '" formnovalidate>' . esc_html__( 'Send a test email to me', 'sidcraft-bot-shield' ) . '</button> <span class="description">' . esc_html( sprintf( /* translators: %s: email address */ __( 'Saves the values above, then sends a test to %s.', 'sidcraft-bot-shield' ), wp_get_current_user()->user_email ) ) . '</span></p>';
		} );
		self::box( __( 'Custom login address', 'sidcraft-bot-shield' ), function () use ( $s, $O ) {
			echo '<p>' . esc_html__( 'Move the login page from /wp-admin to an address only you know. Most password-guessing bots go straight to /wp-login.php and /wp-admin, and will get a “not found” page instead.', 'sidcraft-bot-shield' ) . '</p>';
			if ( is_multisite() ) { echo '<p><strong>' . esc_html__( 'Not available on multisite.', 'sidcraft-bot-shield' ) . '</strong></p>'; return; }
			echo '<p><label><input type="checkbox" name="' . esc_attr( $O ) . '[url_on]" value="1" ' . checked( ! empty( $s['url_on'] ), true, false ) . '> <strong>' . esc_html__( 'Use a custom login address', 'sidcraft-bot-shield' ) . '</strong></label></p>';
			echo '<p>' . esc_html( trailingslashit( home_url() ) ) . ' <input type="text" name="' . esc_attr( $O ) . '[url_slug]" value="' . esc_attr( $s['url_slug'] ) . '" placeholder="mysecret" pattern="[a-zA-Z0-9][a-zA-Z0-9_\-]{2,39}" style="width:200px"> <span class="description">' . esc_html__( 'Letters, numbers, - and _. At least 3 characters.', 'sidcraft-bot-shield' ) . '</span></p>';
			echo '<p>' . esc_html__( 'Visitors who open /wp-login.php or /wp-admin:', 'sidcraft-bot-shield' ) . ' <select name="' . esc_attr( $O ) . '[url_redirect]"><option value="404" ' . selected( $s['url_redirect'], '404', false ) . '>' . esc_html__( 'see a “page not found”', 'sidcraft-bot-shield' ) . '</option><option value="home" ' . selected( $s['url_redirect'], 'home', false ) . '>' . esc_html__( 'go to the home page', 'sidcraft-bot-shield' ) . '</option><option value="custom" ' . selected( $s['url_redirect'], 'custom', false ) . '>' . esc_html__( 'go to this address:', 'sidcraft-bot-shield' ) . '</option></select> <input type="url" name="' . esc_attr( $O ) . '[url_custom]" value="' . esc_attr( $s['url_custom'] ) . '" placeholder="https://example.com/oops" style="width:260px"></p>';
			echo '<p><label><input type="checkbox" name="' . esc_attr( $O ) . '[url_block]" value="1" ' . checked( ! empty( $s['url_block'] ), true, false ) . '> ' . esc_html__( 'Block an address that opens the old login addresses', 'sidcraft-bot-shield' ) . '</label><br>' . esc_html__( 'Block after', 'sidcraft-bot-shield' ) . ' <input type="number" class="small-text" min="1" max="100" name="' . esc_attr( $O ) . '[url_attempts]" value="' . (int) $s['url_attempts'] . '"> ' . esc_html__( 'tries within', 'sidcraft-bot-shield' ) . ' <input type="number" class="small-text" min="1" max="1440" name="' . esc_attr( $O ) . '[url_minutes]" value="' . (int) $s['url_minutes'] . '"> ' . esc_html__( 'minutes, for', 'sidcraft-bot-shield' ) . ' <input type="number" class="small-text" min="0" max="3650" name="' . esc_attr( $O ) . '[url_days]" value="' . (int) $s['url_days'] . '"> ' . esc_html__( 'days (0 = block for good). Counts /wp-login.php and /wp-admin tries by visitors who are not logged in; your own addresses are never blocked.', 'sidcraft-bot-shield' ) . '</p>';
			if ( $s['url_on'] && '' !== $s['url_slug'] ) { echo '<p style="background:#edfaef;border-left:4px solid #00a32a;padding:8px 12px"><strong>' . esc_html__( 'Your login address:', 'sidcraft-bot-shield' ) . '</strong> <a href="' . esc_url( home_url( '/' . $s['url_slug'] . '/' ) ) . '">' . esc_html( home_url( '/' . $s['url_slug'] . '/' ) ) . '</a></p>'; }
			echo '<p class="description">' . esc_html__( 'Write the address down: after saving, it is also emailed to the site administrator. Logged-in users are not affected, and admin-ajax.php keeps working for the front end. If you forget the address, add define( \'SIDCRAFT_BOTSHIELD_LOGIN_URL_OFF\', true ); to wp-config.php, or rename this plugin’s folder over FTP.', 'sidcraft-bot-shield' ) . '</p>';
		} );
		submit_button( __( 'Save login options', 'sidcraft-bot-shield' ) ); echo '</form>';
	}

	// =========================================================== Scan tab
	private static function sev_style( $s ) { $c = array( 'critical' => '#b32d2e', 'high' => '#d63638', 'medium' => '#bd5b00', 'low' => '#646970' ); return 'display:inline-block;min-width:62px;text-align:center;padding:2px 8px;border-radius:10px;color:#fff;font-size:12px;background:' . ( $c[ $s ] ?? '#646970' ); }

	public static function scan_tab( $base ) {
		$st = Sidcraft_BotShield_Scanner::state(); $running = 'running' === $st['status'];
		$f = Sidcraft_BotShield_Scanner::findings();
		$view = isset( $_GET['view'] ) ? sanitize_key( wp_unslash( $_GET['view'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only.
		if ( '' !== $view && isset( $f[ $view ] ) ) { self::file_view( $f[ $view ], $base ); return; }
		self::notice();
		echo '<p>' . esc_html__( 'Looks for hacked or changed WordPress files, malware and backdoors, injected content, exposed backup files, out-of-date software and weak passwords. The scan works in short steps and keeps going in the background if you close this page.', 'sidcraft-bot-shield' ) . '</p>';
		echo '<p><a href="#sbs-quarantine">' . esc_html( sprintf( /* translators: %d: number of files */ __( 'Quarantined files (%d): restore or delete', 'sidcraft-bot-shield' ), count( Sidcraft_BotShield_Scanner::quarantined() ) ) ) . '</a></p>';
		echo '<div style="background:#fff;border:1px solid #c3c4c7;border-radius:6px;padding:14px 18px;margin:14px 0">';
		echo '<p style="margin-top:0"><button id="sbs-scan-btn" class="button button-primary button-hero" data-running="' . ( $running ? '1' : '0' ) . '">' . esc_html( $running ? __( 'Stop scan', 'sidcraft-bot-shield' ) : __( 'Start scan', 'sidcraft-bot-shield' ) ) . '</button> <span id="sbs-scan-label" style="margin-left:10px">';
		if ( $running ) { echo esc_html__( 'Scanning…', 'sidcraft-bot-shield' ); } elseif ( $st['finished'] ) { echo esc_html( sprintf( /* translators: %s: time */ __( 'Last scan finished %s ago.', 'sidcraft-bot-shield' ), human_time_diff( $st['finished'] ) ) ); } else { echo esc_html__( 'No scan yet.', 'sidcraft-bot-shield' ); }
		echo '</span></p><div style="background:#f0f0f1;border-radius:4px;height:14px;overflow:hidden;' . ( $running ? '' : 'display:none' ) . '" id="sbs-bar-wrap"><div id="sbs-bar" style="height:14px;background:#2271b1;width:' . (int) Sidcraft_BotShield_Scanner::progress( $st ) . '%;transition:width .4s"></div></div>';
		echo '<ul id="sbs-scan-log" style="margin:10px 0 0;color:#50575e;font-size:12px">'; foreach ( array_slice( $st['log'], -6 ) as $l ) { echo '<li>' . esc_html( $l[1] ) . '</li>'; } echo '</ul></div>';
		self::scan_script();
		// Summary + results.
		$counts = array( 'critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0 ); foreach ( $f as $x ) { $counts[ $x['sev'] ]++; }
		echo '<h2>' . esc_html__( 'Results', 'sidcraft-bot-shield' ) . '</h2><p>';
		foreach ( $counts as $k => $n ) { echo '<span style="' . esc_attr( self::sev_style( $k ) ) . '">' . esc_html( ucfirst( $k ) . ' ' . $n ) . '</span> '; }
		echo '</p>';
		if ( ! $f ) { echo '<p>' . esc_html( $st['finished'] ? __( 'Nothing found. Your site looks clean.', 'sidcraft-bot-shield' ) : __( 'Run a scan to see results.', 'sidcraft-bot-shield' ) ) . '</p>'; }
		else {
			uasort( $f, function ( $a, $b ) { return Sidcraft_BotShield_Scanner::SEV[ $b['sev'] ] <=> Sidcraft_BotShield_Scanner::SEV[ $a['sev'] ]; } );
			echo '<table class="widefat striped"><thead><tr><th style="width:80px">' . esc_html__( 'Severity', 'sidcraft-bot-shield' ) . '</th><th>' . esc_html__( 'Result', 'sidcraft-bot-shield' ) . '</th><th style="width:300px">' . esc_html__( 'What you can do', 'sidcraft-bot-shield' ) . '</th></tr></thead><tbody>';
			foreach ( $f as $id => $x ) {
				echo '<tr><td><span style="' . esc_attr( self::sev_style( $x['sev'] ) ) . '">' . esc_html( $x['sev'] ) . '</span></td><td><strong>' . esc_html( $x['title'] ) . '</strong>';
				if ( '' !== $x['detail'] ) { echo '<br><span class="description">' . esc_html( $x['detail'] ) . '</span>'; }
				if ( '' !== $x['rel'] && false === strpos( (string) $x['detail'], $x['rel'] ) ) { echo '<br><code style="font-size:12px;word-break:break-all">' . esc_html( $x['rel'] ) . '</code>'; }
				if ( ! empty( $x['extra']['snippet'] ) ) { echo '<br><code style="font-size:11px;word-break:break-all">' . esc_html( $x['extra']['snippet'] ) . '</code>'; }
				echo '</td><td>' . wp_kses( self::finding_links( $id, $x, $base ), array( 'a' => array( 'href' => array(), 'onclick' => array() ), 'em' => array() ) ) . '</td></tr>';
			}
			echo '</tbody></table>';
		}
		self::quarantine_box( $base );
		// Options.
		self::scan_options();
	}

	public static function notice() { $ok = get_transient( 'sidcraft_botshield_notice_ok' ); if ( $ok ) { echo '<div class="notice notice-success is-dismissible"><p>' . esc_html( $ok ) . '</p></div>'; delete_transient( 'sidcraft_botshield_notice_ok' ); } $n = get_transient( 'sidcraft_botshield_notice' ); if ( $n ) { echo '<div class="notice notice-error"><p>' . esc_html( $n ) . '</p></div>'; delete_transient( 'sidcraft_botshield_notice' ); } if ( isset( $_GET['sbs_ok'] ) ) { echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Done.', 'sidcraft-bot-shield' ) . '</p></div>'; } } // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only.

	private static function finding_links( $id, $x, $base ) {
		$act = function ( $a, $label, $confirm = '' ) use ( $id ) { $u = wp_nonce_url( admin_url( 'admin-post.php?action=sidcraft_botshield_finding&act=' . $a . '&id=' . rawurlencode( $id ) ), 'sidcraft_botshield_finding' ); return '<a href="' . esc_url( $u ) . '"' . ( '' !== $confirm ? ' onclick="return confirm(\'' . esc_js( $confirm ) . '\')"' : '' ) . '>' . esc_html( $label ) . '</a>'; };
		$out = array();
		if ( '' !== $x['rel'] && '' !== Sidcraft_BotShield_Scanner::safe_path( $x['rel'] ) ) { $out[] = '<a href="' . esc_url( add_query_arg( array( 'tab' => 'scan', 'view' => $id ), $base ) ) . '">' . esc_html__( 'View file', 'sidcraft-bot-shield' ) . '</a>'; }
		if ( ! empty( $x['extra']['repair'] ) ) { $out[] = $act( 'repair', __( 'Repair (restore the official file)', 'sidcraft-bot-shield' ), __( 'Replace this file with the official copy from WordPress.org?', 'sidcraft-bot-shield' ) ); }
		if ( in_array( $x['type'], array( 'malware', 'upload_php', 'image_php', 'config_file', 'core_unknown', 'plugin_unknown' ), true ) && '' !== $x['rel'] ) {
			if ( '' === Sidcraft_BotShield_Scanner::removal_block( $x ) ) { $out[] = $act( 'quarantine', __( 'Quarantine (can be undone)', 'sidcraft-bot-shield' ), __( 'Move this file out of the site into quarantine? You can put it back from the Quarantine list. If it is part of your theme or a plugin the site may stop working until you restore it.', 'sidcraft-bot-shield' ) ); }
			elseif ( 'malware' === $x['type'] && Sidcraft_BotShield_Scanner::is_core_path( $x['rel'] ) ) { $out[] = '<em>' . esc_html__( 'Core file: use Repair on the matching “core file was modified” result', 'sidcraft-bot-shield' ) . '</em>'; }
		}
		if ( ! empty( $x['extra']['post'] ) ) { $out[] = '<a href="' . esc_url( get_edit_post_link( (int) $x['extra']['post'], 'raw' ) ) . '">' . esc_html__( 'Edit post', 'sidcraft-bot-shield' ) . '</a>'; }
		if ( ! empty( $x['extra']['comment'] ) ) { $out[] = '<a href="' . esc_url( admin_url( 'comment.php?action=editcomment&c=' . (int) $x['extra']['comment'] ) ) . '">' . esc_html__( 'Edit comment', 'sidcraft-bot-shield' ) . '</a>'; }
		if ( ! empty( $x['extra']['link'] ) ) { $out[] = '<a href="' . esc_url( $x['extra']['link'] ) . '">' . esc_html__( 'Open', 'sidcraft-bot-shield' ) . '</a>'; }
		$out[] = $act( 'ignore', __( 'Ignore', 'sidcraft-bot-shield' ), __( 'Never show this result again?', 'sidcraft-bot-shield' ) );
		$out[] = $act( 'dismiss', __( 'Mark as fixed', 'sidcraft-bot-shield' ) );
		return implode( ' · ', $out );
	}

	private static function file_view( $x, $base ) {
		echo '<p><a href="' . esc_url( add_query_arg( 'tab', 'scan', $base ) ) . '">&larr; ' . esc_html__( 'Back to results', 'sidcraft-bot-shield' ) . '</a></p>';
		$abs = Sidcraft_BotShield_Scanner::safe_path( $x['rel'] );
		echo '<h2>' . esc_html( $x['rel'] ) . '</h2><p><strong>' . esc_html( $x['title'] ) . '</strong><br><span class="description">' . esc_html( $x['detail'] ) . '</span></p>';
		if ( '' === $abs ) { echo '<p>' . esc_html__( 'The file is not there any more.', 'sidcraft-bot-shield' ) . '</p>'; return; }
		$size = filesize( $abs ); $txt = (string) file_get_contents( $abs, false, null, 0, 400000 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$lines = preg_split( '/\R/', $txt ); $hl = (int) ( $x['extra']['line'] ?? 0 ); $from = 0; $to = count( $lines );
		if ( $to > 600 ) { $from = max( 0, $hl - 150 ); $to = min( $to, $from + 300 ); }
		echo '<p class="description">' . esc_html( sprintf( /* translators: 1: size 2: first line 3: last line */ __( 'Size %1$s. Showing lines %2$d to %3$d.', 'sidcraft-bot-shield' ), size_format( $size ), $from + 1, $to ) ) . '</p>';
		echo '<div style="background:#fff;border:1px solid #c3c4c7;overflow:auto;max-height:640px"><table style="border-collapse:collapse;font:12px/1.5 monospace;width:100%">';
		for ( $i = $from; $i < $to; $i++ ) { $on = ( $i + 1 === $hl ); echo '<tr style="' . ( $on ? 'background:#fcf0f1' : '' ) . '"><td style="text-align:right;padding:0 8px;color:#8c8f94;user-select:none;vertical-align:top;border-right:1px solid #dcdcde">' . (int) ( $i + 1 ) . '</td><td style="padding:0 8px;white-space:pre-wrap;word-break:break-all">' . esc_html( $lines[ $i ] ) . '</td></tr>'; }
		echo '</table></div>';
	}

	/** One "block after N things in M minutes for D days" row. */
	private static function limit_row( $O, $p, $s, $label, $what, $help ) {
		echo '<p><label><input type="checkbox" name="' . esc_attr( $O ) . '[' . esc_attr( $p ) . '_on]" value="1" ' . checked( ! empty( $s[ $p . '_on' ] ), true, false ) . '> <strong>' . esc_html( $label ) . '</strong></label><br>';
		$name = function ( $suffix ) use ( $O, $p ) { return esc_attr( sprintf( '%1$s[%2$s_%3$s]', $O, $p, $suffix ) ); };
		echo esc_html__( 'Block after', 'sidcraft-bot-shield' ) . ' <input type="number" class="small-text" min="1" max="100" name="' . $name( 'attempts' ) . '" value="' . (int) $s[ $p . '_attempts' ] . '"> ' . esc_html( $what ) . ' ' . esc_html__( 'within', 'sidcraft-bot-shield' ) . ' <input type="number" class="small-text" min="1" max="1440" name="' . $name( 'minutes' ) . '" value="' . (int) $s[ $p . '_minutes' ] . '"> ' . esc_html__( 'minutes, for', 'sidcraft-bot-shield' ) . ' <input type="number" class="small-text" min="0" max="3650" name="' . $name( 'days' ) . '" value="' . (int) $s[ $p . '_days' ] . '"> ' . esc_html__( 'days (0 = for good).', 'sidcraft-bot-shield' ) . '<br><span class="description">' . esc_html( $help ) . '</span></p>';
	}

	private static function quarantine_box( $base ) {
		$q = Sidcraft_BotShield_Scanner::quarantined();
		echo '<h2 id="sbs-quarantine" style="margin-top:30px">' . esc_html( sprintf( /* translators: %d: number of files */ __( 'Quarantine (%d)', 'sidcraft-bot-shield' ), count( $q ) ) ) . '</h2>';
		if ( ! $q ) { echo '<p class="description">' . esc_html__( 'No files are in quarantine. When you quarantine a flagged file it appears here, and you can restore or delete it.', 'sidcraft-bot-shield' ) . '</p>'; return; }
		echo '<p class="description">' . esc_html__( 'Files moved out of the site. They cannot run here. If the site broke after you quarantined one, restore it.', 'sidcraft-bot-shield' ) . '</p>';
		echo '<table class="widefat striped"><thead><tr><th>' . esc_html__( 'File', 'sidcraft-bot-shield' ) . '</th><th>' . esc_html__( 'When', 'sidcraft-bot-shield' ) . '</th><th>' . esc_html__( 'Why', 'sidcraft-bot-shield' ) . '</th><th></th></tr></thead><tbody>';
		foreach ( $q as $qid => $x ) {
			$u = function ( $a ) use ( $qid ) { return wp_nonce_url( admin_url( 'admin-post.php?action=sidcraft_botshield_finding&act=' . $a . '&id=' . rawurlencode( $qid ) ), 'sidcraft_botshield_finding' ); };
			echo '<tr><td><code>' . esc_html( $x['rel'] ) . '</code></td><td>' . esc_html( human_time_diff( $x['time'] ) ) . ' ' . esc_html__( 'ago', 'sidcraft-bot-shield' ) . '</td><td>' . esc_html( $x['title'] ) . '</td><td><a href="' . esc_url( $u( 'restore' ) ) . '">' . esc_html__( 'Restore', 'sidcraft-bot-shield' ) . '</a> · <a href="' . esc_url( $u( 'purge' ) ) . '" onclick="return confirm(\'' . esc_js( __( 'Delete this file for good? It cannot be undone.', 'sidcraft-bot-shield' ) ) . '\')">' . esc_html__( 'Delete for good', 'sidcraft-bot-shield' ) . '</a></td></tr>';
		}
		echo '</tbody></table>';
	}

	private static function scan_options() {
		$o = Sidcraft_BotShield_ScanSettings::all(); $N = Sidcraft_BotShield_ScanSettings::OPTION;
		echo '<h2 id="scan-options" style="margin-top:30px">' . esc_html__( 'Scan options', 'sidcraft-bot-shield' ) . '</h2><form method="post" action="options.php">'; settings_fields( 'sidcraft_botshield_scan_group' );
		echo '<div style="background:#fff;border:1px solid #c3c4c7;border-radius:6px;padding:14px 18px">';
		echo '<p><strong>' . esc_html__( 'Scan type', 'sidcraft-bot-shield' ) . '</strong></p>';
		foreach ( Sidcraft_BotShield_ScanSettings::presets() as $k => $p ) { echo '<p style="margin:3px 0"><label><input type="radio" name="' . esc_attr( $N ) . '[preset]" value="' . esc_attr( $k ) . '" ' . checked( $o['preset'], $k, false ) . '> <strong>' . esc_html( $p['label'] ) . '</strong> — ' . esc_html( $p['desc'] ) . '</label></p>'; }
		echo '<p style="margin:3px 0"><label><input type="radio" name="' . esc_attr( $N ) . '[preset]" value="custom" ' . checked( $o['preset'], 'custom', false ) . '> <strong>' . esc_html__( 'Custom: choose the checks below', 'sidcraft-bot-shield' ) . '</strong></label></p>';
		echo '<p style="margin-top:12px"><strong>' . esc_html__( 'Checks', 'sidcraft-bot-shield' ) . '</strong></p>';
		foreach ( Sidcraft_BotShield_ScanSettings::check_labels() as $k => $l ) { echo '<label style="display:block;margin:3px 0"><input type="checkbox" name="' . esc_attr( $N ) . '[checks][' . esc_attr( $k ) . ']" value="1" ' . checked( ! empty( $o['checks'][ $k ] ), true, false ) . '> ' . esc_html( $l ) . '</label>'; }
		echo '<p class="description">' . esc_html__( 'The checks are only used with “Custom”. The other types set them for you.', 'sidcraft-bot-shield' ) . '</p>';
		echo '<p style="margin-top:12px"><strong>' . esc_html__( 'Resource use', 'sidcraft-bot-shield' ) . '</strong></p>';
		echo '<p>' . esc_html__( 'Skip files larger than', 'sidcraft-bot-shield' ) . ' <input type="number" class="small-text" min="1" max="20" name="' . esc_attr( $N ) . '[max_mb]" value="' . (int) $o['max_mb'] . '"> MB. ' . esc_html__( 'Work in steps of', 'sidcraft-bot-shield' ) . ' <input type="number" class="small-text" min="4" max="30" name="' . esc_attr( $N ) . '[tick_sec]" value="' . (int) $o['tick_sec'] . '"> ' . esc_html__( 'seconds (lower it on slow, shared hosting).', 'sidcraft-bot-shield' ) . '</p>';
		echo '<p><strong>' . esc_html__( 'Do not scan these paths', 'sidcraft-bot-shield' ) . '</strong><br><textarea name="' . esc_attr( $N ) . '[skip_paths]" rows="3" cols="60" placeholder="wp-content/cache/*&#10;wp-content/plugins/my-big-plugin/*">' . esc_textarea( $o['exclude'] ) . '</textarea><br><span class="description">' . esc_html__( 'One pattern per line, relative to the WordPress folder; * matches anything.', 'sidcraft-bot-shield' ) . '</span></p>';
		echo '<p style="margin-top:12px"><strong>' . esc_html__( 'Schedule', 'sidcraft-bot-shield' ) . '</strong></p><p><select name="' . esc_attr( $N ) . '[schedule]"><option value="off" ' . selected( $o['schedule'], 'off', false ) . '>' . esc_html__( 'Only when I start it', 'sidcraft-bot-shield' ) . '</option><option value="daily" ' . selected( $o['schedule'], 'daily', false ) . '>' . esc_html__( 'Every day', 'sidcraft-bot-shield' ) . '</option><option value="weekly" ' . selected( $o['schedule'], 'weekly', false ) . '>' . esc_html__( 'Every week on', 'sidcraft-bot-shield' ) . '</option></select> <select name="' . esc_attr( $N ) . '[weekday]">';
		global $wp_locale;
		foreach ( array( 1, 2, 3, 4, 5, 6, 0 ) as $d ) { $dl = $wp_locale->get_weekday( $d ); echo '<option value="' . (int) $d . '" ' . selected( (int) $o['weekday'], $d, false ) . '>' . esc_html( $dl ) . '</option>'; }
		echo '</select> ' . esc_html__( 'at', 'sidcraft-bot-shield' ) . ' <select name="' . esc_attr( $N ) . '[hour]">'; for ( $h = 0; $h < 24; $h++ ) { echo '<option value="' . (int) $h . '" ' . selected( (int) $o['hour'], $h, false ) . '>' . esc_html( sprintf( '%02d:00', $h ) ) . '</option>'; } echo '</select> <span class="description">' . esc_html__( '(site time; uses WP-Cron, so it needs some visits to the site)', 'sidcraft-bot-shield' ) . '</span></p>';
		echo '<p style="margin-top:12px"><strong>' . esc_html__( 'Email alerts', 'sidcraft-bot-shield' ) . '</strong></p><p><label><input type="checkbox" name="' . esc_attr( $N ) . '[email_on]" value="1" ' . checked( ! empty( $o['email_on'] ), true, false ) . '> ' . esc_html__( 'Email me when a scan finds new problems of level', 'sidcraft-bot-shield' ) . '</label> <select name="' . esc_attr( $N ) . '[email_level]">';
		foreach ( array( 'critical' => __( 'critical', 'sidcraft-bot-shield' ), 'high' => __( 'high or worse', 'sidcraft-bot-shield' ), 'medium' => __( 'medium or worse', 'sidcraft-bot-shield' ), 'low' => __( 'any', 'sidcraft-bot-shield' ) ) as $k => $l ) { echo '<option value="' . esc_attr( $k ) . '" ' . selected( $o['email_level'], $k, false ) . '>' . esc_html( $l ) . '</option>'; }
		echo '</select> ' . esc_html__( 'to', 'sidcraft-bot-shield' ) . ' <input type="email" name="' . esc_attr( $N ) . '[email_to]" value="' . esc_attr( $o['email_to'] ) . '" placeholder="' . esc_attr( get_option( 'admin_email' ) ) . '"></p>';
		echo '</div>'; submit_button( __( 'Save scan options', 'sidcraft-bot-shield' ) ); echo '</form>';
	}

	private static function scan_script() {
		wp_register_script( 'sidcraft-botshield-scan', false, array(), SIDCRAFT_BOTSHIELD_VERSION, true ); wp_enqueue_script( 'sidcraft-botshield-scan' );
		$cfg = wp_json_encode( array( 'ajax' => admin_url( 'admin-ajax.php' ), 'nonce' => wp_create_nonce( 'sidcraft_botshield_scan' ), 'running' => 'running' === Sidcraft_BotShield_Scanner::state()['status'], 'stop' => __( 'Stop scan', 'sidcraft-bot-shield' ), 'start' => __( 'Start scan', 'sidcraft-bot-shield' ) ) );
		wp_add_inline_script( 'sidcraft-botshield-scan', '(function(){var C=' . $cfg . ',b=document.getElementById("sbs-scan-btn");if(!b)return;var l=document.getElementById("sbs-scan-label"),bar=document.getElementById("sbs-bar"),wrap=document.getElementById("sbs-bar-wrap"),log=document.getElementById("sbs-scan-log"),busy=false,stopped=false;' .
			'function post(op){var d=new URLSearchParams();d.set("action","sidcraft_botshield_scan");d.set("op",op);d.set("_ajax_nonce",C.nonce);return fetch(C.ajax,{method:"POST",credentials:"same-origin",body:d}).then(function(r){return r.json()});}' .
			'function show(s){if(!s||!s.data)return s;s=s.data;wrap.style.display="block";bar.style.width=s.progress+"%";l.textContent=s.label;log.innerHTML="";(s.log||[]).forEach(function(x){var li=document.createElement("li");li.textContent=x;log.appendChild(li);});return s;}' .
			'function loop(){if(stopped)return;post("tick").then(show).then(function(s){if(!s)return;if(s.status==="running"){setTimeout(loop,300);}else{location.reload();}}).catch(function(){setTimeout(loop,3000);});}' .
			'b.addEventListener("click",function(e){e.preventDefault();if(b.dataset.running==="1"){stopped=true;post("stop").then(function(){location.reload();});return;}b.disabled=true;post("start").then(show).then(function(){b.disabled=false;b.dataset.running="1";b.textContent=C.stop;stopped=false;loop();});});' .
			'if(C.running){b.dataset.running="1";loop();}})();' );
	}

	public static function ajax() {
		self::cap(); check_ajax_referer( 'sidcraft_botshield_scan' );
		$op = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		if ( 'start' === $op ) { $st = Sidcraft_BotShield_Scanner::start(); }
		elseif ( 'stop' === $op ) { $st = Sidcraft_BotShield_Scanner::stop(); }
		elseif ( 'tick' === $op ) { $st = Sidcraft_BotShield_Scanner::tick(); }
		else { $st = Sidcraft_BotShield_Scanner::state(); }
		$stage = $st['stages'][ $st['si'] ] ?? '';
		wp_send_json_success( array( 'status' => $st['status'], 'progress' => Sidcraft_BotShield_Scanner::progress( $st ), 'label' => 'running' === $st['status'] ? Sidcraft_BotShield_Scanner::stage_label( $stage ) . '…' : ( 'done' === $st['status'] ? __( 'Scan finished.', 'sidcraft-bot-shield' ) : __( 'Not running.', 'sidcraft-bot-shield' ) ), 'log' => array_map( function ( $x ) { return $x[1]; }, array_slice( $st['log'], -6 ) ) ) );
	}

	public static function finding_action() {
		self::cap(); check_admin_referer( 'sidcraft_botshield_finding' );
		$act = isset( $_GET['act'] ) ? sanitize_key( wp_unslash( $_GET['act'] ) ) : ''; $id = isset( $_GET['id'] ) ? sanitize_key( wp_unslash( $_GET['id'] ) ) : '';
		$err = '';
		if ( 'ignore' === $act ) { Sidcraft_BotShield_Scanner::ignore( $id ); }
		elseif ( 'dismiss' === $act ) { Sidcraft_BotShield_Scanner::remove_finding( $id ); }
		elseif ( 'quarantine' === $act ) { $err = Sidcraft_BotShield_Scanner::quarantine_file( $id ); }
		elseif ( 'restore' === $act ) { $err = Sidcraft_BotShield_Scanner::restore_file( $id ); }
		elseif ( 'purge' === $act ) { $err = Sidcraft_BotShield_Scanner::purge_file( $id ); }
		elseif ( 'repair' === $act ) { $err = Sidcraft_BotShield_Scanner::repair_file( $id ); }
		if ( '' !== $err ) { set_transient( 'sidcraft_botshield_notice', $err, 60 ); self::back( 'scan' ); }
		self::back( 'scan', array( 'sbs_ok' => 1 ) );
	}
}
