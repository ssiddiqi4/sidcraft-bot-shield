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
		add_action( 'update_option_' . Sidcraft_BotShield_FwSettings::OPTION, array( 'Sidcraft_BotShield_Firewall', 'ext_sync' ) );
		add_action( 'update_option_' . Sidcraft_BotShield_ScanSettings::OPTION, function () { Sidcraft_BotShield_Scanner::schedule( true ); } );
		add_action( 'add_option_' . Sidcraft_BotShield_ScanSettings::OPTION, function () { Sidcraft_BotShield_Scanner::schedule( true ); } );
	}

	public static function register() {
		register_setting( 'sidcraft_botshield_fw_group', Sidcraft_BotShield_FwSettings::OPTION, array( 'type' => 'array', 'sanitize_callback' => array( 'Sidcraft_BotShield_FwSettings', 'sanitize' ), 'default' => Sidcraft_BotShield_FwSettings::defaults() ) );
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
			echo '<p><label><input type="checkbox" name="' . esc_attr( $O ) . '[bf_invalid_lock]" value="1" ' . checked( ! empty( $s['bf_invalid_lock'] ), true, false ) . '> ' . esc_html__( 'Lock out at once when someone logs in with a user name that does not exist', 'sidcraft-bot-shield' ) . '</label><br>';
			echo '<label><input type="checkbox" name="' . esc_attr( $O ) . '[bf_generic]" value="1" ' . checked( ! empty( $s['bf_generic'] ), true, false ) . '> ' . esc_html__( 'Do not reveal whether the user name or the password was wrong', 'sidcraft-bot-shield' ) . '</label></p>';
			echo '<p>' . esc_html__( 'Strong passwords:', 'sidcraft-bot-shield' ) . ' <select name="' . esc_attr( $O ) . '[strong_pw]"><option value="off" ' . selected( $s['strong_pw'], 'off', false ) . '>' . esc_html__( 'not required', 'sidcraft-bot-shield' ) . '</option><option value="admins" ' . selected( $s['strong_pw'], 'admins', false ) . '>' . esc_html__( 'required for administrators and editors', 'sidcraft-bot-shield' ) . '</option><option value="all" ' . selected( $s['strong_pw'], 'all', false ) . '>' . esc_html__( 'required for everyone', 'sidcraft-bot-shield' ) . '</option></select> <span class="description">' . esc_html__( '12+ characters, mixed, not common, not your user name.', 'sidcraft-bot-shield' ) . '</span></p>';
			echo '<p><label><input type="checkbox" name="' . esc_attr( $O ) . '[breached_pw]" value="1" ' . checked( ! empty( $s['breached_pw'] ), true, false ) . '> ' . esc_html__( 'Block passwords that appeared in data breaches (administrators cannot log in with one until they reset it)', 'sidcraft-bot-shield' ) . '</label><br><span class="description">' . esc_html__( 'Uses the Pwned Passwords service. Only the first 5 characters of a hashed password are sent, never the password. Off by default.', 'sidcraft-bot-shield' ) . '</span></p>';
		} );
		self::box( __( 'Rate limiting', 'sidcraft-bot-shield' ), function () use ( $s, $O ) {
			echo '<p class="description">' . esc_html__( '0 means off. Search engines such as Google and Bing are never limited. The “speed limit” for all visitors is on the Settings tab.', 'sidcraft-bot-shield' ) . '</p>';
			echo '<p>' . esc_html__( 'Crawlers and scripts: no more than', 'sidcraft-bot-shield' ) . ' <input type="number" class="small-text" min="0" max="5000" name="' . esc_attr( $O ) . '[crawler_per_min]" value="' . (int) $s['crawler_per_min'] . '"> ' . esc_html__( 'page requests a minute', 'sidcraft-bot-shield' ) . '</p>';
			echo '<p>' . esc_html__( 'Missing pages (404): no more than', 'sidcraft-bot-shield' ) . ' <input type="number" class="small-text" min="0" max="5000" name="' . esc_attr( $O ) . '[r404_human]" value="' . (int) $s['r404_human'] . '"> ' . esc_html__( 'a minute for people and', 'sidcraft-bot-shield' ) . ' <input type="number" class="small-text" min="0" max="5000" name="' . esc_attr( $O ) . '[r404_crawler]" value="' . (int) $s['r404_crawler'] . '"> ' . esc_html__( 'for crawlers', 'sidcraft-bot-shield' ) . '</p>';
			echo '<p>' . esc_html__( 'When a limit is passed:', 'sidcraft-bot-shield' ) . ' <select name="' . esc_attr( $O ) . '[rate_action]"><option value="throttle" ' . selected( $s['rate_action'], 'throttle', false ) . '>' . esc_html__( 'slow them down (answer “too many requests” for a minute)', 'sidcraft-bot-shield' ) . '</option><option value="block" ' . selected( $s['rate_action'], 'block', false ) . '>' . esc_html__( 'block the address (ban length from the Settings tab)', 'sidcraft-bot-shield' ) . '</option></select></p>';
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
		list( $on, $seen ) = Sidcraft_BotShield_Firewall::ext_status();
		self::box( __( 'Extended protection', 'sidcraft-bot-shield' ), function () use ( $on, $seen ) {
			echo '<p>' . esc_html__( 'Normally the firewall starts together with WordPress, so a request is checked after other plugins have loaded. Extended protection runs it first, before WordPress and every plugin, which also covers attacks on other plugins’ files.', 'sidcraft-bot-shield' ) . '</p>';
			$active = $on && $seen && time() - $seen < 15 * MINUTE_IN_SECONDS;
			echo '<p><strong>' . esc_html__( 'Status:', 'sidcraft-bot-shield' ) . '</strong> ' . esc_html( $active ? __( 'active', 'sidcraft-bot-shield' ) : ( $on ? __( 'set up, waiting for the first visit (some hosts need up to 5 minutes to notice)', 'sidcraft-bot-shield' ) : __( 'not set up', 'sidcraft-bot-shield' ) ) ) . '</p>';
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">'; wp_nonce_field( 'sidcraft_botshield_ext' ); echo '<input type="hidden" name="action" value="sidcraft_botshield_ext">';
			echo '<button class="button button-primary" name="do" value="enable">' . esc_html( $on ? __( 'Set up again', 'sidcraft-bot-shield' ) : __( 'Turn on extended protection', 'sidcraft-bot-shield' ) ) . '</button> ';
			if ( $on ) { echo '<button class="button" name="do" value="disable">' . esc_html__( 'Turn off', 'sidcraft-bot-shield' ) . '</button>'; }
			echo '</form><p class="description">' . esc_html__( 'This adds a marked block to .htaccess and .user.ini in your WordPress folder. It works on Apache (mod_php), LiteSpeed, and PHP-FPM / FastCGI hosts, including Nginx with PHP-FPM. It is removed when you turn it off or deactivate the plugin. Take a backup of those two files first. If the site shows an error afterwards, delete the block between the “BEGIN/END Sidcraft Bot Shield Firewall” lines in both files.', 'sidcraft-bot-shield' ) . '</p>';
		} );
	}

	private static function bans_box() {
		$bans = Sidcraft_BotShield_Bans::all();
		self::box( sprintf( /* translators: %d: number */ __( 'Blocked addresses right now (%d)', 'sidcraft-bot-shield' ), count( $bans ) ), function () use ( $bans ) {
			if ( ! $bans ) { echo '<p>' . esc_html__( 'No address is locked out.', 'sidcraft-bot-shield' ) . '</p>'; return; }
			echo '<table class="widefat striped"><thead><tr><th>' . esc_html__( 'Address', 'sidcraft-bot-shield' ) . '</th><th>' . esc_html__( 'Why', 'sidcraft-bot-shield' ) . '</th><th>' . esc_html__( 'Since', 'sidcraft-bot-shield' ) . '</th><th>' . esc_html__( 'Until', 'sidcraft-bot-shield' ) . '</th><th></th></tr></thead><tbody>';
			foreach ( $bans as $ip => $b ) { $u = wp_nonce_url( admin_url( 'admin-post.php?action=sidcraft_botshield_unban&ip=' . rawurlencode( $ip ) ), 'sidcraft_botshield_unban' ); echo '<tr><td><code>' . esc_html( $ip ) . '</code></td><td>' . esc_html( $b['reason'] ) . '</td><td>' . esc_html( human_time_diff( $b['since'] ) ) . ' ' . esc_html__( 'ago', 'sidcraft-bot-shield' ) . '</td><td>' . esc_html( human_time_diff( time(), $b['until'] ) ) . '</td><td><a href="' . esc_url( $u ) . '">' . esc_html__( 'Unblock', 'sidcraft-bot-shield' ) . '</a></td></tr>'; }
			echo '</tbody></table>';
		} );
	}

	public static function ext_action() {
		self::cap(); check_admin_referer( 'sidcraft_botshield_ext' );
		$do = isset( $_POST['do'] ) ? sanitize_key( wp_unslash( $_POST['do'] ) ) : '';
		if ( 'enable' === $do ) { $err = Sidcraft_BotShield_Firewall::ext_enable(); if ( '' !== $err ) { Sidcraft_BotShield_Firewall::ext_disable(); set_transient( 'sidcraft_botshield_notice', $err, 60 ); } }
		elseif ( 'disable' === $do ) { Sidcraft_BotShield_Firewall::ext_disable(); }
		self::back( 'firewall' );
	}

	public static function unban() {
		self::cap(); check_admin_referer( 'sidcraft_botshield_unban' );
		$ip = isset( $_GET['ip'] ) ? sanitize_text_field( wp_unslash( $_GET['ip'] ) ) : '';
		if ( '' !== Sidcraft_BotShield_Ranges::pack( $ip ) ) { Sidcraft_BotShield_Bans::remove( $ip ); foreach ( array( 'sbs_lf_', 'sbs_fp_', 'sbs_wafn_', 'sbs_rc_', 'sbs_r404_', 'sbs_rate_' ) as $p ) { delete_transient( $p . md5( $ip ) ); } }
		self::back( 'firewall' );
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
				if ( ! empty( $x['extra']['snippet'] ) ) { echo '<br><code style="font-size:11px;word-break:break-all">' . esc_html( $x['extra']['snippet'] ) . '</code>'; }
				echo '</td><td>' . wp_kses( self::finding_links( $id, $x, $base ), array( 'a' => array( 'href' => array(), 'onclick' => array() ) ) ) . '</td></tr>';
			}
			echo '</tbody></table>';
		}
		// Options.
		self::scan_options();
	}

	private static function notice() { $n = get_transient( 'sidcraft_botshield_notice' ); if ( $n ) { echo '<div class="notice notice-error"><p>' . esc_html( $n ) . '</p></div>'; delete_transient( 'sidcraft_botshield_notice' ); } if ( isset( $_GET['sbs_ok'] ) ) { echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Done.', 'sidcraft-bot-shield' ) . '</p></div>'; } } // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only.

	private static function finding_links( $id, $x, $base ) {
		$act = function ( $a, $label, $confirm = '' ) use ( $id ) { $u = wp_nonce_url( admin_url( 'admin-post.php?action=sidcraft_botshield_finding&act=' . $a . '&id=' . rawurlencode( $id ) ), 'sidcraft_botshield_finding' ); return '<a href="' . esc_url( $u ) . '"' . ( '' !== $confirm ? ' onclick="return confirm(\'' . esc_js( $confirm ) . '\')"' : '' ) . '>' . esc_html( $label ) . '</a>'; };
		$out = array();
		if ( '' !== $x['rel'] && '' !== Sidcraft_BotShield_Scanner::safe_path( $x['rel'] ) ) { $out[] = '<a href="' . esc_url( add_query_arg( array( 'tab' => 'scan', 'view' => $id ), $base ) ) . '">' . esc_html__( 'View file', 'sidcraft-bot-shield' ) . '</a>'; }
		if ( ! empty( $x['extra']['repair'] ) ) { $out[] = $act( 'repair', __( 'Repair (restore the official file)', 'sidcraft-bot-shield' ), __( 'Replace this file with the official copy from WordPress.org?', 'sidcraft-bot-shield' ) ); }
		if ( in_array( $x['type'], array( 'malware', 'upload_php', 'image_php', 'config_file', 'core_unknown', 'plugin_unknown' ), true ) && '' !== $x['rel'] ) { $out[] = $act( 'delete', __( 'Delete file', 'sidcraft-bot-shield' ), __( 'Delete this file permanently? Make a backup first if you are not sure.', 'sidcraft-bot-shield' ) ); }
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
		echo '<p><strong>' . esc_html__( 'Do not scan these paths', 'sidcraft-bot-shield' ) . '</strong><br><textarea name="' . esc_attr( $N ) . '[exclude]" rows="3" cols="60" placeholder="wp-content/cache/*&#10;wp-content/plugins/my-big-plugin/*">' . esc_textarea( $o['exclude'] ) . '</textarea><br><span class="description">' . esc_html__( 'One pattern per line, relative to the WordPress folder; * matches anything.', 'sidcraft-bot-shield' ) . '</span></p>';
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
		elseif ( 'delete' === $act ) { $err = Sidcraft_BotShield_Scanner::delete_file( $id ); }
		elseif ( 'repair' === $act ) { $err = Sidcraft_BotShield_Scanner::repair_file( $id ); }
		if ( '' !== $err ) { set_transient( 'sidcraft_botshield_notice', $err, 60 ); self::back( 'scan' ); }
		self::back( 'scan', array( 'sbs_ok' => 1 ) );
	}
}
