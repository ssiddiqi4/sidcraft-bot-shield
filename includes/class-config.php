<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/** Export and import of the plugin's settings, for backup and restore or for moving to another site. */
class Botvanguard_Config {
	const FORMAT = 1;

	/** Settings groups that are saved: option name => class holding the defaults and the sanitiser. */
	private static function groups() {
		return array(
			'settings' => 'Botvanguard_Settings',
			'firewall' => 'Botvanguard_FwSettings',
			'login'    => 'Botvanguard_LoginSettings',
			'scan'     => 'Botvanguard_ScanSettings',
			'ddos'     => 'Botvanguard_Ddos',
		);
	}

	/** Keys that are secrets (API keys, tokens). They are only exported when the owner ticks the box. */
	private static function secrets() {
		return array(
			'settings' => array( 'vpn_api_key' ),
			'firewall' => array( 'ab_key' ),
			'login'    => array( 'twilio_sid', 'twilio_token', 'twilio_from' ),
		);
	}

	public static function init() {
		add_action( 'admin_post_sidcraft_botshield_export', array( __CLASS__, 'export' ) );
		add_action( 'admin_post_sidcraft_botshield_import', array( __CLASS__, 'import' ) );
	}

	private static function allowed() { return current_user_can( 'manage_options' ) && ( ! is_multisite() || is_super_admin() ); }

	/** The export as an array. */
	public static function build( $with_secrets = false ) {
		$data = array();
		foreach ( self::groups() as $g => $class ) {
			$a = $class::all();
			if ( ! $with_secrets ) { foreach ( self::secrets()[ $g ] ?? array() as $k ) { unset( $a[ $k ] ); } }
			$data[ $g ] = $a;
		}
		return array(
			'plugin'          => 'botvanguard',
			'format'          => self::FORMAT,
			'plugin_version'  => defined( 'BOTVANGUARD_VERSION' ) ? BOTVANGUARD_VERSION : '',
			'exported_gmt'    => gmdate( 'Y-m-d H:i:s' ),
			'site'            => home_url(),
			'includes_secrets' => (bool) $with_secrets,
			'settings'        => $data,
		);
	}

	/**
	 * Apply an export. Every value goes through the same checks as the settings screens. A setting that is missing from the file keeps its current value, so a file from an older or newer version, or one without keys, never erases anything.
	 *
	 * @return array{ok:bool,message:string}
	 */
	public static function apply( $json ) {
		$d = json_decode( (string) $json, true );
		if ( ! is_array( $d ) || ( $d['plugin'] ?? '' ) !== 'botvanguard' || ! isset( $d['settings'] ) || ! is_array( $d['settings'] ) ) { return array( 'ok' => false, 'message' => __( 'That file is not a BotVanguard settings export.', 'botvanguard' ) ); }
		if ( (int) ( $d['format'] ?? 0 ) > self::FORMAT ) { return array( 'ok' => false, 'message' => __( 'That file was made by a newer version of BotVanguard. Update the plugin first.', 'botvanguard' ) ); }
		$n = 0;
		foreach ( self::groups() as $g => $class ) {
			if ( empty( $d['settings'][ $g ] ) || ! is_array( $d['settings'][ $g ] ) ) { continue; }
			$cur = $class::all();
			$in  = array_merge( $cur, array_intersect_key( $d['settings'][ $g ], $cur ) );
			if ( 'firewall' === $g ) { // the screen sends the rules that are ON, so turn the file's list of rules that are OFF around.
				$off = is_array( $in['waf_disabled'] ) ? $in['waf_disabled'] : array();
				$in['waf_rules_present'] = '1'; $in['waf_rules'] = array_fill_keys( array_diff( array_keys( Botvanguard_Waf::rules() ), $off ), 1 );
			}
			$clean = $class::sanitize( $in );
			if ( is_array( $clean ) ) { update_option( $class::OPTION, $clean ); $n++; }
		}
		if ( ! $n ) { return array( 'ok' => false, 'message' => __( 'The file holds no settings.', 'botvanguard' ) ); }
		return array( 'ok' => true, 'message' => ! empty( $d['includes_secrets'] ) ? __( 'Settings restored, including API keys.', 'botvanguard' ) : __( 'Settings restored. API keys are not in the file, so the keys saved on this site were kept.', 'botvanguard' ) );
	}

	public static function export() {
		if ( ! self::allowed() ) { wp_die( esc_html__( 'Not allowed.', 'botvanguard' ), 403 ); }
		check_admin_referer( 'sidcraft_botshield_export' );
		$out = wp_json_encode( self::build( ! empty( $_POST['with_secrets'] ) ), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
		nocache_headers();
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'X-Content-Type-Options: nosniff' );
		header( 'Content-Disposition: attachment; filename="botvanguard-settings-' . gmdate( 'Ymd-His' ) . '.json"' );
		header( 'Content-Length: ' . strlen( (string) $out ) );
		echo $out; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- a JSON file download, not a page.
		exit;
	}

	public static function import() {
		if ( ! self::allowed() ) { wp_die( esc_html__( 'Not allowed.', 'botvanguard' ), 403 ); }
		check_admin_referer( 'sidcraft_botshield_import' );
		$tmp  = isset( $_FILES['config']['tmp_name'] ) ? (string) $_FILES['config']['tmp_name'] : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- a path PHP made; checked with is_uploaded_file().
		$size = isset( $_FILES['config']['size'] ) ? (int) $_FILES['config']['size'] : 0;
		$name = isset( $_FILES['config']['name'] ) ? sanitize_file_name( wp_unslash( $_FILES['config']['name'] ) ) : '';
		if ( '' === $tmp || ! is_uploaded_file( $tmp ) || $size < 2 || $size > 1048576 || 'json' !== strtolower( pathinfo( $name, PATHINFO_EXTENSION ) ) ) {
			$r = array( 'ok' => false, 'message' => __( 'Choose a .json file made by Export (up to 1 MB).', 'botvanguard' ) );
		} else {
			$r = self::apply( file_get_contents( $tmp ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- reads the file the administrator just uploaded.
		}
		set_transient( $r['ok'] ? 'sidcraft_botshield_notice_ok' : 'sidcraft_botshield_notice', $r['message'], 60 );
		wp_safe_redirect( admin_url( 'admin.php?page=botvanguard' ) );
		exit;
	}

	/** The box on the Dashboard tab. */
	public static function box() {
		echo '<h2>' . esc_html__( 'Export and import settings', 'botvanguard' ) . '</h2>';
		echo '<p class="description" style="max-width:760px">' . esc_html__( 'Save all BotVanguard settings to a file, and restore them later or on another site. The file holds your options and your never-block, block and custom bot lists. It does not hold the block log, current blocks or scan results.', 'botvanguard' ) . '</p>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="margin:8px 0 14px"><input type="hidden" name="action" value="sidcraft_botshield_export">';
		wp_nonce_field( 'sidcraft_botshield_export' );
		echo '<label><input type="checkbox" name="with_secrets" value="1"> ' . esc_html__( 'Also include API keys and tokens (AbuseIPDB, proxycheck.io, Twilio). Keep such a file private.', 'botvanguard' ) . '</label><br>';
		echo '<button type="submit" class="button button-primary" style="margin-top:6px">' . esc_html__( 'Export settings', 'botvanguard' ) . '</button></form>';
		echo '<form method="post" enctype="multipart/form-data" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="sidcraft_botshield_import">';
		wp_nonce_field( 'sidcraft_botshield_import' );
		echo '<input type="file" name="config" accept=".json,application/json"> <button type="submit" class="button" onclick="return confirm(\'' . esc_js( __( 'Replace the current settings with the ones in the file?', 'botvanguard' ) ) . '\')">' . esc_html__( 'Import settings', 'botvanguard' ) . '</button> ';
		echo '<span class="description">' . esc_html__( 'Importing replaces the settings on this site. Export first if you want to keep the current ones.', 'botvanguard' ) . '</span></form>';
	}
}
