<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/** Downloaded address lists (Tor exit nodes, VPN and hosting ranges) and the optional country database. */
class Sidcraft_BotShield_Lists {
	const STATUS = 'sidcraft_botshield_lists';
	const CRON   = 'sidcraft_botshield_update_lists';

	public static function sources() {
		$raw = 'https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/';
		return array(
			'tor'        => array( 'label' => 'Tor exit nodes', 'urls' => array( 'https://check.torproject.org/torbulkexitlist' ) ),
			'vpn'        => array( 'label' => 'VPN services', 'urls' => array( $raw . 'vpn/ipv4.txt', $raw . 'vpn/ipv6.txt' ) ),
			'datacenter' => array( 'label' => 'Hosting / data centres', 'urls' => array( $raw . 'datacenter/ipv4.txt', $raw . 'datacenter/ipv6.txt' ) ),
		);
	}

	public static function dir() {
		$u = wp_upload_dir( null, false );
		return trailingslashit( $u['basedir'] ) . 'sidcraft-bot-shield/';
	}

	public static function ensure_dir() {
		$d = self::dir();
		if ( ! is_dir( $d ) ) {
			wp_mkdir_p( $d );
			file_put_contents( $d . 'index.php', "<?php\n// Silence is golden.\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
			file_put_contents( $d . '.htaccess', "Require all denied\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		}
		return is_dir( $d ) && is_writable( $d );
	}

	public static function status() { $s = get_option( self::STATUS, array() ); return is_array( $s ) ? $s : array(); }

	/** Which list files does an IP belong to? Fails open (false) if a list was never downloaded. */
	public static function listed( $key, $ip ) {
		$p = Sidcraft_BotShield_Ranges::pack( $ip );
		if ( '' === $p ) { return false; }
		return Sidcraft_BotShield_Ranges::file_contains( self::dir() . $key . ( 4 === strlen( $p ) ? '4' : '6' ) . '.bin', $p );
	}

	/** Download the lists that the owner switched on and rebuild the binary files. */
	public static function update( $only = null ) {
		$s = Sidcraft_BotShield_Settings::all();
		$want = array( 'tor' => ! empty( $s['block_tor'] ), 'vpn' => ! empty( $s['block_vpn'] ), 'datacenter' => ! empty( $s['block_datacenter'] ) );
		$st = self::status(); $msgs = array();
		if ( ! self::ensure_dir() ) { $st['error'] = 'The folder wp-content/uploads/sidcraft-bot-shield is not writable.'; update_option( self::STATUS, $st, false ); return $st; }
		foreach ( self::sources() as $key => $src ) {
			if ( ( $only && $only !== $key ) || ( ! $only && empty( $want[ $key ] ) ) ) { continue; }
			$p4 = array(); $p6 = array(); $ok = false;
			foreach ( $src['urls'] as $url ) {
				$res = wp_safe_remote_get( $url, array( 'timeout' => 25, 'limit_response_size' => 6 * MB_IN_BYTES, 'user-agent' => 'Sidcraft-Bot-Shield/' . SIDCRAFT_BOTSHIELD_VERSION . '; ' . home_url() ) );
				if ( is_wp_error( $res ) || 200 !== (int) wp_remote_retrieve_response_code( $res ) ) { $msgs[] = $src['label'] . ': ' . ( is_wp_error( $res ) ? $res->get_error_message() : 'HTTP ' . wp_remote_retrieve_response_code( $res ) ); continue; }
				foreach ( preg_split( '/\R/', (string) wp_remote_retrieve_body( $res ) ) as $line ) {
					$line = trim( preg_replace( '/[#;].*$/', '', $line ) );
					$pr = Sidcraft_BotShield_Ranges::parse( $line );
					if ( ! $pr ) { continue; }
					if ( 4 === strlen( $pr[0] ) ) { $p4[] = $pr; } else { $p6[] = $pr; }
					$ok = true;
				}
			}
			if ( $ok ) {
				$n4 = Sidcraft_BotShield_Ranges::write( self::dir() . $key . '4.bin', $p4 );
				$n6 = Sidcraft_BotShield_Ranges::write( self::dir() . $key . '6.bin', $p6 );
				$st['lists'][ $key ] = array( 'time' => time(), 'v4' => $n4, 'v6' => $n6 );
			}
		}
		$st['error'] = implode( ' | ', $msgs );
		update_option( self::STATUS, $st, false );
		return $st;
	}

	public static function schedule() {
		$s = Sidcraft_BotShield_Settings::all();
		$need = ! empty( $s['block_tor'] ) || ! empty( $s['block_vpn'] ) || ! empty( $s['block_datacenter'] );
		$next = wp_next_scheduled( self::CRON );
		if ( $need && ! $next ) { wp_schedule_event( time() + 60, 'daily', self::CRON ); }
		if ( ! $need && $next ) { wp_clear_scheduled_hook( self::CRON ); }
	}

	// ---- Country database (user supplied .mmdb) ----
	public static function mmdb_path() { return self::dir() . 'geo.mmdb'; }
	public static function mmdb_exists() { return is_readable( self::mmdb_path() ); }

	public static function remove_all() {
		$d = self::dir();
		if ( is_dir( $d ) ) { foreach ( (array) glob( $d . '*' ) as $f ) { if ( is_file( $f ) ) { wp_delete_file( $f ); } } foreach ( array( '.htaccess' ) as $h ) { if ( is_file( $d . $h ) ) { wp_delete_file( $d . $h ); } } @rmdir( $d ); } // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.rmdir_rmdir
		delete_option( self::STATUS );
	}
}
