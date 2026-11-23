<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/** Scan options (own tab, own option). */
class Botvaguard_ScanSettings {
	const OPTION = 'sidcraft_botshield_scan_opts';

	public static function check_labels() {
		return array(
			'core'      => __( 'Compare WordPress core files with the official versions', 'botvaguard' ),
			'plugins'   => __( 'Compare plugin files with the versions on WordPress.org', 'botvaguard' ),
			'malware'   => __( 'Scan files for malware, backdoors and suspicious code', 'botvaguard' ),
			'images'    => __( 'Look inside images and other non-code files in uploads for hidden PHP', 'botvaguard' ),
			'content'   => __( 'Scan posts, pages and comments for injected scripts, hidden links and spam', 'botvaguard' ),
			'config'    => __( 'Look for exposed backup, configuration, log and information files', 'botvaguard' ),
			'updates'   => __( 'Check for out-of-date WordPress, plugins and themes', 'botvaguard' ),
			'abandoned' => __( 'Check for plugins that were abandoned or removed from WordPress.org', 'botvaguard' ),
			'users'     => __( 'Check administrators and editors for weak passwords', 'botvaguard' ),
			'system'    => __( 'Check disk space and PHP version', 'botvaguard' ),
		);
	}

	public static function presets() {
		$all = array_fill_keys( array_keys( self::check_labels() ), 1 );
		return array(
			'quick'    => array( 'label' => __( 'Quick scan', 'botvaguard' ), 'desc' => __( 'Core, plugins, exposed files, updates. A minute or two.', 'botvaguard' ), 'checks' => array( 'core' => 1, 'plugins' => 1, 'config' => 1, 'updates' => 1, 'system' => 1 ) ),
			'standard' => array( 'label' => __( 'Standard scan', 'botvaguard' ), 'desc' => __( 'Everything except the image check. Recommended.', 'botvaguard' ), 'checks' => array_diff_key( $all, array( 'images' => 1 ) ) ),
			'deep'     => array( 'label' => __( 'High sensitivity', 'botvaguard' ), 'desc' => __( 'Everything, including images, with a larger file size limit. Slower, may show more false alarms.', 'botvaguard' ), 'checks' => $all ),
		);
	}

	public static function defaults() {
		return array( 'preset' => 'standard', 'checks' => self::presets()['standard']['checks'], 'max_mb' => 2, 'tick_sec' => 12, 'skip_paths' => '', 'schedule' => 'off', 'hour' => 3, 'weekday' => 1, 'email_on' => 0, 'email_to' => '', 'email_level' => 'high' );
	}

	public static function all() {
		$o = get_option( self::OPTION, array() ); $d = self::defaults();
		if ( is_array( $o ) && ! isset( $o['skip_paths'] ) && isset( $o['exclude'] ) ) { $o['skip_paths'] = $o['exclude']; }
		$out = array_merge( $d, is_array( $o ) ? array_intersect_key( $o, $d ) : array() );
		if ( 'custom' !== $out['preset'] && isset( self::presets()[ $out['preset'] ] ) ) { $out['checks'] = self::presets()[ $out['preset'] ]['checks']; }
		return $out;
	}

	public static function get( $k ) { $a = self::all(); return $a[ $k ] ?? null; }

	public static function enabled( $check ) { $c = self::get( 'checks' ); return ! empty( $c[ $check ] ); }

	public static function sanitize( $in ) {
		$in = is_array( $in ) ? $in : array(); $o = array(); $presets = self::presets();
		$o['preset'] = ( isset( $in['preset'] ) && ( 'custom' === $in['preset'] || isset( $presets[ $in['preset'] ] ) ) ) ? $in['preset'] : 'standard';
		if ( 'custom' === $o['preset'] ) { $o['checks'] = array(); foreach ( array_keys( self::check_labels() ) as $k ) { $o['checks'][ $k ] = empty( $in['checks'][ $k ] ) ? 0 : 1; } }
		else { $o['checks'] = $presets[ $o['preset'] ]['checks']; }
		$o['max_mb']   = max( 1, min( 20, (int) ( $in['max_mb'] ?? 2 ) ) );
		if ( 'deep' === $o['preset'] ) { $o['max_mb'] = max( $o['max_mb'], 5 ); }
		$o['tick_sec'] = max( 4, min( 30, (int) ( $in['tick_sec'] ?? 12 ) ) );
		$ex = array(); foreach ( preg_split( '/\R/', (string) ( $in['skip_paths'] ?? '' ) ) as $l ) { $l = trim( sanitize_text_field( $l ) ); if ( '' !== $l && count( $ex ) < 100 ) { $ex[] = $l; } }
		$o['skip_paths']  = implode( "\n", $ex );
		$o['schedule'] = in_array( $in['schedule'] ?? '', array( 'off', 'daily', 'weekly' ), true ) ? $in['schedule'] : 'off';
		$o['hour']     = max( 0, min( 23, (int) ( $in['hour'] ?? 3 ) ) );
		$o['weekday']  = max( 0, min( 6, (int) ( $in['weekday'] ?? 1 ) ) );
		$o['email_on'] = empty( $in['email_on'] ) ? 0 : 1;
		$o['email_to'] = isset( $in['email_to'] ) && is_email( $in['email_to'] ) ? sanitize_email( $in['email_to'] ) : '';
		$o['email_level'] = in_array( $in['email_level'] ?? '', array( 'critical', 'high', 'medium', 'low' ), true ) ? $in['email_level'] : 'high';
		return $o;
	}
}
