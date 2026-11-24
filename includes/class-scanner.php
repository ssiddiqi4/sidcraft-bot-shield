<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

// phpcs:disable WordPress.WP.AlternativeFunctions, WordPress.PHP.NoSilencedErrors -- the scanner reads local files; that is its job.

/**
 * Malware and integrity scanner. Runs in short steps ("ticks") so that it never hits a time limit, and continues in
 * the background through WP-Cron if the browser is closed.
 */
class Botvanguard_Scanner {
	const STATE = 'sidcraft_botshield_scan';
	const FINDINGS = 'sidcraft_botshield_findings';
	const IGNORED = 'sidcraft_botshield_ignored';
	const HOOK_TICK = 'sidcraft_botshield_scan_tick';
	const HOOK_START = 'sidcraft_botshield_scan_start';
	const SEV = array( 'critical' => 4, 'high' => 3, 'medium' => 2, 'low' => 1 );

	public static function init() {
		add_action( self::HOOK_TICK, array( __CLASS__, 'cron_tick' ) );
		add_action( self::HOOK_START, array( __CLASS__, 'cron_start' ) );
		add_action( 'init', array( __CLASS__, 'schedule' ) );
	}

	// ---------- state ----------
	public static function state() {
		$s = get_option( self::STATE, array() );
		return is_array( $s ) ? array_merge( array( 'status' => 'idle', 'stages' => array(), 'si' => 0, 'cursor' => 0, 'sub' => '', 'frac' => 0, 'log' => array(), 'files' => 0, 'skipped' => 0, 'started' => 0, 'finished' => 0, 'updated' => 0, 'trigger' => 'manual' ), $s ) : array( 'status' => 'idle', 'stages' => array(), 'si' => 0, 'cursor' => 0, 'sub' => '', 'frac' => 0, 'log' => array(), 'files' => 0, 'skipped' => 0, 'started' => 0, 'finished' => 0, 'updated' => 0, 'trigger' => 'manual' );
	}

	private static function save( $st ) { $st['updated'] = time(); update_option( self::STATE, $st, false ); }

	private static function say( &$st, $msg ) { $st['log'][] = array( time(), $msg ); $st['log'] = array_slice( $st['log'], -60 ); }

	public static function findings() { $f = get_option( self::FINDINGS, array() ); return is_array( $f ) ? $f : array(); }
	public static function ignored() { $f = get_option( self::IGNORED, array() ); return is_array( $f ) ? $f : array(); }

	private static function add( $type, $sev, $title, $detail, $rel = '', $extra = array() ) {
		$f = self::findings(); $id = substr( md5( $type . '|' . $rel . '|' . ( $extra['sig'] ?? '' ) . '|' . ( $extra['key'] ?? '' ) ), 0, 16 );
		if ( count( $f ) >= 600 ) { return; }
		$f[ $id ] = array( 'type' => $type, 'sev' => $sev, 'title' => $title, 'detail' => $detail, 'rel' => $rel, 'extra' => $extra, 'time' => time() );
		update_option( self::FINDINGS, $f, false );
	}

	// ---------- control ----------
	public static function stages() {
		$map = array( 'enumerate' => array( 'core', 'plugins', 'malware', 'images' ), 'core' => 'core', 'plugins' => 'plugins', 'malware' => 'malware', 'content' => 'content', 'config' => 'config', 'updates' => 'updates', 'abandoned' => 'abandoned', 'users' => 'users', 'system' => 'system' );
		$out = array();
		foreach ( $map as $stage => $need ) { foreach ( (array) $need as $n ) { if ( Botvanguard_ScanSettings::enabled( $n ) ) { $out[] = $stage; break; } } }
		return $out;
	}

	public static function start( $trigger = 'manual' ) {
		$st = self::state();
		if ( 'running' === $st['status'] && time() - $st['updated'] < 300 ) { return $st; }
		$stages = self::stages();
		if ( ! $stages ) { return $st; }
		Botvanguard_Lists::ensure_dir();
		foreach ( array( 'scan-dirs.json', 'scan-files.txt', 'scan-verified.txt' ) as $f ) { if ( is_file( self::dir() . $f ) ) { wp_delete_file( self::dir() . $f ); } }
		delete_option( self::FINDINGS );
		$st = array( 'status' => 'running', 'stages' => $stages, 'si' => 0, 'cursor' => 0, 'sub' => '', 'frac' => 0, 'log' => array(), 'files' => 0, 'skipped' => 0, 'started' => time(), 'finished' => 0, 'trigger' => $trigger, 'prev' => array_keys( get_option( 'sidcraft_botshield_prev_findings', array() ) ) );
		self::say( $st, __( 'Scan started.', 'botvanguard' ) );
		self::save( $st );
		if ( ! wp_next_scheduled( self::HOOK_TICK ) ) { wp_schedule_single_event( time() + 45, self::HOOK_TICK ); }
		return $st;
	}

	public static function stop() {
		$st = self::state(); if ( 'running' === $st['status'] ) { $st['status'] = 'stopped'; self::say( $st, __( 'Scan stopped.', 'botvanguard' ) ); self::save( $st ); }
		wp_clear_scheduled_hook( self::HOOK_TICK );
		return $st;
	}

	public static function dir() { return Botvanguard_Lists::dir(); }

	public static function cron_start() { self::start( 'schedule' ); self::cron_tick(); self::schedule( true ); }

	public static function cron_tick() {
		$st = self::tick();
		if ( 'running' === $st['status'] ) { wp_schedule_single_event( time() + 20, self::HOOK_TICK ); spawn_cron(); }
	}

	public static function schedule( $force = false ) {
		$o = Botvanguard_ScanSettings::all(); $next = wp_next_scheduled( self::HOOK_START );
		if ( 'off' === $o['schedule'] ) { if ( $next ) { wp_clear_scheduled_hook( self::HOOK_START ); } return; }
		if ( $next && ! $force ) { return; }
		if ( $force && $next ) { wp_clear_scheduled_hook( self::HOOK_START ); }
		$tz = wp_timezone(); $now = new DateTime( 'now', $tz ); $t = clone $now; $t->setTime( (int) $o['hour'], 7 );
		if ( 'weekly' === $o['schedule'] ) { $diff = ( (int) $o['weekday'] - (int) $t->format( 'w' ) + 7 ) % 7; $t->modify( '+' . $diff . ' days' ); }
		if ( $t <= $now ) { $t->modify( 'weekly' === $o['schedule'] ? '+7 days' : '+1 day' ); }
		wp_schedule_single_event( $t->getTimestamp(), self::HOOK_START );
	}

	/** Do one step of work. Returns the state. */
	public static function tick() {
		$st = self::state();
		if ( 'running' !== $st['status'] ) { return $st; }
		if ( get_transient( 'sbs_scan_lock' ) ) { return $st; }
		set_transient( 'sbs_scan_lock', 1, 90 );
		if ( function_exists( 'set_time_limit' ) ) { @set_time_limit( 60 ); } // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged, WordPress.PHP.NoSilencedErrors.Discouraged -- each scan step is short and bounded by its own deadline
		$deadline = microtime( true ) + (int) Botvanguard_ScanSettings::get( 'tick_sec' );
		try {
			while ( $st['si'] < count( $st['stages'] ) ) {
				$stage = $st['stages'][ $st['si'] ];
				$done = self::run_stage( $stage, $st, $deadline );
				if ( $done ) { $st['si']++; $st['cursor'] = 0; $st['sub'] = ''; $st['frac'] = 0; }
				if ( microtime( true ) >= $deadline ) { break; }
			}
			if ( $st['si'] >= count( $st['stages'] ) ) { self::finish( $st ); }
		} catch ( \Throwable $e ) {
			self::say( $st, 'Error: ' . $e->getMessage() ); $st['status'] = 'error';
		}
		self::save( $st );
		delete_transient( 'sbs_scan_lock' );
		return $st;
	}

	public static function progress( $st ) {
		$n = max( 1, count( $st['stages'] ) );
		if ( 'done' === $st['status'] ) { return 100; }
		return (int) min( 99, round( 100 * ( $st['si'] + min( 1, max( 0, (float) $st['frac'] ) ) ) / $n ) );
	}

	public static function stage_label( $stage ) {
		$l = array( 'enumerate' => __( 'Listing files', 'botvanguard' ), 'core' => __( 'Checking WordPress core files', 'botvanguard' ), 'plugins' => __( 'Checking plugin files', 'botvanguard' ), 'malware' => __( 'Scanning files for malware', 'botvanguard' ), 'content' => __( 'Scanning posts and comments', 'botvanguard' ), 'config' => __( 'Looking for exposed files', 'botvanguard' ), 'updates' => __( 'Checking for updates', 'botvanguard' ), 'abandoned' => __( 'Checking for abandoned plugins', 'botvanguard' ), 'users' => __( 'Checking passwords', 'botvanguard' ), 'system' => __( 'Checking the server', 'botvanguard' ) );
		return $l[ $stage ] ?? $stage;
	}

	private static function run_stage( $stage, &$st, $deadline ) {
		if ( 0 === $st['cursor'] && '' === $st['sub'] ) { self::say( $st, self::stage_label( $stage ) . '…' ); }
		switch ( $stage ) {
			case 'enumerate': return self::st_enumerate( $st, $deadline );
			case 'core':      return self::st_core( $st, $deadline );
			case 'plugins':   return self::st_plugins( $st, $deadline );
			case 'malware':   return self::st_malware( $st, $deadline );
			case 'content':   return self::st_content( $st, $deadline );
			case 'config':    return self::st_config( $st, $deadline );
			case 'updates':   return self::st_updates( $st );
			case 'abandoned': return self::st_abandoned( $st, $deadline );
			case 'users':     return self::st_users( $st, $deadline );
			case 'system':    return self::st_system( $st );
		}
		return true;
	}

	private static function finish( &$st ) {
		$ign = self::ignored(); $f = self::findings(); $f = array_diff_key( $f, array_flip( $ign ) );
		update_option( self::FINDINGS, $f, false );
		$new = array_diff( array_keys( $f ), (array) ( $st['prev'] ?? array() ) );
		update_option( 'sidcraft_botshield_prev_findings', $f, false );
		$st['status'] = 'done'; $st['finished'] = time(); $st['frac'] = 0;
		self::say( $st, sprintf( /* translators: %d: number of findings */ __( 'Scan finished. %d result(s).', 'botvanguard' ), count( $f ) ) );
		foreach ( array( 'scan-dirs.json', 'scan-files.txt', 'scan-verified.txt' ) as $x ) { if ( is_file( self::dir() . $x ) ) { wp_delete_file( self::dir() . $x ); } }
		wp_clear_scheduled_hook( self::HOOK_TICK );
		self::email( $f, $new );
	}

	private static function email( $f, $new ) {
		$o = Botvanguard_ScanSettings::all(); if ( ! $o['email_on'] ) { return; }
		$min = self::SEV[ $o['email_level'] ]; $rows = array();
		foreach ( $new as $id ) { if ( isset( $f[ $id ] ) && self::SEV[ $f[ $id ]['sev'] ] >= $min ) { $rows[] = '[' . strtoupper( $f[ $id ]['sev'] ) . '] ' . $f[ $id ]['title'] . ( '' !== $f[ $id ]['rel'] ? ' (' . $f[ $id ]['rel'] . ')' : '' ); } }
		if ( ! $rows ) { return; }
		$to = '' !== $o['email_to'] ? $o['email_to'] : get_option( 'admin_email' );
		/* translators: %s: site name */
		Botvanguard_Mailer::send( $to, sprintf( __( '[%s] Sidcraft BotVanguard scan found new problems', 'botvanguard' ), wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) ), implode( "\n", array_slice( $rows, 0, 25 ) ) . ( count( $rows ) > 25 ? "\n…" : '' ) . "\n\n" . admin_url( 'admin.php?page=botvanguard&tab=scan' ) );
	}

	// ---------- helpers ----------
	private static function excluded( $rel ) {
		$own = 'wp-content/plugins/' . basename( rtrim( BOTVANGUARD_DIR, '/' ) ) . '/';
		if ( 0 === strpos( $rel, $own ) ) { return true; }
		foreach ( preg_split( '/\R/', (string) Botvanguard_ScanSettings::get( 'skip_paths' ), -1, PREG_SPLIT_NO_EMPTY ) as $p ) { if ( fnmatch( $p, $rel ) || fnmatch( $p . '*', $rel ) ) { return true; } }
		return false;
	}

	private static function rel( $abs ) { return ltrim( str_replace( '\\', '/', substr( $abs, strlen( rtrim( wp_normalize_path( ABSPATH ), '/' ) ) ) ), '/' ); }

	private static function remote_json( $url ) {
		$r = wp_safe_remote_get( $url, array( 'timeout' => 20, 'limit_response_size' => 12 * MB_IN_BYTES ) );
		if ( is_wp_error( $r ) || 200 !== (int) wp_remote_retrieve_response_code( $r ) ) { return null; }
		$j = json_decode( (string) wp_remote_retrieve_body( $r ), true ); return is_array( $j ) ? $j : null;
	}

	private static function verified_add( $rels ) { if ( $rels ) { file_put_contents( self::dir() . 'scan-verified.txt', implode( "\n", $rels ) . "\n", FILE_APPEND ); } }
	private static function verified_load() { $f = self::dir() . 'scan-verified.txt'; return is_file( $f ) ? array_flip( file( $f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES ) ) : array(); }

	// ---------- stage: list files ----------
	private static function st_enumerate( &$st, $deadline ) {
		$dirf = self::dir() . 'scan-dirs.json'; $listf = self::dir() . 'scan-files.txt';
		$root = rtrim( wp_normalize_path( ABSPATH ), '/' );
		$stack = is_file( $dirf ) ? json_decode( (string) file_get_contents( $dirf ), true ) : array( $root );
		if ( ! is_array( $stack ) ) { $stack = array( $root ); }
		$code = array( 'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'pht', 'phar', 'inc', 'js' );
		$images = Botvanguard_ScanSettings::enabled( 'images' ); $img_ext = array( 'jpg', 'jpeg', 'png', 'gif', 'ico', 'webp', 'svg', 'pdf', 'bmp', 'txt' );
		$max = (int) Botvanguard_ScanSettings::get( 'max_mb' ) * MB_IN_BYTES; $buf = '';
		$skip_dirs = array( 'node_modules', '.git', '.svn', 'botvanguard' );
		while ( $stack ) {
			$dir = array_pop( $stack ); $rel_dir = self::rel( $dir . '/x' );
			if ( false !== strpos( $dir, '/uploads/sidcraft-bot-shield' ) ) { continue; }
			$items = @scandir( $dir ); if ( ! is_array( $items ) ) { continue; }
			foreach ( $items as $it ) {
				if ( '.' === $it || '..' === $it ) { continue; }
				$abs = $dir . '/' . $it;
				if ( is_link( $abs ) ) { continue; }
				if ( is_dir( $abs ) ) { if ( ! in_array( $it, $skip_dirs, true ) || 'botvanguard' === $it && false ) { $stack[] = $abs; } continue; }
				$ext = strtolower( pathinfo( $it, PATHINFO_EXTENSION ) ); $rel = self::rel( $abs );
				$in_up = 0 === strpos( $rel, 'wp-content/uploads/' );
				$want = in_array( $ext, $code, true ) || '.htaccess' === $it || '.user.ini' === $it || ( $images && $in_up && in_array( $ext, $img_ext, true ) );
				if ( ! $want || self::excluded( $rel ) ) { continue; }
				$sz = (int) @filesize( $abs ); $buf .= $rel . "\t" . $sz . "\n"; $st['files']++;
			}
			if ( strlen( $buf ) > 60000 ) { file_put_contents( $listf, $buf, FILE_APPEND ); $buf = ''; }
			if ( microtime( true ) >= $deadline ) { break; }
		}
		if ( '' !== $buf ) { file_put_contents( $listf, $buf, FILE_APPEND ); }
		file_put_contents( $dirf, wp_json_encode( $stack ) );
		$st['frac'] = $stack ? 0.5 : 1; $st['cursor'] = 1;
		if ( ! $stack ) { self::say( $st, sprintf( /* translators: %d: number of files */ __( '%d files to check.', 'botvanguard' ), $st['files'] ) ); }
		return ! $stack;
	}

	private static function list_files() {
		$f = self::dir() . 'scan-files.txt'; $out = array();
		if ( ! is_file( $f ) ) { return $out; }
		foreach ( file( $f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES ) as $l ) { $p = explode( "\t", $l ); $out[ $p[0] ] = (int) ( $p[1] ?? 0 ); }
		return $out;
	}

	// ---------- stage: core ----------
	private static function st_core( &$st, $deadline ) {
		global $wp_version; $loc = function_exists( 'get_locale' ) ? get_locale() : 'en_US';
		$k = 'sbs_core_sums_' . md5( $wp_version . $loc ); $sums = get_transient( $k );
		if ( false === $sums ) {
			$j = self::remote_json( 'https://api.wordpress.org/core/checksums/1.0/?version=' . rawurlencode( $wp_version ) . '&locale=' . rawurlencode( $loc ) );
			if ( ! $j || empty( $j['checksums'] ) ) { $j = self::remote_json( 'https://api.wordpress.org/core/checksums/1.0/?version=' . rawurlencode( $wp_version ) . '&locale=en_US' ); }
			$sums = $j['checksums'] ?? null;
			if ( ! is_array( $sums ) || ! $sums ) { self::say( $st, __( 'Could not get the official core file list (WordPress.org not reachable, or this is a development version). Skipped.', 'botvanguard' ) ); return true; }
			set_transient( $k, $sums, 12 * HOUR_IN_SECONDS );
		}
		$keys = array_keys( $sums ); $n = count( $keys ); $root = rtrim( wp_normalize_path( ABSPATH ), '/' ); $ver = array();
		for ( $i = (int) $st['cursor']; $i < $n; $i++ ) {
			$rel = $keys[ $i ];
			if ( 0 === strpos( $rel, 'wp-content/' ) ) { continue; }
			$abs = $root . '/' . $rel;
			if ( ! is_file( $abs ) ) { if ( ! preg_match( '#^(?:readme\.html|license\.txt|wp-config-sample\.php)$#', $rel ) ) { self::add( 'core_missing', 'medium', __( 'A WordPress core file is missing', 'botvanguard' ), $rel, $rel, array( 'repair' => 'core' ) ); } }
			elseif ( md5_file( $abs ) !== $sums[ $rel ] ) { self::add( 'core_modified', 'high', __( 'WordPress core file was modified', 'botvanguard' ), sprintf( /* translators: %s: file */ __( '%1$s is different from the official WordPress %2$s file.', 'botvanguard' ), $rel, $wp_version ), $rel, array( 'repair' => 'core' ) ); }
			else { $ver[] = $rel; }
			if ( microtime( true ) >= $deadline ) { self::verified_add( $ver ); $st['cursor'] = $i + 1; $st['frac'] = $i / $n; return false; }
		}
		self::verified_add( $ver );
		foreach ( array_keys( self::list_files() ) as $rel ) {
			if ( ! preg_match( '#^(?:wp-admin/|wp-includes/|[^/]+\.php$)#', $rel ) || isset( $sums[ $rel ] ) || 'wp-config.php' === $rel ) { continue; }
			if ( ! preg_match( '/\.(?:php\d?|phtml|pht|phar)$/i', $rel ) ) { continue; }
			self::add( 'core_unknown', 'high', __( 'Unknown PHP file in a WordPress core folder', 'botvanguard' ), sprintf( /* translators: %s: file */ __( '%s is not part of WordPress. Core folders only contain files that ship with WordPress.', 'botvanguard' ), $rel ), $rel );
		}
		return true;
	}

	// ---------- stage: plugins ----------
	private static function wporg_slugs() {
		if ( ! function_exists( 'get_plugins' ) ) { require_once ABSPATH . 'wp-admin/includes/plugin.php'; }
		$t = get_site_transient( 'update_plugins' ); $out = array();
		foreach ( get_plugins() as $file => $data ) {
			$slug = dirname( $file ); if ( '.' === $slug ) { continue; }
			$e = isset( $t->response[ $file ] ) ? $t->response[ $file ] : ( isset( $t->no_update[ $file ] ) ? $t->no_update[ $file ] : null );
			if ( $e && ! empty( $e->id ) && 0 === strpos( (string) $e->id, 'w.org/' ) ) { $out[ $file ] = array( 'slug' => $slug, 'version' => $data['Version'], 'name' => $data['Name'] ); }
		}
		return $out;
	}

	private static function st_plugins( &$st, $deadline ) {
		$pl = array_values( self::wporg_slugs() ); $n = count( $pl ); $files = self::list_files();
		for ( $i = (int) $st['cursor']; $i < $n; $i++ ) {
			$p = $pl[ $i ]; $j = self::remote_json( 'https://downloads.wordpress.org/plugin-checksums/' . rawurlencode( $p['slug'] ) . '/' . rawurlencode( $p['version'] ) . '.json' );
			$base = 'wp-content/plugins/' . $p['slug'] . '/';
			if ( $j && ! empty( $j['files'] ) && is_array( $j['files'] ) ) {
				$ver = array();
				$missing = array();
				foreach ( $j['files'] as $f => $h ) {
					if ( preg_match( '#^(?:trunk|tags|branches)/#', (string) $f ) ) { continue; } // folders of the WordPress.org repository, not part of the plugin (a badly made release tag lists them).
					$rel = $base . $f; $abs = rtrim( wp_normalize_path( ABSPATH ), '/' ) . '/' . $rel; $md5 = is_array( $h['md5'] ?? null ) ? $h['md5'][0] : ( $h['md5'] ?? '' );
					if ( ! is_file( $abs ) ) { if ( preg_match( '/\.(php|js)$/', $f ) ) { $missing[] = $f; } continue; }
					if ( '' !== $md5 && md5_file( $abs ) === $md5 ) { $ver[] = $rel; }
					elseif ( ! self::excluded( $rel ) ) { self::add( 'plugin_modified', 'high', sprintf( /* translators: %s: plugin */ __( 'A file of the plugin “%s” was modified', 'botvanguard' ), $p['name'] ), sprintf( /* translators: 1: file 2: version */ __( '%1$s is different from the official version %2$s on WordPress.org.', 'botvanguard' ), $rel, $p['version'] ), $rel, array( 'repair' => 'plugin', 'slug' => $p['slug'], 'version' => $p['version'], 'file' => $f ) ); }
				}
				self::verified_add( $ver );
				if ( count( $missing ) > 5 ) { self::add( 'plugin_missing_many', 'low', sprintf( /* translators: 1: number 2: plugin */ __( '%1$d files of the plugin “%2$s” are missing', 'botvanguard' ), count( $missing ), $p['name'] ), sprintf( /* translators: %s: file names */ __( 'For example: %s. Reinstall the plugin to restore them.', 'botvanguard' ), implode( ', ', array_slice( $missing, 0, 4 ) ) ), '', array( 'key' => $p['slug'], 'link' => admin_url( 'plugins.php' ) ) ); }
				else { foreach ( $missing as $f ) { self::add( 'plugin_missing', 'low', sprintf( /* translators: %s: plugin */ __( 'A file of the plugin “%s” is missing', 'botvanguard' ), $p['name'] ), $base . $f, $base . $f, array( 'repair' => 'plugin', 'slug' => $p['slug'], 'version' => $p['version'], 'file' => $f ) ); } }
				foreach ( array_keys( $files ) as $rel ) { if ( 0 === strpos( $rel, $base ) && preg_match( '/\.(?:php\d?|phtml|pht|phar)$/i', $rel ) && ! isset( $j['files'][ substr( $rel, strlen( $base ) ) ] ) && ! self::excluded( $rel ) ) { self::add( 'plugin_unknown', 'medium', sprintf( /* translators: %s: plugin */ __( 'Unknown PHP file inside the plugin “%s”', 'botvanguard' ), $p['name'] ), sprintf( /* translators: %s: file */ __( '%s is not part of this version of the plugin.', 'botvanguard' ), $rel ), $rel ); } }
			}
			if ( microtime( true ) >= $deadline ) { $st['cursor'] = $i + 1; $st['frac'] = ( $i + 1 ) / max( 1, $n ); return false; }
		}
		return true;
	}

	/** Ask abuse.ch MalwareBazaar whether the SHA-256 fingerprint of a file is a known malware sample. Only the fingerprint is sent, never the file. Returns the malware family (or "malware"), or '' when unknown or on any problem. */
	public static function mb_lookup( $abs ) {
		$sha = hash_file( 'sha256', $abs ); if ( ! is_string( $sha ) ) { return ''; }
		$ck = 'sbs_mb_' . $sha; $c = get_transient( $ck ); if ( false !== $c ) { return is_string( $c ) && 'none' !== $c ? $c : ''; }
		$r = wp_remote_post( 'https://mb-api.abuse.ch/api/v1/', array( 'timeout' => 6, 'headers' => array( 'Auth-Key' => (string) Botvanguard_ScanSettings::get( 'mb_key' ) ), 'body' => array( 'query' => 'get_info', 'hash' => $sha ) ) );
		if ( is_wp_error( $r ) ) { update_option( 'sidcraft_botshield_mb_err', $r->get_error_message(), false ); return ''; }
		$j = json_decode( (string) wp_remote_retrieve_body( $r ), true ); $q = is_array( $j ) ? (string) ( $j['query_status'] ?? '' ) : '';
		if ( 200 !== (int) wp_remote_retrieve_response_code( $r ) || ! is_array( $j ) || ( '' === $q ) ) {
			/* translators: %d: HTTP status code */
			update_option( 'sidcraft_botshield_mb_err', sprintf( __( 'MalwareBazaar answered with code %d. Check the Auth-Key.', 'botvanguard' ), (int) wp_remote_retrieve_response_code( $r ) ), false ); return '';
		}
		if ( 'hash_not_found' === $q ) { delete_option( 'sidcraft_botshield_mb_err' ); set_transient( $ck, 'none', 7 * DAY_IN_SECONDS ); return ''; }
		$d = isset( $j['data'][0] ) && is_array( $j['data'][0] ) ? $j['data'][0] : null;
		if ( ! $d ) { update_option( 'sidcraft_botshield_mb_err', sprintf( /* translators: %s: status text from the service */ __( 'MalwareBazaar answered: %s', 'botvanguard' ), sanitize_text_field( $q ) ), false ); return ''; }
		delete_option( 'sidcraft_botshield_mb_err' );
		$fam = ! empty( $d['signature'] ) && is_string( $d['signature'] ) ? sanitize_text_field( $d['signature'] ) : 'malware';
		set_transient( $ck, $fam, 7 * DAY_IN_SECONDS );
		return $fam;
	}

	// ---------- malware signatures ----------
	public static function signatures() {
		return array(
			'eval_decode'   => array( 'critical', 'Decodes and runs hidden code (eval of base64/gzip)', '/\b(?:eval|assert)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|rawurldecode|urldecode|convert_uudecode|hex2bin)\s*\(/i' ),
			'eval_input'    => array( 'critical', 'Runs code sent by a visitor', '/\b(?:eval|assert|create_function)\s*\(\s*(?:stripslashes\s*\(\s*)?\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b/i' ),
			'system_input'  => array( 'critical', 'Runs a command sent by a visitor', '/\b(?:system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec)\s*\(\s*(?:stripslashes\s*\(\s*)?\$_(?:GET|POST|REQUEST|COOKIE)\b/i' ),
			'include_input' => array( 'critical', 'Includes a file chosen by a visitor', '/\b(?:include|require)(?:_once)?\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE)\b/i' ),
			'callback_input'=> array( 'critical', 'Calls a function chosen by a visitor', '/\b(?:call_user_func(?:_array)?|array_map|array_filter|usort|uasort)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b|\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/i' ),
			'preg_e'        => array( 'critical', 'preg_replace with the /e modifier (runs code)', '/preg_replace\s*\(\s*([\'"])[^\'"]*\/[imsuxADSUXJ]*e[imsuxADSUXJ]*\1\s*,/i' ),
			'webshell_name' => array( 'critical', 'Known web shell', '/\b(?:c99shell|c100shell|r57shell|wso\s*shell|WSO_VERSION|FilesMan|b374k|IndoXploit|Alfa\s*Shell|p0wny|weevely|Mini\s*Shell|Priv8\s*shell|Sym403|AnonymousFox)\b/i' ),
			'upload_dropper'=> array( 'high', 'Lets a visitor upload a file to any place', '/move_uploaded_file\s*\(\s*\$_FILES\s*\[[^\]]+\]\s*\[\s*[\'"]tmp_name[\'"]\s*\]\s*,\s*\$_(?:GET|POST|REQUEST|COOKIE)/i' ),
			'write_input'   => array( 'high', 'Writes a file from visitor data', '/\bfile_put_contents\s*\([^;]{0,120}\$_(?:GET|POST|REQUEST|COOKIE)\b/i' ),
			'hex_blob'      => array( 'high', 'Long hidden (hex-escaped) string', '/(?:\\\\x[0-9a-f]{2}){24,}/i' ),
			'chr_chain'     => array( 'high', 'Code hidden with chr() calls', '/(?:chr\s*\(\s*\d+\s*\)\s*\.\s*){10,}/i' ),
			'var_func_input'=> array( 'high', 'Variable function fed by a visitor', '/\$\w+\s*=\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*;\s*\$\w+\s*\(/i' ),
			'php_in_js'     => array( 'high', 'Hidden script writer', '/document\.write\s*\(\s*unescape\s*\(/i', 'js' ),
			'htaccess_prepend' => array( 'high', 'Runs another script before or after every PHP file', '/^[ \t]*(?:php_(?:admin_)?value[ \t]+)?auto_(?:prepend|append)_file[ \t]*[= \t][ \t]*["\']?(?![^\n]*(?:sidcraft-bot-shield|wordfence-waf\.php))[^\s"\';=]+/im', 'ht' ),
			'htaccess_handler' => array( 'high', 'Makes images or text files run as PHP', '/AddHandler\s+(?:application\/x-httpd-php\d*|php\d*-script)\s+[^\n]*\.(?:jpe?g|png|gif|txt|ico)\b|SetHandler\s+application\/x-httpd-php/i', 'ht' ),
			'htaccess_cloak'   => array( 'high', 'Redirects visitors who come from search engines', '/RewriteCond\s+%\{HTTP_(?:USER_AGENT|REFERER)\}[^\n]*(?:google|bing|yahoo|baidu|yandex)[^\n]*\s*\n\s*RewriteRule[^\n]*https?:\/\//i', 'ht' ),
		);
	}

	private static function scan_text( $text, $kind ) {
		$hits = array();
		foreach ( self::signatures() as $id => $s ) {
			$k = $s[3] ?? 'php'; if ( $k !== $kind ) { continue; }
			if ( @preg_match( $s[2], $text, $m, PREG_OFFSET_CAPTURE ) ) {
				$off = (int) $m[0][1]; $line = substr_count( substr( $text, 0, $off ), "\n" ) + 1;
				// A list of names separated by | (for example a bot or scanner block list in a security plugin) is not a web shell.
				if ( 'webshell_name' === $id ) { $a = strrpos( substr( $text, 0, $off ), "\n" ); $a = false === $a ? 0 : $a + 1; $e = strpos( $text, "\n", $off ); $ln = substr( $text, $a, ( false === $e ? strlen( $text ) : $e ) - $a ); if ( substr_count( $ln, '|' ) >= 3 ) { continue; } }
				$hits[] = array( $id, $s[0], $s[1], $line, substr( preg_replace( '/\s+/', ' ', $m[0][0] ), 0, 120 ) );
			}
		}
		// Heuristic: a very long base64 blob next to a decode call.
		if ( 'php' === $kind && preg_match( '/base64_decode\s*\(/i', $text ) && preg_match( '/[A-Za-z0-9+\/=]{1500,}/', $text, $m, PREG_OFFSET_CAPTURE ) && preg_match( '/\b(?:eval|assert|include|file_put_contents|preg_replace)\b/i', $text ) ) { $hits[] = array( 'b64_blob', 'high', 'Large hidden (base64) block next to a decode call', substr_count( substr( $text, 0, (int) $m[0][1] ), "\n" ) + 1, substr( $m[0][0], 0, 60 ) . '…' ); }
		return $hits;
	}

	private static function st_malware( &$st, $deadline ) {
		if ( ! Botvanguard_ScanSettings::enabled( 'malware' ) && ! Botvanguard_ScanSettings::enabled( 'images' ) ) { return true; }
		$listf = self::dir() . 'scan-files.txt'; if ( ! is_file( $listf ) ) { return true; }
		$total = max( 1, filesize( $listf ) ); $h = fopen( $listf, 'rb' ); fseek( $h, (int) $st['cursor'] );
		$verified = self::verified_load(); $root = rtrim( wp_normalize_path( ABSPATH ), '/' ); $max = (int) Botvanguard_ScanSettings::get( 'max_mb' ) * MB_IN_BYTES;
		$do_mal = Botvanguard_ScanSettings::enabled( 'malware' ); $do_img = Botvanguard_ScanSettings::enabled( 'images' );
		while ( false !== ( $line = fgets( $h ) ) ) {
			$p = explode( "\t", rtrim( $line, "\n" ) ); $rel = $p[0]; $size = (int) ( $p[1] ?? 0 ); $abs = $root . '/' . $rel;
			$ext = strtolower( pathinfo( $rel, PATHINFO_EXTENSION ) ); $base = basename( $rel );
			$is_code = in_array( $ext, array( 'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'pht', 'phar', 'inc' ), true );
			$in_up = 0 === strpos( $rel, 'wp-content/uploads/' );
			if ( ! isset( $verified[ $rel ] ) ) {
				if ( $is_code && $in_up && $size > 80 ) { self::add( 'upload_php', 'high', __( 'PHP file inside the uploads folder', 'botvanguard' ), __( 'Uploads should only hold media. A PHP file here is a common sign of a hacked site.', 'botvanguard' ), $rel ); }
				if ( $size > $max ) { $st['skipped']++; }
				elseif ( is_readable( $abs ) ) {
					$kind = $is_code ? 'php' : ( 'js' === $ext ? 'js' : ( '.htaccess' === $base || '.user.ini' === $base ? 'ht' : 'img' ) );
					if ( 'img' === $kind ) { if ( $do_img && $in_up ) { $head = (string) file_get_contents( $abs, false, null, 0, 65536 ); if ( preg_match( '/<\?php|<\?=|<script\s+language\s*=\s*[\'"]?php/i', $head, $m, PREG_OFFSET_CAPTURE ) ) { self::add( 'image_php', 'critical', __( 'A media file contains hidden PHP code', 'botvanguard' ), __( 'This file looks like an image or document but contains PHP code.', 'botvanguard' ), $rel, array( 'sig' => 'img', 'line' => substr_count( substr( $head, 0, (int) $m[0][1] ), "\n" ) + 1 ) ); } } }
					elseif ( $do_mal ) {
						$text = (string) file_get_contents( $abs, false, null, 0, $max );
						$found = self::scan_text( $text, $kind );
						if ( $found && Botvanguard_ScanSettings::get( 'mb_on' ) && '' !== (string) Botvanguard_ScanSettings::get( 'mb_key' ) && (int) ( $st['mb'] ?? 0 ) < 30 ) {
							$st['mb'] = (int) ( $st['mb'] ?? 0 ) + 1; $known = self::mb_lookup( $abs );
							if ( $known ) { self::add( 'malware', 'critical', sprintf( /* translators: %s: malware family */ __( 'Known malware (MalwareBazaar): %s', 'botvanguard' ), $known ), $rel, $rel, array( 'sig' => 'known_malware', 'line' => 0, 'snippet' => '' ) ); }
						}
						foreach ( $found as $hit ) { self::add( 'malware', $hit[1], sprintf( /* translators: %s: description */ __( 'Suspicious code: %s', 'botvanguard' ), $hit[2] ), $rel . ':' . $hit[3], $rel, array( 'sig' => $hit[0], 'line' => $hit[3], 'snippet' => $hit[4] ) ); }
					}
				}
			}
			if ( microtime( true ) >= $deadline ) { $st['cursor'] = ftell( $h ); $st['frac'] = $st['cursor'] / $total; fclose( $h ); return false; }
		}
		fclose( $h );
		return true;
	}

	// ---------- stage: content ----------
	private static function content_hits( $text, $own_host ) {
		$h = array();
		if ( preg_match( '/<iframe[^>]*(?:width|height)\s*=\s*["\']?[01]["\']?[\s>]|<iframe[^>]*style\s*=\s*["\'][^"\']*(?:display\s*:\s*none|visibility\s*:\s*hidden)/i', $text ) ) { $h[] = array( 'high', __( 'Hidden iframe', 'botvanguard' ) ); }
		if ( preg_match( '/<script[^>]*>[^<]*(?:eval\s*\(|document\.write\s*\(\s*unescape|atob\s*\()/i', $text ) ) { $h[] = array( 'high', __( 'Script that hides its code', 'botvanguard' ) ); }
		if ( preg_match_all( '/<script[^>]+src\s*=\s*["\']https?:\/\/([^\/"\']+)/i', $text, $m ) ) {
			$ok = '/(?:^|\.)(?:youtube\.com|youtube-nocookie\.com|google\.com|googletagmanager\.com|google-analytics\.com|gstatic\.com|googleapis\.com|facebook\.net|facebook\.com|twitter\.com|x\.com|cloudflare\.com|jsdelivr\.net|unpkg\.com|cdnjs\.com|jquery\.com|paypal\.com|stripe\.com|vimeo\.com|instagram\.com|tiktok\.com|calendly\.com|hsforms\.net|hubspot\.com|mailchimp\.com|wp\.com|wordpress\.com|linkedin\.com|pinterest\.com|typeform\.com|trustpilot\.com|' . preg_quote( $own_host, '/' ) . ')$/i';
			foreach ( $m[1] as $host ) { if ( ! preg_match( $ok, $host ) ) { $h[] = array( 'medium', sprintf( /* translators: %s: host */ __( 'Loads a script from %s', 'botvanguard' ), $host ) ); break; } }
		}
		if ( preg_match( '/<(?:div|span|p)[^>]*style\s*=\s*["\'][^"\']*(?:display\s*:\s*none|visibility\s*:\s*hidden|left\s*:\s*-\d{3,}px)[^"\']*["\'][^>]*>(?:(?!<\/(?:div|span|p)>).){0,500}<a\s[^>]*href\s*=\s*["\']https?:\/\//is', $text ) ) { $h[] = array( 'medium', __( 'Hidden links', 'botvanguard' ) ); }
		if ( preg_match_all( '/<a\s[^>]*href\s*=/i', $text ) >= 2 && preg_match( '/\b(?:viagra|cialis|levitra|payday\s+loans?|online\s+casino|casino\s+online|replica\s+watches|essay\s+writing\s+service|buy\s+cheap\s+\w+\s+online)\b/i', $text ) ) { $h[] = array( 'medium', __( 'Spam links', 'botvanguard' ) ); }
		return $h;
	}

	private static function st_content( &$st, $deadline ) {
		$host = (string) wp_parse_url( home_url(), PHP_URL_HOST ); $per = 40;
		if ( '' === $st['sub'] ) { $st['sub'] = 'posts'; $st['cursor'] = 0; }
		if ( 'posts' === $st['sub'] ) {
			do {
				$ids = get_posts( array( 'post_type' => 'any', 'post_status' => array( 'publish', 'private', 'draft', 'pending', 'future' ), 'posts_per_page' => $per, 'offset' => (int) $st['cursor'], 'orderby' => 'ID', 'order' => 'ASC', 'no_found_rows' => true ) );
				foreach ( $ids as $p ) {
					foreach ( self::content_hits( (string) $p->post_content, $host ) as $hit ) { self::add( 'content', $hit[0], sprintf( /* translators: %s: problem */ __( 'Suspicious content: %s', 'botvanguard' ), $hit[1] ), sprintf( /* translators: 1: title 2: type */ __( '“%1$s” (%2$s)', 'botvanguard' ), $p->post_title, $p->post_type ), '', array( 'post' => $p->ID, 'key' => $hit[1] ) ); }
				}
				$st['cursor'] += $per;
				if ( count( $ids ) < $per ) { $st['sub'] = 'comments'; $st['cursor'] = 0; break; }
				if ( microtime( true ) >= $deadline ) { return false; }
			} while ( true );
		}
		if ( 'comments' === $st['sub'] ) {
			do {
				$cs = get_comments( array( 'status' => 'all', 'number' => 100, 'offset' => (int) $st['cursor'], 'orderby' => 'comment_ID', 'order' => 'ASC' ) );
				foreach ( $cs as $c ) { foreach ( self::content_hits( (string) $c->comment_content, $host ) as $hit ) { self::add( 'comment', $hit[0], sprintf( /* translators: %s: problem */ __( 'Suspicious comment: %s', 'botvanguard' ), $hit[1] ), sprintf( /* translators: %s: author */ __( 'Comment by %s', 'botvanguard' ), $c->comment_author ), '', array( 'comment' => $c->comment_ID, 'key' => $hit[1] ) ); } }
				$st['cursor'] += 100;
				if ( count( $cs ) < 100 ) { return true; }
				if ( microtime( true ) >= $deadline ) { return false; }
			} while ( true );
		}
		return true;
	}

	// ---------- stage: exposed files ----------
	private static function st_config( &$st, $deadline ) {
		$root = rtrim( wp_normalize_path( ABSPATH ), '/' ) . '/';
		$names = array( 'wp-config.php.bak', 'wp-config.php.old', 'wp-config.php.save', 'wp-config.php.orig', 'wp-config.php~', 'wp-config.bak', 'wp-config.txt', 'wp-config.php.swp', '.env', '.git/config', '.svn/entries', 'phpinfo.php', 'info.php', 'php.ini', 'error_log', 'php_errorlog', 'debug.log', 'wp-content/debug.log', 'wp-admin/error_log', 'backup.sql', 'database.sql', 'db.sql', 'dump.sql', 'site.zip', 'backup.zip', 'www.zip', 'public_html.zip', 'wp-content/backup.zip', 'adminer.php' );
		foreach ( (array) glob( $root . '*.{sql,sql.gz,tar.gz,tgz,bak}', GLOB_BRACE ) as $g ) { $names[] = basename( $g ); }
		foreach ( (array) glob( $root . 'wp-content/*.{sql,sql.gz,zip,tar.gz,bak}', GLOB_BRACE ) as $g ) { $names[] = 'wp-content/' . basename( $g ); }
		$names = array_unique( $names ); $n = count( $names );
		for ( $i = (int) $st['cursor']; $i < $n; $i++ ) {
			$rel = $names[ $i ]; $abs = $root . $rel;
			if ( is_file( $abs ) && filesize( $abs ) > 0 ) {
				$r = wp_safe_remote_get( home_url( '/' . $rel ), array( 'timeout' => 4, 'redirection' => 0, 'limit_response_size' => 2048 ) );
				$code = is_wp_error( $r ) ? 0 : (int) wp_remote_retrieve_response_code( $r );
				if ( 200 === $code ) { self::add( 'config_file', 'critical', __( 'Sensitive file is publicly downloadable', 'botvanguard' ), sprintf( /* translators: %s: file */ __( '%s can be opened by anyone through your website address. Remove it or block access.', 'botvanguard' ), $rel ), $rel ); }
				else { self::add( 'config_file', 'medium', __( 'Backup, log or information file found', 'botvanguard' ), sprintf( /* translators: %s: file */ __( '%s should not be on a live site. It does not seem to be public, but remove it to be safe.', 'botvanguard' ), $rel ), $rel ); }
			}
			if ( microtime( true ) >= $deadline ) { $st['cursor'] = $i + 1; return false; }
		}
		if ( is_file( $root . 'readme.html' ) ) { self::add( 'config_file', 'low', __( 'readme.html shows your WordPress version', 'botvanguard' ), __( 'Delete readme.html from the site root; it tells attackers which WordPress version you run.', 'botvanguard' ), 'readme.html' ); }
		$r = wp_safe_remote_get( content_url( '/uploads/' ), array( 'timeout' => 4, 'redirection' => 0, 'limit_response_size' => 4096 ) );
		if ( ! is_wp_error( $r ) && 200 === (int) wp_remote_retrieve_response_code( $r ) && false !== stripos( (string) wp_remote_retrieve_body( $r ), 'Index of' ) ) { self::add( 'dir_listing', 'medium', __( 'Directory listing is on for the uploads folder', 'botvanguard' ), __( 'Anyone can browse the list of your uploaded files. Add “Options -Indexes” to .htaccess, or turn directory listing off on the server.', 'botvanguard' ), '' ); }
		return true;
	}

	// ---------- stage: updates ----------
	private static function st_updates( &$st ) {
		require_once ABSPATH . 'wp-admin/includes/update.php'; require_once ABSPATH . 'wp-admin/includes/plugin.php';
		wp_version_check( array(), true ); wp_update_plugins(); wp_update_themes();
		$c = get_core_updates();
		if ( is_array( $c ) && ! empty( $c[0] ) && 'upgrade' === $c[0]->response ) { self::add( 'update_core', 'high', sprintf( /* translators: %s: version */ __( 'WordPress %s is available', 'botvanguard' ), $c[0]->current ), __( 'Updates often fix security problems.', 'botvanguard' ), '', array( 'key' => 'core', 'link' => admin_url( 'update-core.php' ) ) ); }
		$pl = get_site_transient( 'update_plugins' ); $all = get_plugins();
		foreach ( (array) ( $pl->response ?? array() ) as $file => $u ) { self::add( 'update_plugin', 'medium', sprintf( /* translators: %s: plugin */ __( 'The plugin “%s” needs an update', 'botvanguard' ), $all[ $file ]['Name'] ?? $file ), sprintf( /* translators: 1: old version 2: new version */ __( 'You have %1$s, the latest is %2$s.', 'botvanguard' ), $all[ $file ]['Version'] ?? '?', $u->new_version ?? '?' ), '', array( 'key' => $file, 'link' => admin_url( 'plugins.php?plugin_status=upgrade' ) ) ); }
		$th = get_site_transient( 'update_themes' ); $themes = wp_get_themes();
		foreach ( (array) ( $th->response ?? array() ) as $slug => $u ) { self::add( 'update_theme', 'medium', sprintf( /* translators: %s: theme */ __( 'The theme “%s” needs an update', 'botvanguard' ), isset( $themes[ $slug ] ) ? $themes[ $slug ]->get( 'Name' ) : $slug ), '', '', array( 'key' => $slug, 'link' => admin_url( 'themes.php' ) ) ); }
		return true;
	}

	private static function st_abandoned( &$st, $deadline ) {
		require_once ABSPATH . 'wp-admin/includes/plugin-install.php';
		$pl = array_values( self::wporg_slugs() ); $n = count( $pl );
		for ( $i = (int) $st['cursor']; $i < $n; $i++ ) {
			$p = $pl[ $i ]; $info = plugins_api( 'plugin_information', array( 'slug' => $p['slug'], 'fields' => array( 'sections' => false, 'last_updated' => true, 'short_description' => false, 'banners' => false, 'icons' => false, 'versions' => false, 'reviews' => false, 'contributors' => false, 'donate_link' => false, 'tags' => false, 'ratings' => false, 'active_installs' => false ) ) );
			if ( is_wp_error( $info ) ) { if ( 'plugins_api_failed' === $info->get_error_code() && false !== stripos( $info->get_error_message(), 'not found' ) || false !== stripos( $info->get_error_message(), 'closed' ) ) { self::add( 'plugin_removed', 'medium', sprintf( /* translators: %s: plugin */ __( 'The plugin “%s” was removed from WordPress.org', 'botvanguard' ), $p['name'] ), __( 'Plugins are usually closed for security problems or abandonment. Look for a replacement.', 'botvanguard' ), '', array( 'key' => $p['slug'] ) ); } }
			elseif ( ! empty( $info->last_updated ) && strtotime( $info->last_updated ) && strtotime( $info->last_updated ) < time() - 2 * YEAR_IN_SECONDS ) { self::add( 'plugin_abandoned', 'medium', sprintf( /* translators: %s: plugin */ __( 'The plugin “%s” has not been updated in over 2 years', 'botvanguard' ), $p['name'] ), sprintf( /* translators: %s: date */ __( 'Last update: %s. It may be abandoned and no longer receive security fixes.', 'botvanguard' ), gmdate( 'Y-m-d', strtotime( $info->last_updated ) ) ), '', array( 'key' => $p['slug'] ) ); }
			if ( microtime( true ) >= $deadline ) { $st['cursor'] = $i + 1; $st['frac'] = ( $i + 1 ) / max( 1, $n ); return false; }
		}
		return true;
	}

	// ---------- stage: weak passwords ----------
	private static function st_users( &$st, $deadline ) {
		$users = get_users( array( 'role__in' => array( 'administrator', 'editor', 'shop_manager' ), 'fields' => array( 'ID', 'user_login', 'user_email', 'user_pass' ), 'orderby' => 'ID', 'number' => 50 ) ); $n = count( $users );
		$host = (string) wp_parse_url( home_url(), PHP_URL_HOST ); $site = preg_replace( '/^www\./', '', $host ); $site1 = strtok( $site, '.' );
		for ( $i = (int) $st['cursor']; $i < $n; $i++ ) {
			$u = $users[ $i ]; $local = strstr( $u->user_email, '@', true );
			$cand = array_unique( array_filter( array_merge( Botvanguard_Firewall::common_passwords(), array( $u->user_login, strtolower( $u->user_login ), $u->user_login . '123', $u->user_login . '1', $u->user_login . '!', $local, $site, $site1, $site1 . '123', $site1 . '1', 'welcome123', 'Password1', 'Password123', 'Passw0rd!', 'Admin123!' ) ) ) );
			foreach ( $cand as $c ) { if ( wp_check_password( (string) $c, $u->user_pass, $u->ID ) ) { self::add( 'weak_password', 'critical', sprintf( /* translators: %s: user */ __( 'The user “%s” has a very weak password', 'botvanguard' ), $u->user_login ), __( 'This password is on the lists attackers try first. Change it now.', 'botvanguard' ), '', array( 'key' => 'user' . $u->ID, 'link' => admin_url( 'user-edit.php?user_id=' . $u->ID ) ) ); break; } }
			if ( microtime( true ) >= $deadline ) { $st['cursor'] = $i + 1; $st['frac'] = ( $i + 1 ) / max( 1, $n ); return false; }
		}
		return true;
	}

	// ---------- stage: server ----------
	private static function st_system( &$st ) {
		$free = @disk_free_space( ABSPATH ); $tot = @disk_total_space( ABSPATH );
		if ( $free && $tot && ( $free < 200 * MB_IN_BYTES || $free / $tot < 0.03 ) ) { self::add( 'system', 'medium', __( 'Low disk space', 'botvanguard' ), sprintf( /* translators: %s: size */ __( 'Only %s is free. A full disk can break updates, backups and the database.', 'botvanguard' ), size_format( $free ) ), '', array( 'key' => 'disk' ) ); }
		if ( version_compare( PHP_VERSION, '8.1', '<' ) ) { self::add( 'system', 'medium', sprintf( /* translators: %s: version */ __( 'PHP %s no longer gets security fixes', 'botvanguard' ), PHP_VERSION ), __( 'Ask your host to move the site to PHP 8.2 or newer.', 'botvanguard' ), '', array( 'key' => 'php' ) ); }
		return true;
	}

	// ---------- actions on findings ----------
	/** Absolute path of a finding's file, or '' if it is not a file inside this WordPress install. */
	public static function safe_path( $rel ) {
		$root = realpath( ABSPATH ); $abs = realpath( $root . '/' . ltrim( (string) $rel, '/' ) );
		if ( ! $root || ! $abs || 0 !== strpos( $abs, $root . DIRECTORY_SEPARATOR ) || ! is_file( $abs ) ) { return ''; }
		return $abs;
	}

	public static function remove_finding( $id ) { $f = self::findings(); unset( $f[ $id ] ); update_option( self::FINDINGS, $f, false ); $p = get_option( 'sidcraft_botshield_prev_findings', array() ); unset( $p[ $id ] ); update_option( 'sidcraft_botshield_prev_findings', $p, false ); }

	public static function ignore( $id ) { $i = self::ignored(); if ( ! in_array( $id, $i, true ) ) { $i[] = $id; update_option( self::IGNORED, array_slice( $i, -1000 ), false ); } self::remove_finding( $id ); }

	const QUARANTINE = 'sidcraft_botshield_quarantine';

	/** Part of WordPress itself? Such a file is repaired (restored from the official copy), never removed. */
	public static function is_core_path( $rel ) { return (bool) preg_match( '#^(?:wp-admin/|wp-includes/|[^/]+\.php$)#', (string) $rel ); }

	public static function quarantined() { $q = get_option( self::QUARANTINE, array() ); return is_array( $q ) ? $q : array(); }
	private static function qdir() { return self::dir() . 'quarantine/'; }

	/** Why a file may not be taken away, or ''. */
	public static function removal_block( $f ) {
		$rel = $f['rel']; $base = basename( $rel );
		if ( ! in_array( $f['type'], array( 'malware', 'upload_php', 'image_php', 'config_file', 'core_unknown', 'plugin_unknown' ), true ) || '' === $rel ) { return __( 'This file cannot be removed from here.', 'botvanguard' ); }
		if ( 'wp-config.php' === $base ) { return __( 'wp-config.php cannot be removed from here. Open it and delete the bad code by hand, or restore it from a backup.', 'botvanguard' ); }
		if ( 'core_unknown' !== $f['type'] && self::is_core_path( $rel ) ) { return __( 'This is a WordPress core file with bad code in it. Removing it would break the site. Use “Repair” on the matching “WordPress core file was modified” result to restore the official file.', 'botvanguard' ); }
		return '';
	}

	/** Move a flagged file into the quarantine folder (it can be put back). Returns '' or an error. */
	public static function quarantine_file( $id ) {
		$f = self::findings(); if ( ! isset( $f[ $id ] ) ) { return __( 'Unknown result.', 'botvanguard' ); }
		$why = self::removal_block( $f[ $id ] ); if ( '' !== $why ) { return $why; }
		$abs = self::safe_path( $f[ $id ]['rel'] ); if ( '' === $abs ) { return __( 'The file is not there any more.', 'botvanguard' ); }
		if ( ! Botvanguard_Lists::ensure_dir() ) { return __( 'The quarantine folder cannot be created (permissions).', 'botvanguard' ); }
		wp_mkdir_p( self::qdir() );
		$qid = strtolower( wp_generate_password( 12, false ) ); $to = self::qdir() . $qid . '.q';
		$ok = @rename( $abs, $to ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.rename_rename
		if ( ! $ok && @copy( $abs, $to ) ) { wp_delete_file( $abs ); $ok = ! is_file( $abs ); } // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.copy_copy
		if ( ! $ok || is_file( $abs ) ) { return __( 'The file could not be moved (permissions).', 'botvanguard' ); }
		$q = self::quarantined(); $q[ $qid ] = array( 'rel' => $f[ $id ]['rel'], 'time' => time(), 'title' => $f[ $id ]['title'], 'size' => (int) @filesize( $to ) ); update_option( self::QUARANTINE, $q, false ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		self::remove_finding( $id ); return '';
	}

	/** Findings that can be moved into quarantine from here (same rule as the single Quarantine button). */
	public static function quarantinable() {
		$out = array();
		foreach ( self::findings() as $id => $x ) { if ( '' === self::removal_block( $x ) && '' !== self::safe_path( $x['rel'] ) ) { $out[] = $id; } }
		return $out;
	}

	/** Quarantine every file that can be quarantined. Returns array( moved, failed ). */
	public static function quarantine_all() {
		$moved = 0; $failed = 0;
		foreach ( self::quarantinable() as $id ) { if ( '' === self::quarantine_file( $id ) ) { $moved++; } else { $failed++; } }
		return array( $moved, $failed );
	}

	/** Put a quarantined file back where it was. */
	public static function restore_file( $qid ) {
		$q = self::quarantined(); if ( ! isset( $q[ $qid ] ) ) { return __( 'Unknown file.', 'botvanguard' ); }
		$from = self::qdir() . $qid . '.q'; $root = realpath( ABSPATH ); $to = $root . '/' . $q[ $qid ]['rel'];
		if ( ! is_file( $from ) ) { unset( $q[ $qid ] ); update_option( self::QUARANTINE, $q, false ); return __( 'The quarantined file is gone.', 'botvanguard' ); }
		$dir = realpath( dirname( $to ) ); if ( ! $dir || 0 !== strpos( $dir, $root ) ) { return __( 'The original folder does not exist any more.', 'botvanguard' ); }
		if ( file_exists( $to ) ) { return __( 'A file already exists at the original place.', 'botvanguard' ); }
		if ( ! @rename( $from, $to ) ) { // phpcs:ignore PluginCheck.CodeAnalysis.WriteFile.ABSPATHDetected -- restoring a file to the place it was taken from
			 return __( 'The file could not be moved back (permissions).', 'botvanguard' ); } // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.rename_rename
		unset( $q[ $qid ] ); update_option( self::QUARANTINE, $q, false ); return '';
	}

	/** Delete a quarantined file for good. */
	public static function purge_file( $qid ) {
		$q = self::quarantined(); if ( isset( $q[ $qid ] ) ) { wp_delete_file( self::qdir() . $qid . '.q' ); unset( $q[ $qid ] ); update_option( self::QUARANTINE, $q, false ); }
		return '';
	}

	/** Delete every file in quarantine for good. Returns how many were removed. */
	public static function purge_all() {
		$q = self::quarantined(); $n = count( $q );
		foreach ( array_keys( $q ) as $qid ) { wp_delete_file( self::qdir() . sanitize_key( (string) $qid ) . '.q' ); }
		update_option( self::QUARANTINE, array(), false );
		return $n;
	}

	/** Replace a modified or missing core/plugin file with the official copy. Returns '' or an error. */
	public static function repair_file( $id ) {
		global $wp_version; $f = self::findings(); if ( ! isset( $f[ $id ] ) || empty( $f[ $id ]['extra']['repair'] ) ) { return __( 'This result cannot be repaired.', 'botvanguard' ); }
		$e = $f[ $id ]['extra']; $rel = $f[ $id ]['rel'];
		$url = 'core' === $e['repair'] ? 'https://core.svn.wordpress.org/tags/' . rawurlencode( $wp_version ) . '/' . implode( '/', array_map( 'rawurlencode', explode( '/', $rel ) ) ) : 'https://plugins.svn.wordpress.org/' . rawurlencode( $e['slug'] ) . '/tags/' . rawurlencode( $e['version'] ) . '/' . implode( '/', array_map( 'rawurlencode', explode( '/', $e['file'] ) ) );
		$r = wp_safe_remote_get( $url, array( 'timeout' => 30, 'limit_response_size' => 20 * MB_IN_BYTES ) );
		if ( is_wp_error( $r ) || 200 !== (int) wp_remote_retrieve_response_code( $r ) ) { return __( 'Could not download the official file.', 'botvanguard' ); }
		$body = wp_remote_retrieve_body( $r );
		$root = realpath( ABSPATH ); $target = $root . '/' . $rel; $dir = realpath( dirname( $target ) );
		if ( ! $dir || 0 !== strpos( $dir, $root ) ) { return __( 'Invalid path.', 'botvanguard' ); }
		require_once ABSPATH . 'wp-admin/includes/file.php'; WP_Filesystem(); global $wp_filesystem;
		if ( ! $wp_filesystem || ! $wp_filesystem->put_contents( $dir . '/' . basename( $target ), $body, FS_CHMOD_FILE ) ) { return __( 'The file could not be written (permissions).', 'botvanguard' ); }
		self::remove_finding( $id ); return '';
	}
}
