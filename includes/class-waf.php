<?php
/**
 * Web application firewall rules. This file has no WordPress dependency so that it can also run before WordPress
 * loads ("extended protection", through auto_prepend_file).
 *
 * @package Sidcraft_BotShield
 */
if ( ! defined( 'ABSPATH' ) ) {
	// Outside WordPress this file is only loaded by the firewall bootstrap, which defines this constant first.
	if ( ! defined( 'SIDCRAFT_BOTSHIELD_WAF' ) ) {
		exit;
	}
}

// phpcs:disable WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput, WordPress.WP.AlternativeFunctions, WordPress.PHP.NoSilencedErrors, WordPress.PHP.DevelopmentFunctions -- a firewall has to read the raw request and run before WordPress is loaded.

class Botvaguard_Waf {
	/** Rule id => array( category, label, pattern, where ). where: v = values, n = parameter names, c = cookies/headers only, g = query+cookies only. */
	public static function rules() {
		return array(
			'sqli_union'   => array( 'sqli', 'SQL injection: UNION SELECT', '/\bunion\b[\s\(]+(?:all\s+|distinct\s+)?select\b/i', 'v' ),
			'sqli_boolean' => array( 'sqli', 'SQL injection: always-true condition', '/[\'"\)]\s*(?:or|and)\s+[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d+|\b(?:or|and)\s+\d+\s*=\s*\d+\s*(?:--|#|\/\*|$)|\'\s*or\s*\'[^\']*\'\s*=\s*\'/i', 'v' ),
			'sqli_time'    => array( 'sqli', 'SQL injection: time delay', '/\b(?:sleep|pg_sleep)\s*\(\s*\d|\bbenchmark\s*\(\s*\d+\s*,|\bwaitfor\s+delay\b/i', 'v' ),
			'sqli_schema'  => array( 'sqli', 'SQL injection: database structure', '/\binformation_schema\b|\bmysql\.user\b|\bsys\.(?:tables|columns)\b/i', 'v' ),
			'sqli_file'    => array( 'sqli', 'SQL injection: file access', '/\bload_file\s*\(|\binto\s+(?:out|dump)file\b/i', 'v' ),
			'sqli_stack'   => array( 'sqli', 'SQL injection: stacked query', '/;\s*(?:drop|alter|truncate)\s+(?:table|database)\b|;\s*(?:insert\s+into|delete\s+from|update\s+\w+\s+set)\b/i', 'v' ),
			'xss_script'   => array( 'xss', 'Cross-site scripting: script tag', '/<\s*\/?\s*script\b/i', 'v' ),
			'xss_event'    => array( 'xss', 'Cross-site scripting: event handler', '/<[a-z][^>]{0,200}\bon[a-z]{3,20}\s*=/i', 'v' ),
			'xss_uri'      => array( 'xss', 'Cross-site scripting: javascript: link', '/(?:^|[\s"\'=\(])javascript\s*:/i', 'v' ),
			'xss_tags'     => array( 'xss', 'Cross-site scripting: dangerous tag', '/<\s*(?:iframe|object|embed|svg|math|base)\b|<\s*meta\s[^>]*http-equiv/i', 'v' ),
			'lfi_traverse' => array( 'lfi', 'File inclusion: directory traversal', '/(?:\.\.[\\\\\/]){2,}/', 'v' ),
			'lfi_system'   => array( 'lfi', 'File inclusion: system files', '/\/etc\/(?:passwd|shadow|hosts)\b|\bboot\.ini\b|\/proc\/self\/|[a-z]:\\\\windows\\\\/i', 'v' ),
			'lfi_wrapper'  => array( 'lfi', 'File inclusion: PHP wrapper', '/\b(?:php|phar|expect|zip|glob|gopher)\s*:\/\//i', 'v' ),
			'lfi_config'   => array( 'lfi', 'File inclusion: WordPress configuration', '/(?:^|[\/\\\\=])wp-config\.(?:php|bak|txt|old|save)\b/i', 'v' ),
			'rfi_remote'   => array( 'lfi', 'File inclusion: remote file', '/^(?:https?|ftp):\/\/[^\/]+\/[^\s]*\.(?:php\d?|txt|inc)\??/i', 'f' ),
			'rce_php'      => array( 'rce', 'Code execution: PHP function', '/\b(?:eval|assert|system|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(|\bbase64_decode\s*\(|\bphpinfo\s*\(|<\?(?:php|=)|\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[/i', 'v' ),
			'rce_shell'    => array( 'rce', 'Code execution: shell command', '/(?:[;|&]|\$\(|`)\s*(?:cat|wget|curl|nc|netcat|bash|python[23]?|perl|chmod|whoami|uname)\s+[\-\/\w]/i', 'v' ),
			'rce_log4j'    => array( 'rce', 'Code execution: Log4Shell', '/\$\{\s*(?:jndi|\$\{?(?:lower|upper))/i', 'a' ),
			'rce_shellshock' => array( 'rce', 'Code execution: Shellshock', '/\(\)\s*\{[^}]*\}\s*;/', 'h' ),
			'php_object'   => array( 'rce', 'PHP object injection', '/(?:^|[;{}])[OC]:\d+:"[^"]{1,100}":\d+:\{/', 'g' ),
			'null_byte'    => array( 'lfi', 'Null byte in request', '/\x00/', 'v' ),
			'upload_php'   => array( 'upload', 'Upload of a PHP or script file', '', 'u' ),
		);
	}

	public static function categories() {
		return array( 'sqli' => 'SQL injection', 'xss' => 'Cross-site scripting', 'lfi' => 'File inclusion and traversal', 'rce' => 'Code execution', 'upload' => 'Malicious file uploads' );
	}

	/** Flatten nested request arrays into name => value pairs. */
	private static function flatten( $data, $prefix = '', $depth = 0 ) {
		$out = array();
		if ( $depth > 6 ) { return $out; }
		foreach ( (array) $data as $k => $v ) {
			$name = '' === $prefix ? (string) $k : $prefix . '[' . $k . ']';
			if ( is_array( $v ) ) { $out = array_merge( $out, self::flatten( $v, $name, $depth + 1 ) ); } else { $out[] = array( $name, (string) $v, (string) $k ); }
			if ( count( $out ) > 400 ) { break; }
		}
		return $out;
	}

	/** Decode a value the way an attacker may have encoded it. Returns the raw and decoded forms. */
	private static function variants( $v ) {
		$v = substr( $v, 0, 20000 ); $out = array( $v );
		$d = $v;
		for ( $i = 0; $i < 2; $i++ ) { $n = rawurldecode( str_replace( '+', ' ', $d ) ); if ( $n === $d ) { break; } $d = $n; }
		$d = html_entity_decode( $d, ENT_QUOTES | ENT_HTML5, 'UTF-8' );
		$d = preg_replace( '#/\*.*?\*/#s', ' ', $d );
		$d = preg_replace( '/\s+/', ' ', (string) $d );
		if ( $d !== $v ) { $out[] = $d; }
		return $out;
	}

	/**
	 * Inspect one request.
	 *
	 * @param array $req  method, path, get, post, cookies, headers (ua, referer, other), files (name => tmp path).
	 * @param array $opt  disabled (rule ids), allow (lines "path param [rule]"), admin_fields (param names ignored), editor (bool).
	 * @return array|null array( rule, category, label, param ) when a rule matches.
	 */
	public static function inspect( array $req, array $opt = array() ) {
		$rules = self::rules(); $disabled = array_flip( (array) ( $opt['disabled'] ?? array() ) );
		$path  = (string) ( $req['path'] ?? '' );
		$allow = self::parse_allow( (array) ( $opt['allow'] ?? array() ) );
		$sets  = array( 'g' => self::flatten( $req['get'] ?? array() ), 'p' => self::flatten( $req['post'] ?? array() ), 'c' => self::flatten( $req['cookies'] ?? array() ), 'h' => array() );
		foreach ( (array) ( $req['headers'] ?? array() ) as $hn => $hv ) { $sets['h'][] = array( (string) $hn, (string) $hv, (string) $hn ); }
		foreach ( $sets as $src => $items ) {
			foreach ( $items as $it ) {
				list( $name, $val, $leaf ) = $it;
				if ( '' === $val && 'g' !== $src ) { continue; }
				$base = preg_replace( '/\[.*$/', '', $name );
				if ( ! empty( $opt['editor'] ) && 'p' === $src && in_array( strtolower( $base ), (array) ( $opt['admin_fields'] ?? array() ), true ) ) { continue; }
				$vs = self::variants( $val );
				foreach ( $rules as $id => $r ) {
					if ( isset( $disabled[ $id ] ) || '' === $r[2] ) { continue; }
					$w = $r[3];
					if ( 'h' === $w && 'h' !== $src && 'c' !== $src ) { continue; }
					if ( 'g' === $w && 'g' !== $src && 'c' !== $src ) { continue; }
					if ( 'a' === $w ) { /* any source */ }
					if ( 'f' === $w && ! preg_match( '/^(?:file|path|page|include|inc|template|dir|doc|folder|root|pg|style|pdf|view|load|read|show|lang|module|conf|theme)$/i', $leaf ) ) { continue; }
					if ( self::allowed( $allow, $path, $base, $id ) ) { continue; }
					foreach ( $vs as $x ) { if ( @preg_match( $r[2], $x ) ) { return array( 'rule' => $id, 'category' => $r[0], 'label' => $r[1], 'param' => $name ); } }
					if ( 'v' === $w || 'n' === $w ) { if ( $name !== $val && @preg_match( $r[2], $leaf ) && ! preg_match( '/^[\w\-\[\]\.]+$/', $leaf ) ) { return array( 'rule' => $id, 'category' => $r[0], 'label' => $r[1], 'param' => $name ); } }
				}
			}
		}
		// Uploads.
		if ( ! isset( $disabled['upload_php'] ) ) {
			foreach ( (array) ( $req['files'] ?? array() ) as $fname => $tmp ) {
				if ( self::allowed( $allow, $path, 'file', 'upload_php' ) ) { break; }
				$bad = (bool) preg_match( '/\.(?:php\d?|phtml|pht|phar|phps|shtml|cgi|pl|py|sh|asp|aspx|jsp)(?:\.|$)/i', (string) $fname );
				if ( ! $bad && is_string( $tmp ) && '' !== $tmp && is_readable( $tmp ) && filesize( $tmp ) > 0 ) {
					$h = fopen( $tmp, 'rb' ); $head = $h ? (string) fread( $h, 8192 ) : ''; if ( $h ) { fclose( $h ); }
					$bad = (bool) preg_match( '/<\?php|<\?=|<script\s+language\s*=\s*[\'"]?php/i', $head );
				}
				if ( $bad ) { return array( 'rule' => 'upload_php', 'category' => 'upload', 'label' => $rules['upload_php'][1], 'param' => (string) $fname ); }
			}
		}
		return null;
	}

	private static function parse_allow( array $lines ) {
		$out = array();
		foreach ( $lines as $l ) { $p = preg_split( '/\s+/', trim( (string) $l ) ); if ( ! empty( $p[0] ) ) { $out[] = array( $p[0], $p[1] ?? '*', $p[2] ?? '*' ); } }
		return $out;
	}

	private static function allowed( array $allow, $path, $param, $rule ) {
		foreach ( $allow as $a ) {
			$pm = '*' === $a[0] || rtrim( $a[0], '/' ) === rtrim( $path, '/' ) || ( '/' === substr( $a[0], -1 ) && 0 === strpos( $path, $a[0] ) );
			if ( $pm && ( '*' === $a[1] || strtolower( $a[1] ) === strtolower( $param ) ) && ( '*' === $a[2] || $a[2] === $rule ) ) { return true; }
		}
		return false;
	}

	// ---- Extended protection: runs before WordPress ----

	public static function bootstrap( $config_file, $dir ) {
		try {
			if ( defined( 'SIDCRAFT_BOTSHIELD_WAF_DONE' ) || 'cli' === PHP_SAPI ) { return; }
			$seen = $dir . '/waf-seen.txt';
			if ( ! is_file( $seen ) || time() - (int) @filemtime( $seen ) > 60 ) { @file_put_contents( $seen, (string) time() ); }
			$c = json_decode( (string) @file_get_contents( $config_file ), true );
			if ( ! is_array( $c ) || empty( $c['mode'] ) || 'disabled' === $c['mode'] ) { return; }
			define( 'SIDCRAFT_BOTSHIELD_WAF_DONE', 1 );
			$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '';
			if ( ! empty( $c['proxy_header'] ) && ! empty( $_SERVER[ $c['proxy_header'] ] ) ) { $x = trim( explode( ',', (string) $_SERVER[ $c['proxy_header'] ] )[0] ); if ( filter_var( $x, FILTER_VALIDATE_IP ) ) { $ip = $x; } }
			if ( '' !== $ip && ! empty( $c['trusted'] ) && class_exists( 'Botvaguard_Ranges' ) && Botvaguard_Ranges::in_list( $ip, (array) $c['trusted'] ) ) { return; }
			$path = (string) parse_url( isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '/', PHP_URL_PATH );
			if ( false !== strpos( $path, 'wp-cron.php' ) ) { return; }
			$files = array(); foreach ( $_FILES as $f ) { if ( ! is_array( $f ) || ! isset( $f['name'] ) ) { continue; } foreach ( (array) $f['name'] as $i => $n ) { $t = is_array( $f['tmp_name'] ) ? ( $f['tmp_name'][ $i ] ?? '' ) : ( $f['tmp_name'] ?? '' ); $files[ is_array( $n ) ? 'x' : (string) $n ] = is_string( $t ) ? $t : ''; } if ( ! is_array( $f['name'] ) ) { $files[ (string) $f['name'] ] = (string) ( $f['tmp_name'] ?? '' ); } }
			$cookies = $_COOKIE; $has_login_cookie = false;
			foreach ( array_keys( $cookies ) as $k ) { if ( 0 === strpos( (string) $k, 'wordpress_logged_in_' ) ) { $has_login_cookie = true; } }
			$editor = $has_login_cookie && 0 === strpos( $path, '/wp-admin/' ) && ! preg_match( '#/admin-(?:ajax|post)\.php$#', $path ) && 'POST' === ( $_SERVER['REQUEST_METHOD'] ?? '' );
			foreach ( $cookies as $k => $v ) { if ( 0 === strpos( (string) $k, 'wordpress_' ) || 0 === strpos( (string) $k, 'wp-settings' ) ) { unset( $cookies[ $k ] ); } }
			$req = array(
				'path' => $path, 'get' => $_GET, 'post' => $_POST, 'cookies' => $cookies, 'files' => $files,
				'headers' => array( 'user-agent' => (string) ( $_SERVER['HTTP_USER_AGENT'] ?? '' ), 'referer' => (string) ( $_SERVER['HTTP_REFERER'] ?? '' ), 'x-forwarded-for' => (string) ( $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '' ), 'accept' => (string) ( $_SERVER['HTTP_ACCEPT'] ?? '' ) ),
			);
			$hit = self::inspect( $req, array( 'disabled' => $c['disabled'] ?? array(), 'allow' => $c['allow'] ?? array(), 'editor' => $editor, 'admin_fields' => self::admin_fields() ) );
			if ( ! $hit ) { return; }
			$line = botvaguard_json( array( 't' => time(), 'ip' => $ip, 'rule' => $hit['rule'], 'param' => substr( $hit['param'], 0, 80 ), 'p' => substr( $path, 0, 120 ), 'ua' => substr( (string) ( $_SERVER['HTTP_USER_AGENT'] ?? '' ), 0, 160 ), 'm' => 'learning' === $c['mode'] ? 'monitor' : 'block' ) );
			$log = $dir . '/waf-log.jsonl';
			if ( ! is_file( $log ) || filesize( $log ) < 262144 ) { @file_put_contents( $log, $line . "\n", FILE_APPEND | LOCK_EX ); }
			if ( 'learning' === $c['mode'] ) { return; }
			if ( ! headers_sent() ) { header( 'HTTP/1.1 403 Forbidden' ); header( 'Content-Type: text/plain; charset=UTF-8' ); header( 'X-Robots-Tag: noindex' ); }
			echo 'Blocked by the BotVaguard firewall.';
			exit;
		} catch ( \Throwable $e ) { return; }
	}

	/** Form fields in the WordPress admin that legitimately carry HTML, scripts or code. */
	public static function admin_fields() {
		return array( 'content', 'post_content', 'excerpt', 'post_excerpt', 'comment_content', 'newcontent', 'description', 'html', 'text', 'value', 'post_title', 'data', 'customized', 'wp_customize', 'meta', 'metakeyselect', 'metavalue', 'tax_input', 'option_page', 'widget-text', 'widget-custom_html', 'sidebars', 'sidebar', 'page_options', 'code', 'css', 'custom_css' );
	}
}

/** json_encode without needing WordPress. */
function botvaguard_json( $v ) { return json_encode( $v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR ); }
