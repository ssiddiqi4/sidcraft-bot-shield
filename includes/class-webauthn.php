<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/** Passkey (WebAuthn) support: just enough of CBOR and the WebAuthn checks to register and verify security keys and passkeys. */
class Botvaguard_WebAuthn {
	public static function b64u( $s ) { return rtrim( strtr( base64_encode( $s ), '+/', '-_' ), '=' ); }
	public static function unb64u( $s ) { return (string) base64_decode( strtr( (string) $s, '-_', '+/' ) . str_repeat( '=', ( 4 - strlen( (string) $s ) % 4 ) % 4 ) ); }

	/** Relying party id (the site's host name) and origin. */
	public static function rp_id() { return (string) wp_parse_url( home_url(), PHP_URL_HOST ); }
	public static function origin() { $u = wp_parse_url( home_url() ); return $u['scheme'] . '://' . $u['host'] . ( ! empty( $u['port'] ) ? ':' . $u['port'] : '' ); }

	// ---- CBOR ----
	/** Decode one CBOR value at $o. Returns the value and advances $o; throws on bad input. */
	public static function cbor( $s, &$o, $depth = 0 ) {
		if ( $depth > 8 || $o >= strlen( $s ) ) { throw new Exception( 'cbor' ); }
		$b = ord( $s[ $o++ ] ); $t = $b >> 5; $i = $b & 31;
		if ( $i < 24 ) { $n = $i; }
		elseif ( 24 === $i ) { $n = ord( $s[ $o++ ] ); }
		elseif ( 25 === $i ) { $n = unpack( 'n', substr( $s, $o, 2 ) )[1]; $o += 2; }
		elseif ( 26 === $i ) { $n = unpack( 'N', substr( $s, $o, 4 ) )[1]; $o += 4; }
		elseif ( 27 === $i ) { $n = unpack( 'J', substr( $s, $o, 8 ) )[1]; $o += 8; }
		else { throw new Exception( 'cbor' ); }
		switch ( $t ) {
			case 0: return $n;
			case 1: return -1 - $n;
			case 2: case 3: if ( $o + $n > strlen( $s ) ) { throw new Exception( 'cbor' ); } $v = substr( $s, $o, $n ); $o += $n; return $v;
			case 4: $a = array(); for ( $k = 0; $k < $n; $k++ ) { $a[] = self::cbor( $s, $o, $depth + 1 ); } return $a;
			case 5: $m = array(); for ( $k = 0; $k < $n; $k++ ) { $key = self::cbor( $s, $o, $depth + 1 ); $m[ $key ] = self::cbor( $s, $o, $depth + 1 ); } return $m;
			case 7: return 20 === $i ? false : ( 21 === $i ? true : null );
		}
		throw new Exception( 'cbor' );
	}

	// ---- keys ----
	private static function der_len( $n ) { return $n < 128 ? chr( $n ) : ( $n < 256 ? "\x81" . chr( $n ) : "\x82" . pack( 'n', $n ) ); }
	private static function der_int( $b ) { $b = ltrim( $b, "\0" ); if ( '' === $b || ord( $b[0] ) > 127 ) { $b = "\0" . $b; } return "\x02" . self::der_len( strlen( $b ) ) . $b; }

	/** PEM public key from a COSE key map. */
	public static function cose_to_pem( array $k ) {
		$kty = $k[1] ?? 0;
		if ( 2 === $kty && ( $k[3] ?? 0 ) === -7 && ( $k[-1] ?? 0 ) === 1 && strlen( $k[-2] ?? '' ) === 32 && strlen( $k[-3] ?? '' ) === 32 ) {
			$der = hex2bin( '3059301306072a8648ce3d020106082a8648ce3d030107034200' ) . "\x04" . $k[-2] . $k[-3];
			return "-----BEGIN PUBLIC KEY-----\n" . chunk_split( base64_encode( $der ), 64, "\n" ) . "-----END PUBLIC KEY-----\n";
		}
		if ( 3 === $kty && ( $k[3] ?? 0 ) === -257 && ! empty( $k[-1] ) && ! empty( $k[-2] ) ) {
			$seq = self::der_int( $k[-1] ) . self::der_int( $k[-2] ); $rsa = "\x30" . self::der_len( strlen( $seq ) ) . $seq;
			return "-----BEGIN RSA PUBLIC KEY-----\n" . chunk_split( base64_encode( $rsa ), 64, "\n" ) . "-----END RSA PUBLIC KEY-----\n";
		}
		return '';
	}

	// ---- registration ----
	public static function creation_options( $user, $challenge, $exclude ) {
		return array( 'challenge' => self::b64u( $challenge ), 'rp' => array( 'name' => wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ), 'id' => self::rp_id() ),
			'user' => array( 'id' => self::b64u( hash_hmac( 'sha256', 'u' . $user->ID, wp_salt( 'auth' ), true ) ), 'name' => $user->user_login, 'displayName' => $user->display_name ),
			'pubKeyCredParams' => array( array( 'type' => 'public-key', 'alg' => -7 ), array( 'type' => 'public-key', 'alg' => -257 ) ),
			'authenticatorSelection' => array( 'residentKey' => 'preferred', 'userVerification' => 'preferred' ), 'attestation' => 'none', 'timeout' => 120000,
			'excludeCredentials' => array_map( function ( $c ) { return array( 'type' => 'public-key', 'id' => $c['id'] ); }, $exclude ) );
	}

	/** Check a registration response. Returns a credential array or a WP_Error. */
	public static function verify_registration( $client_b64, $att_b64, $challenge ) {
		try {
			$cj = self::unb64u( $client_b64 ); $c = json_decode( $cj, true );
			if ( ! is_array( $c ) || 'webauthn.create' !== ( $c['type'] ?? '' ) || ! hash_equals( self::b64u( $challenge ), (string) ( $c['challenge'] ?? '' ) ) || ( $c['origin'] ?? '' ) !== self::origin() ) { return new WP_Error( 'sbs_pk', 'The passkey response did not match this site.' ); }
			$o = 0; $att = self::cbor( self::unb64u( $att_b64 ), $o ); $ad = $att['authData'] ?? '';
			if ( strlen( $ad ) < 55 || substr( $ad, 0, 32 ) !== hash( 'sha256', self::rp_id(), true ) ) { return new WP_Error( 'sbs_pk', 'The passkey was made for a different site.' ); }
			$flags = ord( $ad[32] ); if ( ! ( $flags & 1 ) || ! ( $flags & 64 ) ) { return new WP_Error( 'sbs_pk', 'The passkey response was incomplete.' ); }
			$counter = unpack( 'N', substr( $ad, 33, 4 ) )[1]; $len = unpack( 'n', substr( $ad, 53, 2 ) )[1]; $id = substr( $ad, 55, $len ); $p = 55 + $len;
			$key = self::cbor( $ad, $p ); $pem = self::cose_to_pem( (array) $key );
			if ( '' === $pem || '' === $id ) { return new WP_Error( 'sbs_pk', 'This kind of passkey is not supported.' ); }
			return array( 'id' => self::b64u( $id ), 'pem' => $pem, 'counter' => $counter, 'created' => time() );
		} catch ( \Throwable $e ) { return new WP_Error( 'sbs_pk', 'The passkey response could not be read.' ); }
	}

	// ---- authentication ----
	public static function request_options( $challenge, $creds ) {
		return array( 'challenge' => self::b64u( $challenge ), 'rpId' => self::rp_id(), 'timeout' => 120000, 'userVerification' => 'preferred', 'allowCredentials' => array_map( function ( $c ) { return array( 'type' => 'public-key', 'id' => $c['id'] ); }, $creds ) );
	}

	/** Check a sign-in response against the user's credentials. Returns the updated credential list or a WP_Error. */
	public static function verify_assertion( $in, $challenge, array $creds ) {
		try {
			$id = (string) ( $in['id'] ?? '' ); $idx = null; foreach ( $creds as $i => $c ) { if ( hash_equals( $c['id'], $id ) ) { $idx = $i; } }
			if ( null === $idx ) { return new WP_Error( 'sbs_pk', 'Unknown passkey.' ); }
			$cj = self::unb64u( $in['clientDataJSON'] ?? '' ); $c = json_decode( $cj, true );
			if ( ! is_array( $c ) || 'webauthn.get' !== ( $c['type'] ?? '' ) || ! hash_equals( self::b64u( $challenge ), (string) ( $c['challenge'] ?? '' ) ) || ( $c['origin'] ?? '' ) !== self::origin() ) { return new WP_Error( 'sbs_pk', 'The passkey response did not match this site.' ); }
			$ad = self::unb64u( $in['authenticatorData'] ?? '' ); $sig = self::unb64u( $in['signature'] ?? '' );
			if ( strlen( $ad ) < 37 || substr( $ad, 0, 32 ) !== hash( 'sha256', self::rp_id(), true ) || ! ( ord( $ad[32] ) & 1 ) ) { return new WP_Error( 'sbs_pk', 'The passkey response was incomplete.' ); }
			$ok = openssl_verify( $ad . hash( 'sha256', $cj, true ), $sig, $creds[ $idx ]['pem'], OPENSSL_ALGO_SHA256 );
			if ( 1 !== $ok ) { return new WP_Error( 'sbs_pk', 'The passkey signature is not valid.' ); }
			$counter = unpack( 'N', substr( $ad, 33, 4 ) )[1];
			if ( $counter > 0 && $counter <= (int) $creds[ $idx ]['counter'] ) { return new WP_Error( 'sbs_pk', 'This passkey looks cloned (its counter went backwards).' ); }
			$creds[ $idx ]['counter'] = $counter; $creds[ $idx ]['last'] = time();
			return $creds;
		} catch ( \Throwable $e ) { return new WP_Error( 'sbs_pk', 'The passkey response could not be read.' ); }
	}
}

/** Authenticator-app codes (TOTP, RFC 6238). */
class Botvaguard_Totp {
	const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/** A new 160-bit secret as 32 base32 characters. */
	public static function secret() {
		$bits = ''; foreach ( str_split( random_bytes( 20 ) ) as $c ) { $bits .= str_pad( decbin( ord( $c ) ), 8, '0', STR_PAD_LEFT ); }
		$s = ''; foreach ( str_split( $bits, 5 ) as $chunk ) { $s .= self::ALPHA[ bindec( $chunk ) ]; }
		return $s;
	}

	public static function b32decode( $s ) {
		$s = strtoupper( preg_replace( '/[^A-Za-z2-7]/', '', $s ) ); $bits = '';
		foreach ( str_split( $s ) as $ch ) { $bits .= str_pad( decbin( strpos( self::ALPHA, $ch ) ), 5, '0', STR_PAD_LEFT ); }
		$out = ''; foreach ( str_split( $bits, 8 ) as $byte ) { if ( 8 === strlen( $byte ) ) { $out .= chr( bindec( $byte ) ); } }
		return $out;
	}

	public static function code( $secret, $step ) {
		$h = hash_hmac( 'sha1', pack( 'J', $step ), self::b32decode( $secret ), true ); $o = ord( $h[19] ) & 15;
		$n = ( ( ord( $h[ $o ] ) & 0x7F ) << 24 ) | ( ord( $h[ $o + 1 ] ) << 16 ) | ( ord( $h[ $o + 2 ] ) << 8 ) | ord( $h[ $o + 3 ] );
		return str_pad( (string) ( $n % 1000000 ), 6, '0', STR_PAD_LEFT );
	}

	/** Returns the matching time step (so that it cannot be used twice), or 0. */
	public static function verify( $secret, $code, $now = null ) {
		$code = preg_replace( '/\s+/', '', (string) $code ); if ( ! preg_match( '/^\d{6}$/', $code ) ) { return 0; }
		$step = (int) floor( ( $now ?? time() ) / 30 );
		for ( $d = -1; $d <= 1; $d++ ) { if ( hash_equals( self::code( $secret, $step + $d ), $code ) ) { return $step + $d; } }
		return 0;
	}

	public static function uri( $secret, $account ) {
		$issuer = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ); $issuer = '' === $issuer ? 'WordPress' : $issuer;
		return 'otpauth://totp/' . rawurlencode( $issuer . ':' . $account ) . '?secret=' . $secret . '&issuer=' . rawurlencode( $issuer ) . '&algorithm=SHA1&digits=6&period=30';
	}
}
