<?php
/**
 * Cryptography helper — secret encryption/decryption.
 *
 * Uses libsodium (preferred) with OpenSSL as fallback.
 * Secrets are stored as base64-encoded ciphertext in usermeta.
 *
 * @package OOSoft2FA
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class OOSOFT_2FA_Crypto {

	/** Meta key under which the derived encryption key material is stored. */
	private const KEY_META = '_oosoft_2fa_enc_key';

	/**
	 * Encrypt a plaintext string.
	 *
	 * @param string $plaintext Value to encrypt.
	 * @return string Base64-encoded ciphertext (includes nonce/IV).
	 * @throws RuntimeException If encryption fails.
	 */
	public static function encrypt( string $plaintext ): string {
		if ( self::sodium_available() ) {
			return self::sodium_encrypt( $plaintext );
		}
		return self::openssl_encrypt( $plaintext );
	}

	/**
	 * Decrypt a previously encrypted string.
	 *
	 * @param string $ciphertext Base64-encoded ciphertext.
	 * @return string Plaintext.
	 * @throws RuntimeException If decryption fails.
	 */
	public static function decrypt( string $ciphertext ): string {
		if ( self::sodium_available() ) {
			return self::sodium_decrypt( $ciphertext );
		}
		return self::openssl_decrypt( $ciphertext );
	}

	/**
	 * Generate a cryptographically secure random Base32 secret (for TOTP).
	 *
	 * @param int $bytes Number of raw bytes (default 20 → 160-bit secret).
	 * @return string Base32-encoded secret.
	 */
	public static function generate_totp_secret( int $bytes = 20 ): string {
		$raw = random_bytes( $bytes );
		return self::base32_encode( $raw );
	}

	/**
	 * Generate a secure random numeric OTP.
	 *
	 * @param int $digits Length of OTP (default 6).
	 * @return string Zero-padded numeric OTP.
	 */
	public static function generate_numeric_otp( int $digits = 6 ): string {
		$max = (int) str_pad( '1', $digits + 1, '0' ); // 10^digits
		return str_pad( (string) random_int( 0, $max - 1 ), $digits, '0', STR_PAD_LEFT );
	}

	/**
	 * Constant-time string comparison (prevents timing attacks).
	 *
	 * @param string $a First string.
	 * @param string $b Second string.
	 * @return bool True if strings match.
	 */
	public static function hash_equals( string $a, string $b ): bool {
		return hash_equals( $a, $b );
	}

	// -----------------------------------------------------------------------
	// Sodium helpers
	// -----------------------------------------------------------------------

	private static function sodium_available(): bool {
		return function_exists( 'sodium_crypto_secretbox' );
	}

	private static function sodium_encrypt( string $plaintext ): string {
		$key    = self::get_encryption_key( SODIUM_CRYPTO_SECRETBOX_KEYBYTES );
		$nonce  = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$cipher = sodium_crypto_secretbox( $plaintext, $nonce, $key );
		// sodium_memzero requires the native ext-sodium C extension.
		// sodium_compat (pure-PHP polyfill) intentionally throws here — skip it.
		if ( extension_loaded( 'sodium' ) ) {
			sodium_memzero( $key );
		}
		return base64_encode( $nonce . $cipher ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
	}

	private static function sodium_decrypt( string $ciphertext ): string {
		$raw   = base64_decode( $ciphertext, true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		if ( false === $raw ) {
			throw new RuntimeException( 'Invalid base64 ciphertext.' );
		}
		$nonce_len = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES;
		if ( strlen( $raw ) <= $nonce_len ) {
			throw new RuntimeException( 'Ciphertext too short.' );
		}
		$nonce  = substr( $raw, 0, $nonce_len );
		$cipher = substr( $raw, $nonce_len );
		$key   = self::get_encryption_key( SODIUM_CRYPTO_SECRETBOX_KEYBYTES );
		$plain = sodium_crypto_secretbox_open( $cipher, $nonce, $key );
		if ( extension_loaded( 'sodium' ) ) {
			sodium_memzero( $key );
		}
		if ( false === $plain ) {
			throw new RuntimeException( 'Decryption failed — data may be tampered.' );
		}
		return $plain;
	}

	// -----------------------------------------------------------------------
	// OpenSSL helpers (fallback)
	// -----------------------------------------------------------------------

	/**
	 * Preferred cipher with GCM authentication; falls back to CBC+HMAC if GCM
	 * is unavailable (some older OpenSSL builds on shared hosts lack GCM support).
	 */
	private const OPENSSL_CIPHER_GCM = 'aes-256-gcm';
	private const OPENSSL_CIPHER_CBC = 'aes-256-cbc';

	private static function openssl_encrypt( string $plaintext ): string {
		$use_gcm = in_array( self::OPENSSL_CIPHER_GCM, openssl_get_cipher_methods(), true );
		$cipher  = $use_gcm ? self::OPENSSL_CIPHER_GCM : self::OPENSSL_CIPHER_CBC;
		$key     = self::get_encryption_key( 32 );
		$iv_len  = (int) openssl_cipher_iv_length( $cipher );

		if ( $iv_len <= 0 ) {
			throw new RuntimeException( 'OpenSSL: could not determine IV length for cipher: ' . $cipher );
		}

		$iv  = random_bytes( $iv_len );
		$tag = '';

		if ( $use_gcm ) {
			$encrypted = openssl_encrypt( $plaintext, $cipher, $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16 );
		} else {
			// CBC mode: compute HMAC-SHA256 as authentication tag.
			$encrypted = openssl_encrypt( $plaintext, $cipher, $key, OPENSSL_RAW_DATA, $iv );
			$tag       = hash_hmac( 'sha256', $iv . $encrypted, $key, true );
		}

		if ( false === $encrypted ) {
			throw new RuntimeException( 'OpenSSL encryption failed.' );
		}

		// Layout: [1-byte mode flag][iv][tag(16 or 32)][ciphertext]
		$mode_flag = $use_gcm ? "\x01" : "\x00";
		return base64_encode( $mode_flag . $iv . $tag . $encrypted ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
	}

	private static function openssl_decrypt( string $ciphertext ): string {
		$raw = base64_decode( $ciphertext, true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		if ( false === $raw || strlen( $raw ) < 2 ) {
			throw new RuntimeException( 'Invalid base64 ciphertext.' );
		}

		// Read mode flag written by openssl_encrypt().
		$use_gcm = ( "\x01" === $raw[0] );
		$raw     = substr( $raw, 1 ); // Strip mode byte.
		$cipher  = $use_gcm ? self::OPENSSL_CIPHER_GCM : self::OPENSSL_CIPHER_CBC;
		$iv_len  = (int) openssl_cipher_iv_length( $cipher );
		$tag_len = $use_gcm ? 16 : 32; // GCM tag vs HMAC-SHA256.

		if ( strlen( $raw ) <= $iv_len + $tag_len ) {
			throw new RuntimeException( 'Ciphertext too short.' );
		}

		$iv         = substr( $raw, 0, $iv_len );
		$tag        = substr( $raw, $iv_len, $tag_len );
		$encrypted  = substr( $raw, $iv_len + $tag_len );
		$key        = self::get_encryption_key( 32 );

		if ( $use_gcm ) {
			$plain = openssl_decrypt( $encrypted, $cipher, $key, OPENSSL_RAW_DATA, $iv, $tag );
		} else {
			// Verify HMAC before decrypting (encrypt-then-MAC).
			$expected_tag = hash_hmac( 'sha256', $iv . $encrypted, $key, true );
			if ( ! hash_equals( $expected_tag, $tag ) ) {
				throw new RuntimeException( 'OpenSSL CBC: authentication tag mismatch — data may be tampered.' );
			}
			$plain = openssl_decrypt( $encrypted, $cipher, $key, OPENSSL_RAW_DATA, $iv );
		}

		if ( false === $plain ) {
			throw new RuntimeException( 'OpenSSL decryption failed.' );
		}
		return $plain;
	}

	// -----------------------------------------------------------------------
	// Key derivation
	// -----------------------------------------------------------------------

	/**
	 * Derive (or retrieve) a stable encryption key for this installation.
	 *
	 * The key is derived from WordPress secret keys via HKDF so each
	 * installation has a unique key without storing raw key material.
	 *
	 * @param int $length Desired key length in bytes.
	 * @return string Raw key bytes.
	 */
	private static function get_encryption_key( int $length ): string {
		$ikm  = defined( 'AUTH_KEY' ) ? AUTH_KEY : wp_generate_password( 64, true, true );
		$salt = defined( 'SECURE_AUTH_SALT' ) ? SECURE_AUTH_SALT : 'oosoft-2fa-default-salt';

		// HKDF using SHA-256.
		$prk = hash_hmac( 'sha256', $ikm, $salt, true );
		$key = '';
		$t   = '';
		$i   = 1;
		while ( strlen( $key ) < $length ) {
			$t    = hash_hmac( 'sha256', $t . 'oosoft-2fa' . chr( $i++ ), $prk, true );
			$key .= $t;
		}
		return substr( $key, 0, $length );
	}

	// -----------------------------------------------------------------------
	// Base32 encoder (RFC 4648 — required for TOTP secrets)
	// -----------------------------------------------------------------------

	private const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	public static function base32_encode( string $data ): string {
		$encoded  = '';
		$data_len = strlen( $data );
		$buffer   = 0;
		$bits_left = 0;

		for ( $i = 0; $i < $data_len; $i++ ) {
			$buffer    = ( $buffer << 8 ) | ord( $data[ $i ] );
			$bits_left += 8;
			while ( $bits_left >= 5 ) {
				$bits_left -= 5;
				$encoded   .= self::BASE32_CHARS[ ( $buffer >> $bits_left ) & 0x1F ];
			}
		}

		if ( $bits_left > 0 ) {
			$encoded .= self::BASE32_CHARS[ ( $buffer << ( 5 - $bits_left ) ) & 0x1F ];
		}

		// Pad to multiple of 8.
		$padding = ( 8 - ( strlen( $encoded ) % 8 ) ) % 8;
		return $encoded . str_repeat( '=', $padding );
	}

	public static function base32_decode( string $data ): string {
		$data     = strtoupper( rtrim( $data, '=' ) );
		$chars    = self::BASE32_CHARS;
		$decoded  = '';
		$buffer   = 0;
		$bits_left = 0;

		for ( $i = 0, $len = strlen( $data ); $i < $len; $i++ ) {
			$pos = strpos( $chars, $data[ $i ] );
			if ( false === $pos ) {
				throw new InvalidArgumentException( 'Invalid Base32 character: ' . $data[ $i ] );
			}
			$buffer    = ( $buffer << 5 ) | $pos;
			$bits_left += 5;
			if ( $bits_left >= 8 ) {
				$bits_left -= 8;
				$decoded   .= chr( ( $buffer >> $bits_left ) & 0xFF );
			}
		}

		return $decoded;
	}
}
