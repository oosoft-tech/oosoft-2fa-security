<?php
/**
 * TOTP (RFC 6238) implementation — Google Authenticator compatible.
 *
 * Implements HMAC-based One-Time Passwords per RFC 4226 with a
 * time-step of 30 seconds and SHA-1 as required by most authenticator apps.
 * Allows a ±1 window (90-second tolerance) to account for clock drift.
 *
 * @package OOSoft2FA
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class OOSOFT_2FA_TOTP {

	private const PERIOD    = 30;   // seconds per time step (RFC 6238 default).
	private const DIGITS    = 6;    // OTP length.
	private const ALGORITHM = 'sha1'; // Required by Google Authenticator.
	private const WINDOW    = 1;    // ±1 time steps to accept.

	/**
	 * Verify a user-supplied TOTP code against the stored secret.
	 *
	 * @param int    $user_id   WordPress user ID.
	 * @param string $code      6-digit code from the authenticator app.
	 * @return bool True if the code is valid and has not been used before.
	 */
	public static function verify( int $user_id, string $code ): bool {
		$code = preg_replace( '/\D/', '', $code );

		if ( strlen( $code ) !== self::DIGITS ) {
			return false;
		}

		$secret = self::get_secret( $user_id );
		if ( empty( $secret ) ) {
			return false;
		}

		$time_step = (int) floor( time() / self::PERIOD );

		for ( $i = -self::WINDOW; $i <= self::WINDOW; $i++ ) {
			$expected = self::generate_code( $secret, $time_step + $i );
			if ( hash_equals( $expected, $code ) ) {
				// Replay protection — each time step may only be used once.
				if ( self::is_code_used( $user_id, $time_step + $i ) ) {
					OOSOFT_2FA_Logger::log( 'totp_replay_attempt', OOSOFT_2FA_Logger::WARNING, $user_id );
					return false;
				}
				self::mark_code_used( $user_id, $time_step + $i );
				return true;
			}
		}

		return false;
	}

	/**
	 * Generate the current TOTP code for a user (useful for testing).
	 *
	 * @param int $user_id WordPress user ID.
	 * @return string|null Current 6-digit code, or null if no secret set.
	 */
	public static function get_current_code( int $user_id ): ?string {
		$secret = self::get_secret( $user_id );
		if ( empty( $secret ) ) {
			return null;
		}
		$time_step = (int) floor( time() / self::PERIOD );
		return self::generate_code( $secret, $time_step );
	}

	/**
	 * Provision a new TOTP secret for a user (does NOT activate it yet).
	 * The secret is stored encrypted and flagged as pending confirmation.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return string The Base32-encoded plaintext secret (shown once to user).
	 */
	public static function provision_secret( int $user_id ): string {
		$secret    = OOSOFT_2FA_Crypto::generate_totp_secret();
		$encrypted = OOSOFT_2FA_Crypto::encrypt( $secret );
		update_user_meta( $user_id, '_oosoft_2fa_totp_pending', $encrypted );
		return $secret;
	}

	/**
	 * Confirm and activate a provisioned secret by verifying the first code.
	 *
	 * @param int    $user_id WordPress user ID.
	 * @param string $code    Code from authenticator app.
	 * @return bool True if confirmed successfully.
	 */
	public static function confirm_secret( int $user_id, string $code ): bool {
		$pending_enc = get_user_meta( $user_id, '_oosoft_2fa_totp_pending', true );
		if ( empty( $pending_enc ) ) {
			return false;
		}

		try {
			$secret = OOSOFT_2FA_Crypto::decrypt( $pending_enc );
		} catch ( RuntimeException $e ) {
			OOSOFT_2FA_Logger::log( 'totp_decrypt_error', OOSOFT_2FA_Logger::ERROR, $user_id );
			return false;
		}

		$code      = preg_replace( '/\D/', '', $code );
		$time_step = (int) floor( time() / self::PERIOD );

		for ( $i = -self::WINDOW; $i <= self::WINDOW; $i++ ) {
			if ( hash_equals( self::generate_code( $secret, $time_step + $i ), $code ) ) {
				// Activate: move pending → active.
				update_user_meta( $user_id, '_oosoft_2fa_totp_secret', $pending_enc );
				delete_user_meta( $user_id, '_oosoft_2fa_totp_pending' );
				update_user_meta( $user_id, '_oosoft_2fa_totp_enabled', '1' );
				OOSOFT_2FA_Logger::log( 'totp_enabled', OOSOFT_2FA_Logger::INFO, $user_id );
				return true;
			}
		}

		return false;
	}

	/**
	 * Disable TOTP for a user and wipe stored secret.
	 *
	 * @param int $user_id WordPress user ID.
	 */
	public static function disable( int $user_id ): void {
		delete_user_meta( $user_id, '_oosoft_2fa_totp_secret' );
		delete_user_meta( $user_id, '_oosoft_2fa_totp_pending' );
		delete_user_meta( $user_id, '_oosoft_2fa_totp_enabled' );
		delete_user_meta( $user_id, '_oosoft_2fa_totp_used_steps' );
		OOSOFT_2FA_Logger::log( 'totp_disabled', OOSOFT_2FA_Logger::WARNING, $user_id );
	}

	/**
	 * Check whether the user has TOTP enabled and an active secret.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return bool
	 */
	public static function is_enabled( int $user_id ): bool {
		return '1' === get_user_meta( $user_id, '_oosoft_2fa_totp_enabled', true )
			&& ! empty( get_user_meta( $user_id, '_oosoft_2fa_totp_secret', true ) );
	}

	/**
	 * Build an otpauth:// URI for QR code generation.
	 *
	 * @param int    $user_id  WordPress user ID.
	 * @param string $secret   Plaintext Base32 secret.
	 * @return string otpauth URI.
	 */
	public static function get_otpauth_uri( int $user_id, string $secret ): string {
		$user    = get_userdata( $user_id );
		$account = $user ? rawurlencode( $user->user_email ) : 'user';
		$issuer  = rawurlencode( get_bloginfo( 'name' ) );

		// algorithm/digits/period are omitted — all apps (Google Authenticator,
		// Authy, etc.) default to SHA1/6/30 and ignore or reject unknown params.
		// Shorter URI = lower QR version = easier to scan.
		return sprintf(
			'otpauth://totp/%s:%s?secret=%s&issuer=%s',
			$issuer,
			$account,
			rawurlencode( $secret ),
			$issuer
		);
	}

	// -----------------------------------------------------------------------
	// HOTP core (RFC 4226)
	// -----------------------------------------------------------------------

	private static function generate_code( string $secret, int $counter ): string {
		try {
			$key = OOSOFT_2FA_Crypto::base32_decode( $secret );
		} catch ( InvalidArgumentException $e ) {
			return '';
		}

		// Pack counter as big-endian 64-bit integer.
		$msg  = pack( 'N*', 0 ) . pack( 'N*', $counter );
		$hash = hash_hmac( self::ALGORITHM, $msg, $key, true );

		// Dynamic truncation.
		$offset = ord( $hash[19] ) & 0x0F;
		$code   = (
			( ord( $hash[ $offset ] )     & 0x7F ) << 24 |
			( ord( $hash[ $offset + 1 ] ) & 0xFF ) << 16 |
			( ord( $hash[ $offset + 2 ] ) & 0xFF ) <<  8 |
			( ord( $hash[ $offset + 3 ] ) & 0xFF )
		) % ( 10 ** self::DIGITS );

		return str_pad( (string) $code, self::DIGITS, '0', STR_PAD_LEFT );
	}

	// -----------------------------------------------------------------------
	// Secret storage helpers
	// -----------------------------------------------------------------------

	private static function get_secret( int $user_id ): string {
		$encrypted = get_user_meta( $user_id, '_oosoft_2fa_totp_secret', true );
		if ( empty( $encrypted ) ) {
			return '';
		}
		try {
			return OOSOFT_2FA_Crypto::decrypt( $encrypted );
		} catch ( RuntimeException $e ) {
			OOSOFT_2FA_Logger::log( 'totp_decrypt_error', OOSOFT_2FA_Logger::ERROR, $user_id );
			return '';
		}
	}

	// -----------------------------------------------------------------------
	// Replay protection
	// -----------------------------------------------------------------------

	private static function is_code_used( int $user_id, int $time_step ): bool {
		$used = get_user_meta( $user_id, '_oosoft_2fa_totp_used_steps', true );
		$used = is_array( $used ) ? $used : [];
		return in_array( $time_step, $used, true );
	}

	private static function mark_code_used( int $user_id, int $time_step ): void {
		$used = get_user_meta( $user_id, '_oosoft_2fa_totp_used_steps', true );
		$used = is_array( $used ) ? $used : [];

		$used[] = $time_step;

		// Prune steps older than 3 periods to keep the list small.
		$min  = (int) floor( time() / self::PERIOD ) - 3;
		$used = array_filter( $used, fn( $s ) => $s >= $min );

		update_user_meta( $user_id, '_oosoft_2fa_totp_used_steps', array_values( $used ) );
	}
}
