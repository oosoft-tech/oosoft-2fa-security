<?php
/**
 * Email OTP — fallback second factor.
 *
 * Sends a time-limited numeric OTP to the user's registered email address.
 * The OTP hash is stored in a transient (not the raw code) so the DB
 * cannot be used to recover the OTP even if compromised.
 *
 * @package OOSoft2FA
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class OOSOFT_2FA_Email_OTP {

	private const TRANSIENT_PREFIX = 'oosoft2fa_email_otp_';
	private const DEFAULT_EXPIRY   = 600; // 10 minutes.
	private const DIGITS           = 6;
	private const MAX_SEND_RATE    = 3;   // Max OTPs per window.
	private const SEND_WINDOW      = 300; // 5 minutes.

	/**
	 * Generate and send an OTP to the user's email.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return bool True on successful send.
	 */
	public static function send( int $user_id ): bool {
		$user = get_userdata( $user_id );
		if ( ! $user || ! is_email( $user->user_email ) ) {
			OOSOFT_2FA_Logger::log( 'email_otp_invalid_user', OOSOFT_2FA_Logger::ERROR, $user_id );
			return false;
		}

		// Rate-limit sends to prevent OTP spam.
		if ( self::is_send_rate_exceeded( $user_id ) ) {
			OOSOFT_2FA_Logger::log( 'email_otp_send_rate_exceeded', OOSOFT_2FA_Logger::WARNING, $user_id );
			return false;
		}

		$otp     = OOSOFT_2FA_Crypto::generate_numeric_otp( self::DIGITS );
		$expiry  = (int) get_option( 'oosoft_2fa_email_otp_expiry', self::DEFAULT_EXPIRY );
		$hash    = wp_hash( $otp . $user_id ); // One-way hash; raw OTP is never stored.

		set_transient( self::otp_key( $user_id ), $hash, $expiry );
		self::increment_send_count( $user_id );

		$sent = self::deliver_email( $user, $otp, $expiry );

		if ( $sent ) {
			OOSOFT_2FA_Logger::log( 'email_otp_sent', OOSOFT_2FA_Logger::INFO, $user_id );
		} else {
			OOSOFT_2FA_Logger::log( 'email_otp_send_failed', OOSOFT_2FA_Logger::ERROR, $user_id );
		}

		return $sent;
	}

	/**
	 * Verify a user-supplied OTP code.
	 *
	 * @param int    $user_id WordPress user ID.
	 * @param string $code    Code supplied by the user.
	 * @return bool
	 */
	public static function verify( int $user_id, string $code ): bool {
		$code = preg_replace( '/\D/', '', sanitize_text_field( $code ) );

		if ( strlen( $code ) !== self::DIGITS ) {
			return false;
		}

		$stored = get_transient( self::otp_key( $user_id ) );

		if ( false === $stored ) {
			return false; // Expired or never sent.
		}

		$expected = wp_hash( $code . $user_id );

		if ( hash_equals( $expected, $stored ) ) {
			// Invalidate immediately (single-use).
			delete_transient( self::otp_key( $user_id ) );
			return true;
		}

		return false;
	}

	/**
	 * Invalidate any pending OTP for a user.
	 *
	 * @param int $user_id WordPress user ID.
	 */
	public static function invalidate( int $user_id ): void {
		delete_transient( self::otp_key( $user_id ) );
	}

	// -----------------------------------------------------------------------
	// Private helpers
	// -----------------------------------------------------------------------

	private static function otp_key( int $user_id ): string {
		return self::TRANSIENT_PREFIX . $user_id;
	}

	private static function send_count_key( int $user_id ): string {
		return self::TRANSIENT_PREFIX . 'rate_' . $user_id;
	}

	private static function is_send_rate_exceeded( int $user_id ): bool {
		return (int) get_transient( self::send_count_key( $user_id ) ) >= self::MAX_SEND_RATE;
	}

	private static function increment_send_count( int $user_id ): void {
		$key     = self::send_count_key( $user_id );
		$current = (int) get_transient( $key );
		delete_transient( $key );
		set_transient( $key, $current + 1, self::SEND_WINDOW );
	}

	private static function deliver_email( WP_User $user, string $otp, int $expiry ): bool {
		$site_name   = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$expiry_mins = ceil( $expiry / 60 );

		$subject = sprintf(
			/* translators: %s: site name */
			__( '[%s] Your two-factor authentication code', 'oosoft-2fa-security' ),
			$site_name
		);

		$message = sprintf(
			/* translators: 1: user display name, 2: site name, 3: OTP code, 4: expiry minutes */
			__(
				"Hello %1\$s,\n\n" .
				"Your two-factor authentication code for %2\$s is:\n\n" .
				"    %3\$s\n\n" .
				"This code expires in %4\$d minute(s).\n\n" .
				"If you did not attempt to log in, please change your password immediately.\n\n" .
				"-- %2\$s Security Team",
				'oosoft-2fa-security'
			),
			esc_html( $user->display_name ),
			esc_html( $site_name ),
			$otp, // Numeric only — no HTML context.
			$expiry_mins
		);

		$headers = [ 'Content-Type: text/plain; charset=UTF-8' ];

		return wp_mail( $user->user_email, $subject, $message, $headers );
	}
}
