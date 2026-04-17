<?php
/**
 * User 2FA status manager.
 *
 * Centralises all queries about a user's 2FA configuration and
 * determines which method(s) are available or required.
 *
 * @package OOSoft2FA
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class OOSOFT_2FA_User_Manager {

	/** Session transient prefix — stores interim auth state between login and 2FA. */
	private const SESSION_PREFIX = 'oosoft2fa_session_';
	private const SESSION_TTL    = 600; // 10 minutes.

	// Available 2FA methods.
	const METHOD_TOTP    = 'totp';
	const METHOD_EMAIL   = 'email';
	const METHOD_BACKUP  = 'backup';

	// -----------------------------------------------------------------------
	// 2FA requirement checks
	// -----------------------------------------------------------------------

	/**
	 * Check whether 2FA is required for a given user.
	 *
	 * A user requires 2FA if:
	 *  - the plugin is globally enabled AND
	 *  - either the user's role is in the forced-roles list, or the user
	 *    has voluntarily enabled 2FA for their account.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return bool
	 */
	public static function requires_2fa( int $user_id ): bool {
		if ( ! get_option( 'oosoft_2fa_enabled', true ) ) {
			return false;
		}

		// Check forced roles.
		if ( self::is_role_forced( $user_id ) ) {
			return true;
		}

		// User opted in.
		return '1' === get_user_meta( $user_id, '_oosoft_2fa_opted_in', true );
	}

	/**
	 * Check whether any 2FA method is configured for the user.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return bool
	 */
	public static function has_2fa_configured( int $user_id ): bool {
		return OOSOFT_2FA_TOTP::is_enabled( $user_id )
			|| self::email_otp_available( $user_id )
			|| OOSOFT_2FA_Backup_Codes::has_codes( $user_id );
	}

	/**
	 * Return which methods are available for a user, in preferred order.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return string[] Array of method constants.
	 */
	public static function available_methods( int $user_id ): array {
		$methods = [];

		if ( OOSOFT_2FA_TOTP::is_enabled( $user_id ) ) {
			$methods[] = self::METHOD_TOTP;
		}

		if ( self::email_otp_available( $user_id ) ) {
			$methods[] = self::METHOD_EMAIL;
		}

		if ( OOSOFT_2FA_Backup_Codes::has_codes( $user_id ) ) {
			$methods[] = self::METHOD_BACKUP;
		}

		return $methods;
	}

	/**
	 * Determine the preferred (primary) method for a user.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return string|null Method constant or null if none configured.
	 */
	public static function preferred_method( int $user_id ): ?string {
		$methods = self::available_methods( $user_id );
		return $methods[0] ?? null;
	}

	// -----------------------------------------------------------------------
	// Interim auth session (state between credential check and 2FA)
	// -----------------------------------------------------------------------

	/**
	 * Create a secure short-lived session token after password verification.
	 *
	 * The token is stored in a transient keyed to a secure random ID.
	 * The browser holds the token in a session cookie (set by the public class).
	 *
	 * @param int    $user_id  WordPress user ID.
	 * @param string $redirect URL to redirect to after successful 2FA.
	 * @return string Opaque session token.
	 */
	public static function create_interim_session( int $user_id, string $redirect = '' ): string {
		$token = bin2hex( random_bytes( 32 ) );
		$data  = [
			'user_id'  => $user_id,
			'redirect' => esc_url_raw( $redirect ),
			'created'  => time(),
		];
		set_transient( self::SESSION_PREFIX . $token, $data, self::SESSION_TTL );
		return $token;
	}

	/**
	 * Validate and retrieve the interim session data.
	 *
	 * @param string $token Session token from cookie.
	 * @return array|null Session data or null if invalid/expired.
	 */
	public static function get_interim_session( string $token ): ?array {
		if ( ! ctype_xdigit( $token ) || strlen( $token ) !== 64 ) {
			return null;
		}
		$data = get_transient( self::SESSION_PREFIX . $token );
		return is_array( $data ) ? $data : null;
	}

	/**
	 * Destroy the interim session (call after successful or failed 2FA).
	 *
	 * @param string $token Session token.
	 */
	public static function destroy_interim_session( string $token ): void {
		delete_transient( self::SESSION_PREFIX . $token );
	}

	// -----------------------------------------------------------------------
	// Helpers
	// -----------------------------------------------------------------------

	/**
	 * Check whether the user belongs to a role that has forced 2FA.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return bool
	 */
	public static function is_role_forced( int $user_id ): bool {
		$forced_roles = (array) get_option( 'oosoft_2fa_forced_roles', [] );
		if ( empty( $forced_roles ) ) {
			return false;
		}

		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return false;
		}

		foreach ( $user->roles as $role ) {
			if ( in_array( $role, $forced_roles, true ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Check whether email OTP is a usable method for this user.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return bool
	 */
	public static function email_otp_available( int $user_id ): bool {
		if ( ! get_option( 'oosoft_2fa_email_otp_enabled', true ) ) {
			return false;
		}
		$user = get_userdata( $user_id );
		return $user && is_email( $user->user_email );
	}

	/**
	 * Set whether the user has opted into 2FA voluntarily.
	 *
	 * @param int  $user_id WordPress user ID.
	 * @param bool $opted_in True to opt in.
	 */
	public static function set_opted_in( int $user_id, bool $opted_in ): void {
		update_user_meta( $user_id, '_oosoft_2fa_opted_in', $opted_in ? '1' : '0' );
	}
}
