<?php
/**
 * Backup codes — one-time emergency recovery codes.
 *
 * Generates a set of secure single-use codes stored as bcrypt hashes.
 * Each code can only be used once; once all codes are consumed the user
 * must regenerate.
 *
 * @package OOSoft2FA
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class OOSOFT_2FA_Backup_Codes {

	private const META_KEY   = '_oosoft_2fa_backup_codes';
	private const CODE_COUNT = 10;
	private const CODE_BYTES = 5; // 10 hex chars per code.

	/**
	 * Generate and store a fresh set of backup codes for a user.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return string[] Plain-text codes (shown once; never stored in plaintext).
	 */
	public static function generate( int $user_id ): array {
		$plain_codes = [];
		$hashed      = [];

		for ( $i = 0; $i < self::CODE_COUNT; $i++ ) {
			$code          = strtoupper( bin2hex( random_bytes( self::CODE_BYTES ) ) );
			$plain_codes[] = $code;
			$hashed[]      = [
				'hash' => wp_hash_password( $code ),
				'used' => false,
			];
		}

		update_user_meta( $user_id, self::META_KEY, $hashed );
		OOSOFT_2FA_Logger::log( 'backup_codes_generated', OOSOFT_2FA_Logger::INFO, $user_id );

		return $plain_codes;
	}

	/**
	 * Verify a user-supplied backup code.
	 *
	 * Iterates all unused codes and checks the hash. Marks the matching
	 * code as used so it cannot be reused.
	 *
	 * @param int    $user_id WordPress user ID.
	 * @param string $code    Code supplied by the user (raw, no formatting).
	 * @return bool True if a valid, unused code was found.
	 */
	public static function verify( int $user_id, string $code ): bool {
		// Normalise: uppercase, strip spaces/dashes.
		$code  = strtoupper( preg_replace( '/[\s\-]/', '', sanitize_text_field( $code ) ) );
		$codes = get_user_meta( $user_id, self::META_KEY, true );

		if ( ! is_array( $codes ) || empty( $codes ) ) {
			return false;
		}

		$matched = false;
		foreach ( $codes as &$entry ) {
			if ( $entry['used'] ) {
				continue;
			}
			if ( wp_check_password( $code, $entry['hash'] ) ) {
				$entry['used'] = true;
				$matched       = true;
				break;
			}
		}
		unset( $entry );

		if ( $matched ) {
			update_user_meta( $user_id, self::META_KEY, $codes );
			OOSOFT_2FA_Logger::log( 'backup_code_used', OOSOFT_2FA_Logger::WARNING, $user_id );
		}

		return $matched;
	}

	/**
	 * Count how many unused backup codes remain.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return int
	 */
	public static function remaining_count( int $user_id ): int {
		$codes = get_user_meta( $user_id, self::META_KEY, true );
		if ( ! is_array( $codes ) ) {
			return 0;
		}
		return count( array_filter( $codes, fn( $c ) => ! $c['used'] ) );
	}

	/**
	 * Check whether the user has any backup codes.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return bool
	 */
	public static function has_codes( int $user_id ): bool {
		return self::remaining_count( $user_id ) > 0;
	}

	/**
	 * Wipe all backup codes for a user.
	 *
	 * @param int $user_id WordPress user ID.
	 */
	public static function delete( int $user_id ): void {
		delete_user_meta( $user_id, self::META_KEY );
	}
}
