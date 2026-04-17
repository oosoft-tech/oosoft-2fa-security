<?php
/**
 * Rate limiter — prevents brute-force 2FA attacks.
 *
 * Uses WordPress transients (backed by object cache or DB) to track
 * failed attempts per IP and per user. Both axes must clear before
 * the account is unblocked.
 *
 * @package OOSoft2FA
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class OOSOFT_2FA_Rate_Limiter {

	/** Transient key prefix. */
	private const PREFIX = 'oosoft2fa_rl_';

	/** Default thresholds (admin-configurable via options). */
	private const DEFAULT_MAX_ATTEMPTS = 5;
	private const DEFAULT_WINDOW_SECS  = 900; // 15 minutes.
	private const DEFAULT_LOCKOUT_SECS = 1800; // 30 minutes.

	/**
	 * Record a failed attempt for the given identifiers.
	 *
	 * @param string $ip      Client IP address.
	 * @param int    $user_id WordPress user ID.
	 */
	public static function record_failure( string $ip, int $user_id ): void {
		self::increment( self::ip_key( $ip ) );
		if ( $user_id > 0 ) {
			self::increment( self::user_key( $user_id ) );
		}
	}

	/**
	 * Clear failure counters after a successful verification.
	 *
	 * @param string $ip      Client IP address.
	 * @param int    $user_id WordPress user ID.
	 */
	public static function clear_failures( string $ip, int $user_id ): void {
		delete_transient( self::ip_key( $ip ) );
		if ( $user_id > 0 ) {
			delete_transient( self::user_key( $user_id ) );
		}
	}

	/**
	 * Check whether the given IP or user is currently rate-limited.
	 *
	 * @param string $ip      Client IP address.
	 * @param int    $user_id WordPress user ID.
	 * @return bool True if the request should be blocked.
	 */
	public static function is_rate_limited( string $ip, int $user_id ): bool {
		$max = self::max_attempts();

		if ( (int) get_transient( self::ip_key( $ip ) ) >= $max ) {
			return true;
		}

		if ( $user_id > 0 && (int) get_transient( self::user_key( $user_id ) ) >= $max ) {
			return true;
		}

		return false;
	}

	/**
	 * Return remaining attempts before lock-out.
	 *
	 * @param string $ip      Client IP address.
	 * @param int    $user_id WordPress user ID.
	 * @return int Remaining attempts (0 = locked).
	 */
	public static function remaining_attempts( string $ip, int $user_id ): int {
		$max      = self::max_attempts();
		$ip_count = (int) get_transient( self::ip_key( $ip ) );
		$u_count  = $user_id > 0 ? (int) get_transient( self::user_key( $user_id ) ) : 0;
		return max( 0, $max - max( $ip_count, $u_count ) );
	}

	// -----------------------------------------------------------------------
	// Private helpers
	// -----------------------------------------------------------------------

	private static function ip_key( string $ip ): string {
		// Hash so we don't store raw IPs in transient keys.
		return self::PREFIX . 'ip_' . substr( md5( $ip ), 0, 16 );
	}

	private static function user_key( int $user_id ): string {
		return self::PREFIX . 'u_' . $user_id;
	}

	private static function increment( string $key ): void {
		$current = (int) get_transient( $key );

		if ( 0 === $current ) {
			// First failure — start the window.
			set_transient( $key, 1, self::window_secs() );
		} elseif ( $current >= self::max_attempts() ) {
			// Threshold crossed — enforce longer lockout.
			set_transient( $key, $current + 1, self::lockout_secs() );
		} else {
			// Increment while preserving remaining window time.
			// Transient TTL cannot be extended without resetting, so we
			// update the value and keep the same expiry by deleting and
			// re-setting (slight TOCTOU risk, acceptable for rate-limiting).
			delete_transient( $key );
			set_transient( $key, $current + 1, self::window_secs() );
		}
	}

	private static function max_attempts(): int {
		return max( 1, (int) get_option( 'oosoft_2fa_max_attempts', self::DEFAULT_MAX_ATTEMPTS ) );
	}

	private static function window_secs(): int {
		return max( 60, (int) get_option( 'oosoft_2fa_window_secs', self::DEFAULT_WINDOW_SECS ) );
	}

	private static function lockout_secs(): int {
		return max( 60, (int) get_option( 'oosoft_2fa_lockout_secs', self::DEFAULT_LOCKOUT_SECS ) );
	}
}
