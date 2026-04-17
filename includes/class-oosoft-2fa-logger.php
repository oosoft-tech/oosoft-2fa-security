<?php
/**
 * Security event logger.
 *
 * Writes structured log entries to a custom DB table and optionally to
 * the PHP error log. Provides query helpers for the admin log viewer.
 *
 * @package OOSoft2FA
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class OOSOFT_2FA_Logger {

	/** DB table name (without prefix). */
	const TABLE = 'oosoft_2fa_logs';

	// Event severity levels.
	const INFO    = 'info';
	const WARNING = 'warning';
	const ERROR   = 'error';

	/**
	 * Log a security event.
	 *
	 * @param string   $event   Short event identifier (e.g. 'totp_success').
	 * @param string   $level   Severity: info | warning | error.
	 * @param int|null $user_id WordPress user ID (0 for unauthenticated).
	 * @param array    $context Additional key-value context data.
	 */
	public static function log( string $event, string $level = self::INFO, int $user_id = 0, array $context = [] ): void {
		global $wpdb;

		$table = $wpdb->prefix . self::TABLE;

		// Sanitize level.
		$level = in_array( $level, [ self::INFO, self::WARNING, self::ERROR ], true ) ? $level : self::INFO;

		// Capture IP safely (respects proxy headers set by admin).
		$ip = self::get_client_ip();

		$data = [
			'event'      => sanitize_key( $event ),
			'level'      => $level,
			'user_id'    => absint( $user_id ),
			'ip_address' => sanitize_text_field( $ip ),
			'user_agent' => sanitize_text_field( isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ), 0, 255 ) : '' ), // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
			'context'    => wp_json_encode( $context ),
			'created_at' => current_time( 'mysql', true ), // UTC.
		];

		$formats = [ '%s', '%s', '%d', '%s', '%s', '%s', '%s' ];

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$result = $wpdb->insert( $table, $data, $formats );

		if ( false === $result ) {
			// Fall back to PHP error log so events are never silently lost.
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			error_log( sprintf(
				'[OOSOFT 2FA] %s | %s | user=%d | ip=%s | %s',
				strtoupper( $level ),
				$event,
				$user_id,
				$ip,
				wp_json_encode( $context )
			) );
		}
	}

	/**
	 * Retrieve log entries with optional filters and pagination.
	 *
	 * @param array $args {
	 *     @type string $level    Filter by severity level.
	 *     @type int    $user_id  Filter by user.
	 *     @type int    $per_page Rows per page (default 50, max 200).
	 *     @type int    $page     1-based page number.
	 * }
	 * @return array { 'items' => array, 'total' => int }
	 */
	public static function get_logs( array $args = [] ): array {
		global $wpdb;

		$table    = $wpdb->prefix . self::TABLE;
		$per_page = min( absint( $args['per_page'] ?? 50 ), 200 );
		$page     = max( 1, absint( $args['page'] ?? 1 ) );
		$offset   = ( $page - 1 ) * $per_page;

		$where  = '1=1';
		$params = [];

		if ( ! empty( $args['level'] ) ) {
			$where   .= ' AND level = %s';
			$params[] = sanitize_text_field( $args['level'] );
		}

		if ( ! empty( $args['user_id'] ) ) {
			$where   .= ' AND user_id = %d';
			$params[] = absint( $args['user_id'] );
		}

		// Count query.
		$count_sql = "SELECT COUNT(*) FROM {$table} WHERE {$where}"; // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
		$total = empty( $params ) ? (int) $wpdb->get_var( $count_sql ) : (int) $wpdb->get_var( $wpdb->prepare( $count_sql, ...$params ) );

		// Data query.
		$params[] = $per_page;
		$params[] = $offset;
		$sql      = "SELECT * FROM {$table} WHERE {$where} ORDER BY id DESC LIMIT %d OFFSET %d"; // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
		$items = $wpdb->get_results( $wpdb->prepare( $sql, ...$params ) );

		return [
			'items' => $items ?: [],
			'total' => $total,
		];
	}

	/**
	 * Purge log entries older than $days days.
	 *
	 * @param int $days Retention period in days (default 90).
	 */
	public static function purge_old_logs( int $days = 90 ): void {
		global $wpdb;
		$table = $wpdb->prefix . self::TABLE;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query( $wpdb->prepare(
			"DELETE FROM {$table} WHERE created_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d DAY)", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$days
		) );
	}

	/**
	 * Create the logs table on activation.
	 */
	public static function create_table(): void {
		global $wpdb;

		$table       = $wpdb->prefix . self::TABLE;
		$charset_col = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE IF NOT EXISTS {$table} (
			id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			event       VARCHAR(100)    NOT NULL DEFAULT '',
			level       ENUM('info','warning','error') NOT NULL DEFAULT 'info',
			user_id     BIGINT UNSIGNED NOT NULL DEFAULT 0,
			ip_address  VARCHAR(45)     NOT NULL DEFAULT '',
			user_agent  VARCHAR(255)    NOT NULL DEFAULT '',
			context     LONGTEXT,
			created_at  DATETIME        NOT NULL,
			PRIMARY KEY (id),
			KEY idx_event   (event),
			KEY idx_user_id (user_id),
			KEY idx_level   (level),
			KEY idx_created (created_at)
		) {$charset_col};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}

	// -----------------------------------------------------------------------
	// Private helpers
	// -----------------------------------------------------------------------

	/**
	 * Returns the most reliable client IP address.
	 * Only trusts proxy headers when the plugin option says to.
	 */
	private static function get_client_ip(): string {
		$trust_proxy = (bool) get_option( 'oosoft_2fa_trust_proxy_headers', false );

		if ( $trust_proxy ) {
			$headers = [
				'HTTP_CF_CONNECTING_IP', // Cloudflare.
				'HTTP_X_FORWARDED_FOR',
				'HTTP_X_REAL_IP',
			];
			foreach ( $headers as $h ) {
				if ( ! empty( $_SERVER[ $h ] ) ) {
					// X-Forwarded-For can be a CSV list; take the first.
					$ip = trim( explode( ',', sanitize_text_field( wp_unslash( $_SERVER[ $h ] ) ) )[0] );
					if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
						return $ip;
					}
				}
			}
		}

		$remote = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		return filter_var( $remote, FILTER_VALIDATE_IP ) ? $remote : '0.0.0.0';
	}
}
