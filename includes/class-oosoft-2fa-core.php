<?php
/**
 * Plugin core — singleton that bootstraps all sub-systems.
 *
 * @package OOSoft2FA
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class OOSOFT_2FA_Core {

	/** Singleton instance. */
	private static ?self $instance = null;

	/** Cached sub-system objects. */
	private OOSOFT_2FA_Admin  $admin;
	private OOSOFT_2FA_Public $public_handler;

	// -----------------------------------------------------------------------
	// Singleton
	// -----------------------------------------------------------------------

	private function __construct() {}

	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	// -----------------------------------------------------------------------
	// Bootstrap
	// -----------------------------------------------------------------------

	/**
	 * Initialise hooks. Called on plugins_loaded.
	 */
	public function init(): void {
		load_plugin_textdomain( 'oosoft-2fa', false, dirname( OOSOFT_2FA_PLUGIN_BASENAME ) . '/languages' );

		$this->admin          = new OOSOFT_2FA_Admin();
		$this->public_handler = new OOSOFT_2FA_Public();

		$this->admin->init();
		$this->public_handler->init();

		// Schedule daily log-pruning event.
		if ( ! wp_next_scheduled( 'oosoft_2fa_daily_cron' ) ) {
			wp_schedule_event( time(), 'daily', 'oosoft_2fa_daily_cron' );
		}
		add_action( 'oosoft_2fa_daily_cron', [ $this, 'run_daily_tasks' ] );
	}

	/**
	 * Daily maintenance tasks.
	 */
	public function run_daily_tasks(): void {
		$retention = (int) get_option( 'oosoft_2fa_log_retention_days', 90 );
		OOSOFT_2FA_Logger::purge_old_logs( $retention );
	}

	// -----------------------------------------------------------------------
	// Activation / Deactivation
	// -----------------------------------------------------------------------

	public static function activate(): void {
		OOSOFT_2FA_Logger::create_table();
		self::set_default_options();

		// Flush rewrite rules in case any custom endpoints are added later.
		flush_rewrite_rules();
	}

	public static function deactivate(): void {
		wp_clear_scheduled_hook( 'oosoft_2fa_daily_cron' );
	}

	// -----------------------------------------------------------------------
	// Default options
	// -----------------------------------------------------------------------

	private static function set_default_options(): void {
		$defaults = [
			'oosoft_2fa_enabled'              => true,
			'oosoft_2fa_forced_roles'          => [ 'administrator' ],
			'oosoft_2fa_email_otp_enabled'     => true,
			'oosoft_2fa_email_otp_expiry'      => 600,
			'oosoft_2fa_max_attempts'          => 5,
			'oosoft_2fa_window_secs'           => 900,
			'oosoft_2fa_lockout_secs'          => 1800,
			'oosoft_2fa_log_retention_days'    => 90,
			'oosoft_2fa_trust_proxy_headers'   => false,
			'oosoft_2fa_redirect_after_login'  => admin_url(),
		];

		foreach ( $defaults as $key => $value ) {
			if ( false === get_option( $key ) ) {
				add_option( $key, $value, '', 'no' ); // 'no' = not autoloaded.
			}
		}
	}
}
