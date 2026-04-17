<?php
/**
 * Admin panel — settings, log viewer, and user profile integration.
 *
 * @package OOSoft2FA
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class OOSOFT_2FA_Admin {

	private const SETTINGS_PAGE  = 'oosoft-2fa-settings';
	private const SETTINGS_GROUP = 'oosoft_2fa_settings';
	private const LOGS_PAGE      = 'oosoft-2fa-logs';
	private const CAPABILITY      = 'manage_options';

	// -----------------------------------------------------------------------
	// Boot
	// -----------------------------------------------------------------------

	public function init(): void {
		add_action( 'admin_menu',              [ $this, 'register_menus' ] );
		add_action( 'admin_init',              [ $this, 'register_settings' ] );
		add_action( 'admin_enqueue_scripts',   [ $this, 'enqueue_assets' ] );

		// User profile 2FA management.
		add_action( 'show_user_profile',       [ $this, 'render_user_profile_section' ] );
		add_action( 'edit_user_profile',       [ $this, 'render_user_profile_section' ] );
		add_action( 'personal_options_update', [ $this, 'save_user_profile' ] );
		add_action( 'edit_user_profile_update',[ $this, 'save_user_profile' ] );

		// AJAX: generate QR code data.
		add_action( 'wp_ajax_oosoft_2fa_setup_totp',    [ $this, 'ajax_setup_totp' ] );
		add_action( 'wp_ajax_oosoft_2fa_confirm_totp',  [ $this, 'ajax_confirm_totp' ] );
		add_action( 'wp_ajax_oosoft_2fa_disable_totp',  [ $this, 'ajax_disable_totp' ] );
		add_action( 'wp_ajax_oosoft_2fa_gen_backup',    [ $this, 'ajax_generate_backup_codes' ] );
		add_action( 'wp_ajax_oosoft_2fa_diagnose',      [ $this, 'ajax_diagnose' ] );

		// Admin notice: force-2FA users who haven't configured it.
		add_action( 'admin_notices',           [ $this, 'maybe_show_setup_notice' ] );
	}

	// -----------------------------------------------------------------------
	// Menus
	// -----------------------------------------------------------------------

	public function register_menus(): void {
		add_menu_page(
			__( 'OOSOFT 2FA Security', 'oosoft-2fa-security' ),
			__( '2FA Security', 'oosoft-2fa-security' ),
			self::CAPABILITY,
			self::SETTINGS_PAGE,
			[ $this, 'render_settings_page' ],
			'dashicons-shield',
			80
		);

		add_submenu_page(
			self::SETTINGS_PAGE,
			__( 'Settings', 'oosoft-2fa-security' ),
			__( 'Settings', 'oosoft-2fa-security' ),
			self::CAPABILITY,
			self::SETTINGS_PAGE,
			[ $this, 'render_settings_page' ]
		);

		add_submenu_page(
			self::SETTINGS_PAGE,
			__( 'Security Logs', 'oosoft-2fa-security' ),
			__( 'Logs', 'oosoft-2fa-security' ),
			self::CAPABILITY,
			self::LOGS_PAGE,
			[ $this, 'render_logs_page' ]
		);
	}

	// -----------------------------------------------------------------------
	// Settings registration
	// -----------------------------------------------------------------------

	public function register_settings(): void {
		// General section.
		add_settings_section(
			'oosoft_2fa_general',
			__( 'General Settings', 'oosoft-2fa-security' ),
			'__return_null',
			self::SETTINGS_PAGE
		);

		$fields = [
			[
				'id'       => 'oosoft_2fa_enabled',
				'label'    => __( 'Enable 2FA Plugin', 'oosoft-2fa-security' ),
				'type'     => 'checkbox',
				'sanitize' => fn( $v ) => (bool) $v,
			],
			[
				'id'       => 'oosoft_2fa_forced_roles',
				'label'    => __( 'Force 2FA for Roles', 'oosoft-2fa-security' ),
				'type'     => 'roles',
				'sanitize' => fn( $v ) => array_map( 'sanitize_key', (array) $v ),
			],
			[
				'id'       => 'oosoft_2fa_email_otp_enabled',
				'label'    => __( 'Allow Email OTP Fallback', 'oosoft-2fa-security' ),
				'type'     => 'checkbox',
				'sanitize' => fn( $v ) => (bool) $v,
			],
			[
				'id'       => 'oosoft_2fa_email_otp_expiry',
				'label'    => __( 'Email OTP Expiry (seconds)', 'oosoft-2fa-security' ),
				'type'     => 'number',
				'sanitize' => fn( $v ) => max( 60, min( 3600, absint( $v ) ) ),
			],
			[
				'id'       => 'oosoft_2fa_max_attempts',
				'label'    => __( 'Max Failed Attempts', 'oosoft-2fa-security' ),
				'type'     => 'number',
				'sanitize' => fn( $v ) => max( 1, min( 20, absint( $v ) ) ),
			],
			[
				'id'       => 'oosoft_2fa_window_secs',
				'label'    => __( 'Failure Window (seconds)', 'oosoft-2fa-security' ),
				'type'     => 'number',
				'sanitize' => fn( $v ) => max( 60, min( 3600, absint( $v ) ) ),
			],
			[
				'id'       => 'oosoft_2fa_lockout_secs',
				'label'    => __( 'Lockout Duration (seconds)', 'oosoft-2fa-security' ),
				'type'     => 'number',
				'sanitize' => fn( $v ) => max( 60, min( 86400, absint( $v ) ) ),
			],
			[
				'id'       => 'oosoft_2fa_log_retention_days',
				'label'    => __( 'Log Retention (days)', 'oosoft-2fa-security' ),
				'type'     => 'number',
				'sanitize' => fn( $v ) => max( 7, min( 365, absint( $v ) ) ),
			],
			[
				'id'       => 'oosoft_2fa_trust_proxy_headers',
				'label'    => __( 'Trust Proxy Headers (Cloudflare / load balancer)', 'oosoft-2fa-security' ),
				'type'     => 'checkbox',
				'sanitize' => fn( $v ) => (bool) $v,
			],
		];

		foreach ( $fields as $field ) {
			register_setting(
				self::SETTINGS_GROUP,
				$field['id'],
				[
					'sanitize_callback' => $field['sanitize'],
					'type'              => $field['type'] === 'number' ? 'integer' : 'string',
				]
			);

			add_settings_field(
				$field['id'],
				$field['label'],
				[ $this, 'render_field_' . $field['type'] ],
				self::SETTINGS_PAGE,
				'oosoft_2fa_general',
				[ 'id' => $field['id'] ]
			);
		}
	}

	// -----------------------------------------------------------------------
	// Field renderers
	// -----------------------------------------------------------------------

	public function render_field_checkbox( array $args ): void {
		printf(
			'<input type="checkbox" id="%s" name="%s" value="1" %s>',
			esc_attr( $args['id'] ),
			esc_attr( $args['id'] ),
			checked( true, (bool) get_option( $args['id'] ), false )
		);
	}

	public function render_field_number( array $args ): void {
		printf(
			'<input type="number" id="%s" name="%s" value="%d" min="1" class="small-text">',
			esc_attr( $args['id'] ),
			esc_attr( $args['id'] ),
			absint( get_option( $args['id'] ) )
		);
	}

	public function render_field_roles( array $args ): void {
		$id      = esc_attr( $args['id'] );
		$saved   = (array) get_option( $args['id'], [] );
		$roles   = wp_roles()->get_names();

		echo '<fieldset>';
		foreach ( $roles as $slug => $name ) {
			printf(
				'<label><input type="checkbox" name="%s[]" value="%s" %s> %s</label><br>',
				esc_attr( $id ),
				esc_attr( $slug ),
				checked( in_array( $slug, $saved, true ), true, false ),
				esc_html( translate_user_role( $name ) )
			);
		}
		echo '</fieldset>';
	}

	// -----------------------------------------------------------------------
	// Page renderers
	// -----------------------------------------------------------------------

	public function render_settings_page(): void {
		if ( ! current_user_can( self::CAPABILITY ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'oosoft-2fa-security' ) );
		}
		require OOSOFT_2FA_PLUGIN_DIR . 'admin/views/admin-settings.php';
	}

	public function render_logs_page(): void {
		if ( ! current_user_can( self::CAPABILITY ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'oosoft-2fa-security' ) );
		}
		require OOSOFT_2FA_PLUGIN_DIR . 'admin/views/admin-logs.php';
	}

	// -----------------------------------------------------------------------
	// User profile section
	// -----------------------------------------------------------------------

	public function render_user_profile_section( WP_User $profile_user ): void {
		// Each user can manage their own 2FA; admins can manage any user.
		if ( get_current_user_id() !== $profile_user->ID && ! current_user_can( 'edit_users' ) ) {
			return;
		}
		require OOSOFT_2FA_PLUGIN_DIR . 'admin/views/user-profile.php';
	}

	public function save_user_profile( int $user_id ): void {
		if ( ! current_user_can( 'edit_user', $user_id ) ) {
			return;
		}

		check_admin_referer( 'update-user_' . $user_id );

		// Save opt-in preference.
		if ( isset( $_POST['oosoft_2fa_opted_in'] ) ) {
			OOSOFT_2FA_User_Manager::set_opted_in( $user_id, (bool) $_POST['oosoft_2fa_opted_in'] );
		}
	}

	// -----------------------------------------------------------------------
	// AJAX handlers
	// -----------------------------------------------------------------------

	public function ajax_setup_totp(): void {
		check_ajax_referer( 'oosoft_2fa_setup_nonce', 'nonce' );

		$user_id = get_current_user_id();
		if ( ! $user_id ) {
			wp_send_json_error( [ 'message' => __( 'Not logged in.', 'oosoft-2fa-security' ) ], 401 );
		}

		// Users may only provision 2FA for themselves.
		if ( ! current_user_can( 'edit_user', $user_id ) ) {
			wp_send_json_error( [ 'message' => __( 'You do not have permission to perform this action.', 'oosoft-2fa-security' ) ], 403 );
		}

		try {
			$secret = OOSOFT_2FA_TOTP::provision_secret( $user_id );
		} catch ( Throwable $e ) {
			// Catch both Exception and PHP 8 Error/TypeError/ValueError subtypes.
			try {
				OOSOFT_2FA_Logger::log( 'totp_provision_error', OOSOFT_2FA_Logger::ERROR, $user_id, [
					'error' => $e->getMessage(),
					'class' => get_class( $e ),
				] );
			} catch ( Throwable $log_e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedCatch
				// Logger failure must never mask the original error.
			}
			$msg = defined( 'WP_DEBUG' ) && WP_DEBUG
				? sprintf( '[%s] %s', get_class( $e ), $e->getMessage() )
				: __( 'Could not generate secret. Check server crypto support.', 'oosoft-2fa-security' );
			wp_send_json_error( [ 'message' => $msg ] );
		}

		$uri = OOSOFT_2FA_TOTP::get_otpauth_uri( $user_id, $secret );
		// Generate QR code server-side as inline SVG (no JS library needed).
		$qr_svg = OOSOFT_2FA_QRCode::svg( $uri, 4, 4 );

		wp_send_json_success( [
			'secret' => esc_html( $secret ),
			'uri'    => $uri,    // For the manual-entry fallback link.
			'qr_svg' => $qr_svg, // Inline SVG — injected into DOM via JS.
		] );
	}

	public function ajax_confirm_totp(): void {
		check_ajax_referer( 'oosoft_2fa_setup_nonce', 'nonce' );

		$user_id = get_current_user_id();
		if ( ! $user_id ) {
			wp_send_json_error( [ 'message' => __( 'Not logged in.', 'oosoft-2fa-security' ) ], 401 );
		}

		$code = sanitize_text_field( wp_unslash( $_POST['code'] ?? '' ) );

		try {
			$confirmed = OOSOFT_2FA_TOTP::confirm_secret( $user_id, $code );
		} catch ( Throwable $e ) {
			OOSOFT_2FA_Logger::log( 'totp_confirm_error', OOSOFT_2FA_Logger::ERROR, $user_id, [ 'error' => $e->getMessage() ] );
			$msg = defined( 'WP_DEBUG' ) && WP_DEBUG
				? sprintf( '[%s] %s', get_class( $e ), $e->getMessage() )
				: __( 'Verification error. Please try again.', 'oosoft-2fa-security' );
			wp_send_json_error( [ 'message' => $msg ] );
		}

		if ( $confirmed ) {
			OOSOFT_2FA_User_Manager::set_opted_in( $user_id, true );
			wp_send_json_success( [ 'message' => __( 'Authenticator app configured successfully.', 'oosoft-2fa-security' ) ] );
		} else {
			OOSOFT_2FA_Logger::log( 'totp_confirm_failed', OOSOFT_2FA_Logger::WARNING, $user_id );
			wp_send_json_error( [ 'message' => __( 'Invalid code. Please try again.', 'oosoft-2fa-security' ) ] );
		}
	}

	public function ajax_disable_totp(): void {
		check_ajax_referer( 'oosoft_2fa_setup_nonce', 'nonce' );

		$user_id = get_current_user_id();
		// Admins may disable 2FA for another user.
		if ( isset( $_POST['user_id'] ) && current_user_can( 'edit_users' ) ) {
			$user_id = absint( $_POST['user_id'] );
		}

		if ( ! $user_id ) {
			wp_send_json_error( [], 401 );
		}

		OOSOFT_2FA_TOTP::disable( $user_id );
		wp_send_json_success( [ 'message' => __( 'TOTP disabled.', 'oosoft-2fa-security' ) ] );
	}

	public function ajax_generate_backup_codes(): void {
		check_ajax_referer( 'oosoft_2fa_setup_nonce', 'nonce' );

		$user_id = get_current_user_id();
		if ( ! $user_id ) {
			wp_send_json_error( [], 401 );
		}

		try {
			$codes = OOSOFT_2FA_Backup_Codes::generate( $user_id );
		} catch ( Throwable $e ) {
			OOSOFT_2FA_Logger::log( 'backup_gen_error', OOSOFT_2FA_Logger::ERROR, $user_id, [ 'error' => $e->getMessage() ] );
			$msg = defined( 'WP_DEBUG' ) && WP_DEBUG
				? sprintf( '[%s] %s', get_class( $e ), $e->getMessage() )
				: __( 'Could not generate backup codes. Please try again.', 'oosoft-2fa-security' );
			wp_send_json_error( [ 'message' => $msg ] );
		}

		// Format as groups of 5 characters for readability: AAAAA-BBBBB.
		$formatted = array_map( fn( $c ) => implode( '-', str_split( $c, 5 ) ), $codes );

		wp_send_json_success( [ 'codes' => $formatted ] );
	}

	// -----------------------------------------------------------------------
	// Crypto diagnostics (admin-only)
	// -----------------------------------------------------------------------

	/**
	 * AJAX handler: run per-component crypto checks and return a JSON report.
	 * Useful for diagnosing "Could not generate secret" on unusual server configs.
	 */
	public function ajax_diagnose(): void {
		check_ajax_referer( 'oosoft_2fa_setup_nonce', 'nonce' );
		if ( ! current_user_can( self::CAPABILITY ) ) {
			wp_send_json_error( [], 403 );
		}

		$report = [];

		// PHP version.
		$report['php_version'] = PHP_VERSION;

		// random_bytes.
		try {
			$rb = random_bytes( 16 );
			$report['random_bytes'] = strlen( $rb ) === 16 ? 'OK (16 bytes)' : 'FAIL: wrong length';
		} catch ( Throwable $e ) {
			$report['random_bytes'] = 'FAIL: ' . $e->getMessage();
		}

		// Sodium.
		$report['sodium_available'] = function_exists( 'sodium_crypto_secretbox' );
		if ( $report['sodium_available'] ) {
			try {
				$test_key   = str_repeat( "\x00", SODIUM_CRYPTO_SECRETBOX_KEYBYTES );
				$test_nonce = str_repeat( "\x00", SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
				$enc        = sodium_crypto_secretbox( 'test', $test_nonce, $test_key );
				$dec        = sodium_crypto_secretbox_open( $enc, $test_nonce, $test_key );
				$report['sodium_secretbox'] = ( 'test' === $dec ) ? 'OK' : 'FAIL: decrypt mismatch';
			} catch ( Throwable $e ) {
				$report['sodium_secretbox'] = 'FAIL: ' . $e->getMessage();
			}
			try {
				$k = str_repeat( 'a', SODIUM_CRYPTO_SECRETBOX_KEYBYTES );
				sodium_memzero( $k );
				$report['sodium_memzero'] = strlen( $k ) === SODIUM_CRYPTO_SECRETBOX_KEYBYTES ? 'OK' : 'FAIL: unexpected length';
			} catch ( Throwable $e ) {
				$report['sodium_memzero'] = 'FAIL: ' . $e->getMessage();
			}
		}

		// OpenSSL.
		$report['openssl_available'] = function_exists( 'openssl_encrypt' );
		if ( $report['openssl_available'] ) {
			$gcm_ciphers = openssl_get_cipher_methods();
			$report['openssl_gcm_available'] = in_array( 'aes-256-gcm', $gcm_ciphers, true );
			$report['openssl_cbc_available'] = in_array( 'aes-256-cbc', $gcm_ciphers, true );
		}

		// hash_hmac.
		$report['hash_hmac'] = function_exists( 'hash_hmac' ) ? 'OK' : 'MISSING';

		// Full encrypt/decrypt round-trip.
		try {
			$cipher    = OOSOFT_2FA_Crypto::encrypt( 'hello-2fa-test' );
			$plain     = OOSOFT_2FA_Crypto::decrypt( $cipher );
			$report['encrypt_decrypt_roundtrip'] = ( 'hello-2fa-test' === $plain ) ? 'OK' : 'FAIL: mismatch';
		} catch ( Throwable $e ) {
			$report['encrypt_decrypt_roundtrip'] = 'FAIL: [' . get_class( $e ) . '] ' . $e->getMessage();
		}

		// Base32 round-trip.
		try {
			$raw     = random_bytes( 20 );
			$enc     = OOSOFT_2FA_Crypto::base32_encode( $raw );
			$dec     = OOSOFT_2FA_Crypto::base32_decode( $enc );
			$report['base32_roundtrip'] = ( $raw === $dec ) ? 'OK' : 'FAIL: mismatch';
		} catch ( Throwable $e ) {
			$report['base32_roundtrip'] = 'FAIL: ' . $e->getMessage();
		}

		// AUTH_KEY defined.
		$report['auth_key_defined']       = defined( 'AUTH_KEY' ) && AUTH_KEY !== 'put your unique phrase here';
		$report['secure_auth_salt_defined'] = defined( 'SECURE_AUTH_SALT' ) && SECURE_AUTH_SALT !== 'put your unique phrase here';

		wp_send_json_success( $report );
	}

	// -----------------------------------------------------------------------
	// Admin notice
	// -----------------------------------------------------------------------

	public function maybe_show_setup_notice(): void {
		$user_id = get_current_user_id();
		if ( ! OOSOFT_2FA_User_Manager::is_role_forced( $user_id ) ) {
			return;
		}
		if ( OOSOFT_2FA_User_Manager::has_2fa_configured( $user_id ) ) {
			return;
		}

		$profile_url = esc_url( get_edit_profile_url( $user_id ) . '#oosoft-2fa-section' );
		echo '<div class="notice notice-warning is-dismissible"><p>' .
			wp_kses(
				sprintf(
					/* translators: %s: link to profile page */
					__( '<strong>OOSOFT 2FA:</strong> Your role requires Two-Factor Authentication. <a href="%s">Configure it now</a>.', 'oosoft-2fa-security' ),
					$profile_url
				),
				[ 'strong' => [], 'a' => [ 'href' => [] ] ]
			) .
			'</p></div>';
	}

	// -----------------------------------------------------------------------
	// Asset enqueueing
	// -----------------------------------------------------------------------

	public function enqueue_assets( string $hook ): void {
		$relevant_hooks = [
			'toplevel_page_' . self::SETTINGS_PAGE,
			'2fa-security_page_' . self::LOGS_PAGE,
			'profile.php',
			'user-edit.php',
		];

		if ( ! in_array( $hook, $relevant_hooks, true ) ) {
			return;
		}

		wp_enqueue_style(
			'oosoft-2fa-admin',
			OOSOFT_2FA_PLUGIN_URL . 'assets/css/oosoft-2fa-admin.css',
			[],
			OOSOFT_2FA_VERSION
		);

		wp_enqueue_script(
			'qrcodejs',
			OOSOFT_2FA_PLUGIN_URL . 'assets/js/qrcodejs.min.js',
			[],
			OOSOFT_2FA_VERSION,
			true
		);

		wp_enqueue_script(
			'oosoft-2fa-admin',
			OOSOFT_2FA_PLUGIN_URL . 'assets/js/oosoft-2fa-admin.js',
			[ 'jquery', 'qrcodejs' ],
			OOSOFT_2FA_VERSION,
			true
		);

		wp_localize_script( 'oosoft-2fa-admin', 'oosoft2faAdmin', [
			'ajaxUrl' => admin_url( 'admin-ajax.php' ),
			'nonce'   => wp_create_nonce( 'oosoft_2fa_setup_nonce' ),
			'i18n'    => [
				'confirmDisable'  => __( 'Are you sure you want to disable TOTP? You should generate backup codes first.', 'oosoft-2fa-security' ),
				'confirmRegenerate' => __( 'Regenerating will invalidate all existing backup codes. Continue?', 'oosoft-2fa-security' ),
				'copied'          => __( 'Copied!', 'oosoft-2fa-security' ),
				'copySecret'      => __( 'Copy secret key', 'oosoft-2fa-security' ),
			],
		] );
	}
}
