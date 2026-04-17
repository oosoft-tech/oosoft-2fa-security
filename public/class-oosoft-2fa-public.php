<?php
/**
 * Front-end login flow — intercepts WordPress authentication,
 * redirects to the 2FA challenge page, and completes the login.
 *
 * @package OOSoft2FA
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class OOSOFT_2FA_Public {

	/** Name of the interim-token cookie. */
	private const COOKIE_NAME = 'oosoft_2fa_token';

	/** Slug of the 2FA challenge page (appended to login URL as query arg). */
	private const CHALLENGE_SLUG = 'oosoft-2fa';

	// -----------------------------------------------------------------------
	// Boot
	// -----------------------------------------------------------------------

	public function init(): void {
		// Intercept the authentication pipeline.
		add_filter( 'authenticate',          [ $this, 'intercept_auth' ], 50, 3 );
		add_action( 'login_init',            [ $this, 'handle_challenge_page' ] );

		// Redirect to 2FA challenge AFTER a failed login caused by our WP_Error.
		// login_redirect only fires on SUCCESS — wp_login_failed fires on failure.
		add_action( 'wp_login_failed',       [ $this, 'redirect_to_challenge_on_failure' ], 10, 2 );

		// Enqueue assets on the WP login page.
		add_action( 'login_enqueue_scripts', [ $this, 'enqueue_login_assets' ] );

		// AJAX: send email OTP (logged-out context via nopriv).
		add_action( 'wp_ajax_nopriv_oosoft_2fa_send_email_otp', [ $this, 'ajax_send_email_otp' ] );
	}

	// -----------------------------------------------------------------------
	// Authentication interception
	// -----------------------------------------------------------------------

	/**
	 * After WordPress validates the password, check whether 2FA is required.
	 * If it is, stash the user in an interim session and return a WP_Error
	 * to prevent WordPress from completing the login immediately.
	 *
	 * @param WP_User|WP_Error|null $user     Result from previous filter.
	 * @param string                $username Username or email.
	 * @param string                $password Plain-text password.
	 * @return WP_User|WP_Error
	 */
	public function intercept_auth( $user, string $username, string $password ) {
		// Only act on a successfully authenticated user.
		if ( ! ( $user instanceof WP_User ) ) {
			return $user;
		}

		if ( ! OOSOFT_2FA_User_Manager::requires_2fa( $user->ID ) ) {
			return $user;
		}

		// If 2FA is forced but the user has NOT yet configured any method,
		// allow login so they can reach their profile page to set it up.
		// The admin notice will prompt them immediately.
		if ( ! OOSOFT_2FA_User_Manager::has_2fa_configured( $user->ID ) ) {
			OOSOFT_2FA_Logger::log( '2fa_login_no_method', OOSOFT_2FA_Logger::WARNING, $user->ID );
			return $user;
		}

		// Redirect target — honour 'redirect_to' param.
		// wp_validate_redirect() restricts the URL to the same host, preventing open redirects.
		$redirect = wp_validate_redirect(
			esc_url_raw( wp_unslash( $_POST['redirect_to'] ?? '' ) ),
			admin_url()
		);

		// Create the interim session.
		$token = OOSOFT_2FA_User_Manager::create_interim_session( $user->ID, $redirect );

		// Store token in a short-lived, HttpOnly, SameSite=Strict cookie.
		self::set_challenge_cookie( $token );

		// Return a WP_Error to abort the normal login flow.
		// wp_login_failed will fire and we redirect to the challenge page there.
		return new WP_Error(
			'oosoft_2fa_required',
			esc_html__( 'Two-factor authentication required. Redirecting…', 'oosoft-2fa' )
		);
	}

	/**
	 * Fired by wp_login_failed — redirects to the 2FA challenge page when the
	 * failure was caused by our own intercept (not a wrong password, etc.).
	 *
	 * login_redirect only fires on SUCCESS so this hook is the correct place.
	 *
	 * @param string   $username Attempted username.
	 * @param WP_Error $error    The error returned by authenticate.
	 */
	public function redirect_to_challenge_on_failure( string $username, WP_Error $error ): void {
		if ( $error->get_error_code() !== 'oosoft_2fa_required' ) {
			return;
		}
		wp_safe_redirect( $this->get_challenge_url() );
		exit;
	}

	// -----------------------------------------------------------------------
	// Challenge page
	// -----------------------------------------------------------------------

	/**
	 * Hooked to login_init — renders or processes the 2FA challenge.
	 */
	public function handle_challenge_page(): void {
		$action = sanitize_key( wp_unslash( $_GET['action'] ?? '' ) );
		if ( $action !== self::CHALLENGE_SLUG ) {
			return;
		}

		// Validate the interim session token from the cookie.
		$token   = sanitize_text_field( wp_unslash( $_COOKIE[ self::COOKIE_NAME ] ?? '' ) );
		$session = OOSOFT_2FA_User_Manager::get_interim_session( $token );

		if ( null === $session ) {
			// Invalid or expired session — redirect to login.
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		$user_id = (int) $session['user_id'];
		$ip      = $this->get_client_ip();

		// Rate-limit check.
		if ( OOSOFT_2FA_Rate_Limiter::is_rate_limited( $ip, $user_id ) ) {
			OOSOFT_2FA_Logger::log( 'rate_limited', OOSOFT_2FA_Logger::WARNING, $user_id, [ 'ip' => $ip ] );
			$this->render_challenge( $user_id, 'rate_limited' );
			exit;
		}

		// POST: code submission.
		if ( 'POST' === $_SERVER['REQUEST_METHOD'] ) {
			$this->process_challenge( $user_id, $token, $session, $ip );
			exit;
		}

		// GET: render the challenge form.
		$this->render_challenge( $user_id );
		exit;
	}

	/**
	 * Process a submitted 2FA code.
	 */
	private function process_challenge( int $user_id, string $token, array $session, string $ip ): void {
		// Validate nonce.
		if ( ! isset( $_POST['_wpnonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ), 'oosoft_2fa_challenge' ) ) {
			OOSOFT_2FA_Logger::log( 'invalid_nonce', OOSOFT_2FA_Logger::ERROR, $user_id );
			$this->render_challenge( $user_id, 'invalid_nonce' );
			return;
		}

		$method = sanitize_key( wp_unslash( $_POST['method'] ?? '' ) );
		$code   = sanitize_text_field( wp_unslash( $_POST['otp_code'] ?? '' ) );
		$valid  = false;

		switch ( $method ) {
			case OOSOFT_2FA_User_Manager::METHOD_TOTP:
				$valid = OOSOFT_2FA_TOTP::verify( $user_id, $code );
				break;

			case OOSOFT_2FA_User_Manager::METHOD_EMAIL:
				$valid = OOSOFT_2FA_Email_OTP::verify( $user_id, $code );
				break;

			case OOSOFT_2FA_User_Manager::METHOD_BACKUP:
				$valid = OOSOFT_2FA_Backup_Codes::verify( $user_id, $code );
				break;
		}

		if ( $valid ) {
			OOSOFT_2FA_Rate_Limiter::clear_failures( $ip, $user_id );
			OOSOFT_2FA_Logger::log( '2fa_success', OOSOFT_2FA_Logger::INFO, $user_id, [ 'method' => $method ] );

			// Destroy interim session and cookie.
			OOSOFT_2FA_User_Manager::destroy_interim_session( $token );
			self::clear_challenge_cookie();

			// Complete the WordPress login.
			wp_set_auth_cookie( $user_id, false );
			do_action( 'wp_login', get_userdata( $user_id )->user_login, get_userdata( $user_id ) );

			$redirect = esc_url_raw( $session['redirect'] ?: admin_url() );
			wp_safe_redirect( $redirect );
		} else {
			OOSOFT_2FA_Rate_Limiter::record_failure( $ip, $user_id );
			OOSOFT_2FA_Logger::log( '2fa_failure', OOSOFT_2FA_Logger::WARNING, $user_id, [ 'method' => $method ] );
			$this->render_challenge( $user_id, 'invalid_code' );
		}
	}

	/**
	 * Render the 2FA challenge form and exit.
	 *
	 * @param int    $user_id  WordPress user ID.
	 * @param string $error    Error key (empty = no error).
	 */
	private function render_challenge( int $user_id, string $error = '' ): void {
		$methods          = OOSOFT_2FA_User_Manager::available_methods( $user_id );
		$preferred_method = OOSOFT_2FA_User_Manager::preferred_method( $user_id );
		$remaining        = OOSOFT_2FA_Rate_Limiter::remaining_attempts( $this->get_client_ip(), $user_id );

		// Load the login page template.
		require OOSOFT_2FA_PLUGIN_DIR . 'public/views/challenge-form.php';
	}

	// -----------------------------------------------------------------------
	// AJAX: send email OTP
	// -----------------------------------------------------------------------

	public function ajax_send_email_otp(): void {
		check_ajax_referer( 'oosoft_2fa_challenge', 'nonce' );

		$token   = sanitize_text_field( wp_unslash( $_COOKIE[ self::COOKIE_NAME ] ?? '' ) );
		$session = OOSOFT_2FA_User_Manager::get_interim_session( $token );

		if ( null === $session ) {
			wp_send_json_error( [ 'message' => __( 'Session expired. Please log in again.', 'oosoft-2fa' ) ], 401 );
		}

		$user_id = (int) $session['user_id'];

		if ( OOSOFT_2FA_Rate_Limiter::is_rate_limited( $this->get_client_ip(), $user_id ) ) {
			wp_send_json_error( [ 'message' => __( 'Too many attempts. Please wait before requesting a new code.', 'oosoft-2fa' ) ], 429 );
		}

		if ( OOSOFT_2FA_Email_OTP::send( $user_id ) ) {
			wp_send_json_success( [ 'message' => __( 'A new code has been sent to your email.', 'oosoft-2fa' ) ] );
		} else {
			wp_send_json_error( [ 'message' => __( 'Could not send email. Please contact an administrator.', 'oosoft-2fa' ) ] );
		}
	}

	// -----------------------------------------------------------------------
	// Asset enqueueing
	// -----------------------------------------------------------------------

	public function enqueue_login_assets(): void {
		$action = sanitize_key( wp_unslash( $_GET['action'] ?? '' ) );
		if ( $action !== self::CHALLENGE_SLUG ) {
			return;
		}

		wp_enqueue_style(
			'oosoft-2fa-login',
			OOSOFT_2FA_PLUGIN_URL . 'assets/css/oosoft-2fa-login.css',
			[ 'login' ],
			OOSOFT_2FA_VERSION
		);

		wp_enqueue_script(
			'oosoft-2fa-login',
			OOSOFT_2FA_PLUGIN_URL . 'assets/js/oosoft-2fa-login.js',
			[ 'jquery' ],
			OOSOFT_2FA_VERSION,
			true
		);

		wp_localize_script( 'oosoft-2fa-login', 'oosoft2faLogin', [
			'ajaxUrl' => admin_url( 'admin-ajax.php' ),
			'nonce'   => wp_create_nonce( 'oosoft_2fa_challenge' ),
			'i18n'    => [
				'sending'     => __( 'Sending…', 'oosoft-2fa' ),
				'codeSent'    => __( 'Code sent. Check your inbox.', 'oosoft-2fa' ),
				'sendFailed'  => __( 'Failed to send code. Please try again.', 'oosoft-2fa' ),
			],
		] );
	}

	// -----------------------------------------------------------------------
	// Helpers
	// -----------------------------------------------------------------------

	private function get_challenge_url(): string {
		return add_query_arg( 'action', self::CHALLENGE_SLUG, wp_login_url() );
	}

	private static function set_challenge_cookie( string $token ): void {
		$expiry  = time() + 600; // 10 minutes.
		$is_ssl  = is_ssl();
		$path    = COOKIEPATH;
		$domain  = COOKIE_DOMAIN;

		// PHP 7.3+ cookie options array with SameSite support.
		setcookie( self::COOKIE_NAME, $token, [
			'expires'  => $expiry,
			'path'     => $path,
			'domain'   => $domain,
			'secure'   => $is_ssl,
			'httponly' => true,
			'samesite' => 'Strict',
		] );

		// Populate the superglobal for immediate use in the same request.
		$_COOKIE[ self::COOKIE_NAME ] = $token;
	}

	private static function clear_challenge_cookie(): void {
		setcookie( self::COOKIE_NAME, '', time() - 3600, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true );
		unset( $_COOKIE[ self::COOKIE_NAME ] );
	}

	private function get_client_ip(): string {
		// Lightweight wrapper — full logic lives in Logger.
		$trust_proxy = (bool) get_option( 'oosoft_2fa_trust_proxy_headers', false );
		if ( $trust_proxy ) {
			foreach ( [ 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP' ] as $h ) {
				if ( ! empty( $_SERVER[ $h ] ) ) {
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
