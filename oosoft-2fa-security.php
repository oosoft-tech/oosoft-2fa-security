<?php
/**
 * Plugin Name:       OOSOFT 2FA Security
 * Plugin URI:        https://oosoft.co.in/plugins/2fa-security
 * Description:       Enterprise-grade Two-Factor Authentication for WordPress. Supports Google Authenticator (TOTP) and Email OTP with backup codes, rate limiting, and role-based enforcement.
 * Version:           1.0.2
 * Requires at least: 6.0
 * Requires PHP:      8.0
 * Author:            OOSOFT Technology
 * Author URI:        https://oosoft.co.in
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       oosoft-2fa-security
 * Domain Path:       /languages
 *
 * @package OOSoft2FA
 */

// Prevent direct file access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Plugin version and constants.
define( 'OOSOFT_2FA_VERSION', '1.0.2' );
define( 'OOSOFT_2FA_PLUGIN_FILE', __FILE__ );
define( 'OOSOFT_2FA_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'OOSOFT_2FA_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'OOSOFT_2FA_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );

// Minimum requirements check.
if ( version_compare( PHP_VERSION, '8.0', '<' ) ) {
	add_action( 'admin_notices', function () {
		echo '<div class="notice notice-error"><p>' .
			esc_html__( 'OOSOFT 2FA Security requires PHP 8.0 or higher.', 'oosoft-2fa-security' ) .
			'</p></div>';
	} );
	return;
}

// Warn if WordPress secret keys are still set to the placeholder defaults.
// TOTP secrets are encrypted using AUTH_KEY + SECURE_AUTH_SALT; placeholder
// values produce a near-constant encryption key across all default installs.
add_action( 'admin_notices', function () {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	$placeholder = 'put your unique phrase here';
	$bad_key     = ! defined( 'AUTH_KEY' )         || AUTH_KEY         === $placeholder;
	$bad_salt    = ! defined( 'SECURE_AUTH_SALT' ) || SECURE_AUTH_SALT === $placeholder;
	if ( $bad_key || $bad_salt ) {
		echo '<div class="notice notice-error"><p>' .
			esc_html__( 'OOSOFT 2FA Security: Your wp-config.php secret keys (AUTH_KEY / SECURE_AUTH_SALT) are not set or are using placeholder values. 2FA secrets cannot be securely encrypted until you update them.', 'oosoft-2fa-security' ) .
			' <a href="https://api.wordpress.org/secret-key/1.1/salt/" target="_blank" rel="noopener noreferrer">' .
			esc_html__( 'Generate new keys', 'oosoft-2fa-security' ) .
			'</a></p></div>';
	}
} );

/**
 * Autoloader for plugin classes.
 *
 * @param string $class_name Fully-qualified class name.
 */
spl_autoload_register( function ( string $class_name ) {
	$prefix = 'OOSoft2FA\\';
	if ( strncmp( $prefix, $class_name, strlen( $prefix ) ) !== 0 ) {
		return;
	}

	$relative = substr( $class_name, strlen( $prefix ) );
	$parts    = explode( '\\', $relative );
	$file     = '';

	if ( count( $parts ) === 1 ) {
		$file = OOSOFT_2FA_PLUGIN_DIR . 'includes/class-' . strtolower( str_replace( '_', '-', $parts[0] ) ) . '.php';
	} elseif ( $parts[0] === 'Admin' ) {
		$file = OOSOFT_2FA_PLUGIN_DIR . 'admin/class-' . strtolower( str_replace( '_', '-', $parts[1] ) ) . '.php';
	} elseif ( $parts[0] === 'Frontend' ) {
		$file = OOSOFT_2FA_PLUGIN_DIR . 'public/class-' . strtolower( str_replace( '_', '-', $parts[1] ) ) . '.php';
	}

	if ( $file && is_readable( $file ) ) {
		require_once $file;
	}
} );

/**
 * Load required files manually (fallback for non-namespaced includes).
 */
function oosoft_2fa_load_dependencies(): void {
	$includes = [
		'includes/class-oosoft-2fa-crypto.php',
		'includes/class-oosoft-2fa-qrcode.php',
		'includes/class-oosoft-2fa-logger.php',
		'includes/class-oosoft-2fa-rate-limiter.php',
		'includes/class-oosoft-2fa-totp.php',
		'includes/class-oosoft-2fa-email-otp.php',
		'includes/class-oosoft-2fa-backup-codes.php',
		'includes/class-oosoft-2fa-user-manager.php',
		'includes/class-oosoft-2fa-core.php',
		'admin/class-oosoft-2fa-admin.php',
		'public/class-oosoft-2fa-public.php',
	];

	foreach ( $includes as $file ) {
		$path = OOSOFT_2FA_PLUGIN_DIR . $file;
		if ( is_readable( $path ) ) {
			require_once $path;
		}
	}
}

/**
 * Returns the main plugin instance (singleton).
 *
 * @return OOSOFT_2FA_Core
 */
function oosoft_2fa(): OOSOFT_2FA_Core {
	return OOSOFT_2FA_Core::get_instance();
}

// Activation hook.
register_activation_hook( __FILE__, function () {
	oosoft_2fa_load_dependencies();
	OOSOFT_2FA_Core::activate();
} );

// Deactivation hook.
register_deactivation_hook( __FILE__, function () {
	oosoft_2fa_load_dependencies();
	OOSOFT_2FA_Core::deactivate();
} );

// Bootstrap the plugin after all plugins are loaded.
add_action( 'plugins_loaded', function () {
	oosoft_2fa_load_dependencies();
	oosoft_2fa()->init();
} );
