<?php
/**
 * 2FA challenge form — rendered on the WordPress login page.
 *
 * Variables available from the calling context (OOSOFT_2FA_Public):
 *   $user_id          — int
 *   $methods          — string[]
 *   $preferred_method — string|null
 *   $error            — string (empty = no error)
 *   $remaining        — int
 *
 * @package OOSoft2FA
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Error messages.
$error_messages = [
	'invalid_code'  => __( 'The code you entered is incorrect. Please try again.', 'oosoft-2fa-security' ),
	'invalid_nonce' => __( 'Security token expired. Please refresh and try again.', 'oosoft-2fa-security' ),
	'rate_limited'  => __( 'Too many failed attempts. Please wait a few minutes before trying again.', 'oosoft-2fa-security' ),
];

$method_labels = [
	OOSOFT_2FA_User_Manager::METHOD_TOTP   => __( 'Authenticator App', 'oosoft-2fa-security' ),
	OOSOFT_2FA_User_Manager::METHOD_EMAIL  => __( 'Email Code', 'oosoft-2fa-security' ),
	OOSOFT_2FA_User_Manager::METHOD_BACKUP => __( 'Backup Code', 'oosoft-2fa-security' ),
];

$active_method = sanitize_key( wp_unslash( $_GET['method'] ?? ( $preferred_method ?? '' ) ) );
if ( ! in_array( $active_method, $methods, true ) ) {
	$active_method = $methods[0] ?? '';
}

// Use WordPress login page scaffolding.
login_header( __( 'Two-Factor Authentication', 'oosoft-2fa-security' ), '', null );
?>

<div id="oosoft-2fa-challenge">

	<?php if ( ! empty( $error ) && isset( $error_messages[ $error ] ) ) : ?>
		<div id="login_error" class="notice notice-error">
			<strong><?php esc_html_e( 'Error:', 'oosoft-2fa-security' ); ?></strong>
			<?php echo esc_html( $error_messages[ $error ] ); ?>
			<?php if ( 'rate_limited' !== $error && $remaining > 0 ) : ?>
				<br>
				<small>
					<?php
					printf(
						/* translators: %d: attempts remaining */
						esc_html( _n( '%d attempt remaining.', '%d attempts remaining.', $remaining, 'oosoft-2fa-security' ) ),
						(int) $remaining
					);
					?>
				</small>
			<?php endif; ?>
		</div>
	<?php endif; ?>

	<p class="oosoft-2fa-intro">
		<?php esc_html_e( 'Your account is protected with two-factor authentication. Enter the code for your selected method below.', 'oosoft-2fa-security' ); ?>
	</p>

	<!-- Method selector tabs (only shown when multiple methods available) -->
	<?php if ( count( $methods ) > 1 ) : ?>
	<div class="oosoft-2fa-methods" role="tablist" aria-label="<?php esc_attr_e( '2FA methods', 'oosoft-2fa-security' ); ?>">
		<?php foreach ( $methods as $m ) : ?>
			<a href="<?php echo esc_url( add_query_arg( 'method', $m ) ); ?>"
			   class="oosoft-2fa-method-tab <?php echo esc_attr( $m === $active_method ? 'active' : '' ); ?>"
			   role="tab" aria-selected="<?php echo esc_attr( $m === $active_method ? 'true' : 'false' ); ?>">
				<?php echo esc_html( $method_labels[ $m ] ?? $m ); ?>
			</a>
		<?php endforeach; ?>
	</div>
	<?php endif; ?>

	<form name="oosoft2faform" id="oosoft2faform" action="<?php echo esc_url( add_query_arg( 'action', 'oosoft-2fa', wp_login_url() ) ); ?>" method="post">
		<?php wp_nonce_field( 'oosoft_2fa_challenge' ); ?>
		<input type="hidden" name="method" value="<?php echo esc_attr( $active_method ); ?>">

		<?php if ( $active_method === OOSOFT_2FA_User_Manager::METHOD_TOTP ) : ?>

			<p><?php esc_html_e( 'Open your authenticator app and enter the 6-digit code.', 'oosoft-2fa-security' ); ?></p>
			<div class="user-pass-wrap">
				<label for="otp_code"><?php esc_html_e( 'Authentication Code', 'oosoft-2fa-security' ); ?></label>
				<div class="wp-pwd">
					<input type="text" name="otp_code" id="otp_code"
					       class="input" value="" size="6"
					       inputmode="numeric" autocomplete="one-time-code"
					       maxlength="6" pattern="\d{6}"
					       autofocus required
					       placeholder="000000"
					       style="font-size:24px;letter-spacing:6px;text-align:center;width:160px">
				</div>
			</div>

		<?php elseif ( $active_method === OOSOFT_2FA_User_Manager::METHOD_EMAIL ) : ?>

			<p>
				<?php esc_html_e( 'A one-time code will be sent to your registered email address.', 'oosoft-2fa-security' ); ?>
			</p>
			<p>
				<button type="button" id="oosoft-2fa-send-email-otp" class="button button-secondary">
					<?php esc_html_e( 'Send code to my email', 'oosoft-2fa-security' ); ?>
				</button>
				<span id="oosoft-2fa-email-otp-status" aria-live="polite"></span>
			</p>
			<div class="user-pass-wrap" id="oosoft-2fa-email-code-wrap" style="display:none">
				<label for="otp_code"><?php esc_html_e( 'Email Code', 'oosoft-2fa-security' ); ?></label>
				<div class="wp-pwd">
					<input type="text" name="otp_code" id="otp_code"
					       class="input" value="" size="6"
					       inputmode="numeric" autocomplete="one-time-code"
					       maxlength="6" pattern="\d{6}"
					       placeholder="000000"
					       style="font-size:24px;letter-spacing:6px;text-align:center;width:160px">
				</div>
			</div>

		<?php elseif ( $active_method === OOSOFT_2FA_User_Manager::METHOD_BACKUP ) : ?>

			<p><?php esc_html_e( 'Enter one of your saved backup codes. Each code can only be used once.', 'oosoft-2fa-security' ); ?></p>
			<div class="user-pass-wrap">
				<label for="otp_code"><?php esc_html_e( 'Backup Code', 'oosoft-2fa-security' ); ?></label>
				<div class="wp-pwd">
					<input type="text" name="otp_code" id="otp_code"
					       class="input" value=""
					       autocomplete="off" spellcheck="false"
					       maxlength="12"
					       autofocus required
					       placeholder="AAAAA-BBBBB"
					       style="font-size:16px;letter-spacing:2px;text-align:center;width:200px">
				</div>
			</div>

		<?php endif; ?>

		<?php if ( $active_method !== OOSOFT_2FA_User_Manager::METHOD_EMAIL ) : ?>
			<p class="submit">
				<input type="submit" name="wp-submit" id="wp-submit"
				       class="button button-primary button-large"
				       value="<?php esc_attr_e( 'Verify', 'oosoft-2fa-security' ); ?>">
			</p>
		<?php else : ?>
			<p class="submit" id="oosoft-2fa-email-submit-wrap" style="display:none">
				<input type="submit" name="wp-submit" id="wp-submit"
				       class="button button-primary button-large"
				       value="<?php esc_attr_e( 'Verify', 'oosoft-2fa-security' ); ?>">
			</p>
		<?php endif; ?>
	</form>

</div>

<?php
login_footer( 'otp_code' );
