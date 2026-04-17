<?php
/**
 * User profile 2FA management section.
 *
 * Variables available from the calling context:
 *   $profile_user — WP_User object of the user being edited.
 *
 * @package OOSoft2FA
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$uid             = $profile_user->ID;
$totp_enabled    = OOSOFT_2FA_TOTP::is_enabled( $uid );
$backup_count    = OOSOFT_2FA_Backup_Codes::remaining_count( $uid );
$is_forced       = OOSOFT_2FA_User_Manager::is_role_forced( $uid );
$opted_in        = '1' === get_user_meta( $uid, '_oosoft_2fa_opted_in', true );
$email_available = OOSOFT_2FA_User_Manager::email_otp_available( $uid );
?>
<div id="oosoft-2fa-section">
	<h2><?php esc_html_e( 'Two-Factor Authentication (2FA)', 'oosoft-2fa-security' ); ?></h2>

	<?php if ( $is_forced ) : ?>
		<div class="notice notice-warning inline">
			<p><?php esc_html_e( 'Your role requires 2FA. You must configure at least one method.', 'oosoft-2fa-security' ); ?></p>
		</div>
	<?php endif; ?>

	<table class="form-table" role="presentation">

		<!-- Opt-in toggle (only if role is not forced) -->
		<?php if ( ! $is_forced ) : ?>
		<tr>
			<th scope="row"><?php esc_html_e( 'Enable 2FA', 'oosoft-2fa-security' ); ?></th>
			<td>
				<label>
					<input type="checkbox" name="oosoft_2fa_opted_in" value="1" <?php checked( $opted_in ); ?>>
					<?php esc_html_e( 'Enable two-factor authentication for my account', 'oosoft-2fa-security' ); ?>
				</label>
			</td>
		</tr>
		<?php endif; ?>

		<!-- TOTP (Google Authenticator) -->
		<tr>
			<th scope="row"><?php esc_html_e( 'Authenticator App (TOTP)', 'oosoft-2fa-security' ); ?></th>
			<td>
				<?php if ( $totp_enabled ) : ?>
					<p>
						<span class="oosoft-2fa-badge oosoft-2fa-badge--ok">&#10003; <?php esc_html_e( 'Configured', 'oosoft-2fa-security' ); ?></span>
					</p>
					<button type="button" id="oosoft-2fa-disable-totp" class="button button-secondary">
						<?php esc_html_e( 'Remove authenticator app', 'oosoft-2fa-security' ); ?>
					</button>
				<?php else : ?>
					<p class="description"><?php esc_html_e( 'Use Google Authenticator, Authy, or any TOTP-compatible app.', 'oosoft-2fa-security' ); ?></p>
					<button type="button" id="oosoft-2fa-start-totp" class="button button-primary">
						<?php esc_html_e( 'Set up authenticator app', 'oosoft-2fa-security' ); ?>
					</button>

					<!-- TOTP setup wizard (hidden until button clicked) -->
					<div id="oosoft-2fa-totp-wizard" style="display:none;margin-top:15px">
						<ol>
							<li>
								<p><?php esc_html_e( 'Scan this QR code with your authenticator app:', 'oosoft-2fa-security' ); ?></p>
								<div id="oosoft-2fa-qr-container" style="margin:10px 0">
									<div id="oosoft-2fa-qr-code"></div>
								</div>
								<p>
									<?php esc_html_e( 'Or enter this secret key manually:', 'oosoft-2fa-security' ); ?><br>
									<code id="oosoft-2fa-secret-display" style="font-size:14px;letter-spacing:2px"></code>
									<button type="button" id="oosoft-2fa-copy-secret" class="button-link"
									        aria-label="<?php esc_attr_e( 'Copy secret key', 'oosoft-2fa-security' ); ?>">
										<?php esc_html_e( 'Copy', 'oosoft-2fa-security' ); ?>
									</button>
								</p>
							</li>
							<li>
								<p><?php esc_html_e( 'Enter the 6-digit code from your app to confirm setup:', 'oosoft-2fa-security' ); ?></p>
								<input type="text" id="oosoft-2fa-confirm-code"
								       inputmode="numeric" autocomplete="one-time-code"
								       maxlength="6" pattern="\d{6}" placeholder="000000"
								       style="width:120px;font-size:20px;text-align:center;letter-spacing:4px">
								<button type="button" id="oosoft-2fa-confirm-totp" class="button button-primary">
									<?php esc_html_e( 'Verify and enable', 'oosoft-2fa-security' ); ?>
								</button>
								<span id="oosoft-2fa-confirm-msg" style="margin-left:10px"></span>
							</li>
						</ol>
					</div>
				<?php endif; ?>
			</td>
		</tr>

		<!-- Email OTP status -->
		<?php if ( $email_available ) : ?>
		<tr>
			<th scope="row"><?php esc_html_e( 'Email OTP', 'oosoft-2fa-security' ); ?></th>
			<td>
				<span class="oosoft-2fa-badge oosoft-2fa-badge--ok">&#10003; <?php esc_html_e( 'Available', 'oosoft-2fa-security' ); ?></span>
				<p class="description">
					<?php
					echo wp_kses_post( sprintf(
						/* translators: %s: email address */
						__( 'A one-time code will be sent to %s when you log in.', 'oosoft-2fa-security' ),
						'<strong>' . esc_html( $profile_user->user_email ) . '</strong>'
					) );
					?>
				</p>
			</td>
		</tr>
		<?php endif; ?>

		<!-- Backup codes -->
		<tr>
			<th scope="row"><?php esc_html_e( 'Backup Codes', 'oosoft-2fa-security' ); ?></th>
			<td>
				<?php if ( $backup_count > 0 ) : ?>
					<span class="oosoft-2fa-badge oosoft-2fa-badge--ok">
						<?php
						printf(
							/* translators: %d: number of codes remaining */
							esc_html( _n( '%d code remaining', '%d codes remaining', $backup_count, 'oosoft-2fa-security' ) ),
							(int) $backup_count
						);
						?>
					</span>
				<?php else : ?>
					<span class="oosoft-2fa-badge oosoft-2fa-badge--warn">
						<?php esc_html_e( 'No backup codes', 'oosoft-2fa-security' ); ?>
					</span>
				<?php endif; ?>

				<p class="description"><?php esc_html_e( 'Backup codes let you access your account if you lose access to your authenticator app.', 'oosoft-2fa-security' ); ?></p>

				<button type="button" id="oosoft-2fa-gen-backup" class="button button-secondary">
					<?php $backup_count > 0 ? esc_html_e( 'Regenerate backup codes', 'oosoft-2fa-security' ) : esc_html_e( 'Generate backup codes', 'oosoft-2fa-security' ); ?>
				</button>

				<div id="oosoft-2fa-backup-codes-display" style="display:none;margin-top:15px">
					<div class="notice notice-warning inline">
						<p><strong><?php esc_html_e( 'Save these codes now!', 'oosoft-2fa-security' ); ?></strong>
						<?php esc_html_e( 'They will not be shown again. Each code can be used only once.', 'oosoft-2fa-security' ); ?></p>
					</div>
					<ul id="oosoft-2fa-backup-codes-list" style="font-family:monospace;font-size:16px;column-count:2"></ul>
				</div>
			</td>
		</tr>

	</table>
</div>

<!-- Inline script: pass user context for AJAX calls from this profile. -->
<script>
/* globals oosoft2faAdmin */
var oosoft2faProfileUserId = <?php echo absint( $uid ); ?>;
</script>
