<?php
/**
 * Admin settings page view.
 *
 * @package OOSoft2FA
 * @var string $this OOSOFT_2FA_Admin instance (called via require).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<div class="wrap oosoft-2fa-settings">
	<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>

	<p class="description">
		<?php esc_html_e( 'Configure two-factor authentication settings for your WordPress site.', 'oosoft-2fa-security' ); ?>
	</p>

	<?php settings_errors( 'oosoft_2fa_settings' ); ?>

	<form method="post" action="options.php">
		<?php
		settings_fields( 'oosoft_2fa_settings' );
		do_settings_sections( 'oosoft-2fa-settings' );
		submit_button();
		?>
	</form>

	<hr>

	<h2><?php esc_html_e( 'System Status', 'oosoft-2fa-security' ); ?></h2>

	<p>
		<button type="button" id="oosoft-2fa-run-diagnostics" class="button button-secondary">
			<?php esc_html_e( 'Run Crypto Diagnostics', 'oosoft-2fa-security' ); ?>
		</button>
	</p>
	<pre id="oosoft-2fa-diag-output" style="display:none;background:#1e1e1e;color:#d4d4d4;padding:14px 16px;border-radius:4px;max-width:700px;overflow-x:auto;font-size:13px;line-height:1.6"></pre>

	<table class="widefat striped" style="max-width:600px">
		<tbody>
			<tr>
				<td><?php esc_html_e( 'PHP Version', 'oosoft-2fa-security' ); ?></td>
				<td><?php echo esc_html( PHP_VERSION ); ?></td>
			</tr>
			<tr>
				<td><?php esc_html_e( 'libsodium Available', 'oosoft-2fa-security' ); ?></td>
				<td>
					<?php if ( function_exists( 'sodium_crypto_secretbox' ) ) : ?>
						<span class="oosoft-2fa-badge oosoft-2fa-badge--ok">&#10003; <?php esc_html_e( 'Yes', 'oosoft-2fa-security' ); ?></span>
					<?php else : ?>
						<span class="oosoft-2fa-badge oosoft-2fa-badge--warn">&#9888; <?php esc_html_e( 'No — using OpenSSL fallback', 'oosoft-2fa-security' ); ?></span>
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<td><?php esc_html_e( 'OpenSSL Available', 'oosoft-2fa-security' ); ?></td>
				<td>
					<?php if ( function_exists( 'openssl_encrypt' ) ) : ?>
						<span class="oosoft-2fa-badge oosoft-2fa-badge--ok">&#10003; <?php esc_html_e( 'Yes', 'oosoft-2fa-security' ); ?></span>
					<?php else : ?>
						<span class="oosoft-2fa-badge oosoft-2fa-badge--error">&#10007; <?php esc_html_e( 'No — encryption unavailable!', 'oosoft-2fa-security' ); ?></span>
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<td><?php esc_html_e( 'WordPress Cron', 'oosoft-2fa-security' ); ?></td>
				<td>
					<?php $next = wp_next_scheduled( 'oosoft_2fa_daily_cron' ); ?>
					<?php if ( $next ) : ?>
						<span class="oosoft-2fa-badge oosoft-2fa-badge--ok">
							<?php
							printf(
								/* translators: %s: human-readable time */
								esc_html__( 'Next run: %s', 'oosoft-2fa-security' ),
								esc_html( human_time_diff( $next ) )
							);
							?>
						</span>
					<?php else : ?>
						<span class="oosoft-2fa-badge oosoft-2fa-badge--warn"><?php esc_html_e( 'Not scheduled', 'oosoft-2fa-security' ); ?></span>
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<td><?php esc_html_e( 'Plugin Version', 'oosoft-2fa-security' ); ?></td>
				<td><?php echo esc_html( OOSOFT_2FA_VERSION ); ?></td>
			</tr>
		</tbody>
	</table>
</div>
