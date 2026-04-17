<?php
/**
 * Security logs page view.
 *
 * @package OOSoft2FA
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Sanitised filter inputs.
$filter_level   = sanitize_key( wp_unslash( $_GET['level'] ?? '' ) );
$filter_user_id = absint( $_GET['user_id'] ?? 0 );
$current_page   = max( 1, absint( $_GET['paged'] ?? 1 ) );
$per_page       = 50;

$result = OOSOFT_2FA_Logger::get_logs( [
	'level'    => $filter_level,
	'user_id'  => $filter_user_id,
	'per_page' => $per_page,
	'page'     => $current_page,
] );

$items      = $result['items'];
$total      = $result['total'];
$page_count = (int) ceil( $total / $per_page );

$level_labels = [
	OOSOFT_2FA_Logger::INFO    => __( 'Info', 'oosoft-2fa-security' ),
	OOSOFT_2FA_Logger::WARNING => __( 'Warning', 'oosoft-2fa-security' ),
	OOSOFT_2FA_Logger::ERROR   => __( 'Error', 'oosoft-2fa-security' ),
];
?>
<div class="wrap oosoft-2fa-logs">
	<h1><?php esc_html_e( 'OOSOFT 2FA Security Logs', 'oosoft-2fa-security' ); ?></h1>

	<p class="description">
		<?php
		printf(
			/* translators: %d: total log count */
			esc_html__( 'Showing %d total events.', 'oosoft-2fa-security' ),
			(int) $total
		);
		?>
	</p>

	<!-- Filters -->
	<form method="get" action="">
		<input type="hidden" name="page" value="oosoft-2fa-logs">
		<select name="level">
			<option value=""><?php esc_html_e( '— All Levels —', 'oosoft-2fa-security' ); ?></option>
			<?php foreach ( $level_labels as $val => $label ) : ?>
				<option value="<?php echo esc_attr( $val ); ?>" <?php selected( $filter_level, $val ); ?>>
					<?php echo esc_html( $label ); ?>
				</option>
			<?php endforeach; ?>
		</select>
		<input type="number" name="user_id" placeholder="<?php esc_attr_e( 'User ID', 'oosoft-2fa-security' ); ?>"
		       value="<?php echo esc_attr( $filter_user_id ?: '' ); ?>" min="1" style="width:100px">
		<?php submit_button( __( 'Filter', 'oosoft-2fa-security' ), 'secondary', '', false ); ?>
	</form>

	<br>

	<?php if ( empty( $items ) ) : ?>
		<p><?php esc_html_e( 'No log entries found.', 'oosoft-2fa-security' ); ?></p>
	<?php else : ?>
		<table class="wp-list-table widefat fixed striped">
			<thead>
				<tr>
					<th scope="col" style="width:50px"><?php esc_html_e( 'ID', 'oosoft-2fa-security' ); ?></th>
					<th scope="col" style="width:70px"><?php esc_html_e( 'Level', 'oosoft-2fa-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Event', 'oosoft-2fa-security' ); ?></th>
					<th scope="col" style="width:80px"><?php esc_html_e( 'User', 'oosoft-2fa-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'IP Address', 'oosoft-2fa-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Context', 'oosoft-2fa-security' ); ?></th>
					<th scope="col" style="width:160px"><?php esc_html_e( 'Date (UTC)', 'oosoft-2fa-security' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $items as $item ) :
					$level_class = 'level-' . esc_attr( $item->level );
					$user        = $item->user_id > 0 ? get_userdata( (int) $item->user_id ) : null;
				?>
					<tr class="<?php echo esc_attr( $level_class ); ?>">
						<td><?php echo esc_html( $item->id ); ?></td>
						<td>
							<span class="oosoft-2fa-badge oosoft-2fa-badge--<?php echo esc_attr( $item->level ); ?>">
								<?php echo esc_html( $level_labels[ $item->level ] ?? $item->level ); ?>
							</span>
						</td>
						<td><?php echo esc_html( $item->event ); ?></td>
						<td>
							<?php if ( $user ) : ?>
								<a href="<?php echo esc_url( get_edit_user_link( (int) $item->user_id ) ); ?>">
									<?php echo esc_html( $user->user_login ); ?>
								</a>
							<?php else : ?>
								<?php echo esc_html( $item->user_id > 0 ? '#' . $item->user_id : '—' ); ?>
							<?php endif; ?>
						</td>
						<td><?php echo esc_html( $item->ip_address ); ?></td>
						<td>
							<code style="font-size:11px;word-break:break-all"><?php
								$ctx = json_decode( $item->context, true );
								echo esc_html( $ctx ? wp_json_encode( $ctx ) : '' );
							?></code>
						</td>
						<td><?php echo esc_html( $item->created_at ); ?></td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>

		<!-- Pagination -->
		<?php if ( $page_count > 1 ) : ?>
		<div class="tablenav bottom">
			<div class="tablenav-pages">
				<?php
				echo wp_kses_post( paginate_links( [
					'base'      => add_query_arg( 'paged', '%#%' ),
					'format'    => '',
					'current'   => $current_page,
					'total'     => $page_count,
					'prev_text' => '&laquo;',
					'next_text' => '&raquo;',
				] ) );
				?>
			</div>
		</div>
		<?php endif; ?>
	<?php endif; ?>
</div>
