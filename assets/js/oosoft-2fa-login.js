/**
 * Login / challenge page JS — OOSOFT 2FA Security
 *
 * Handles:
 *  - "Send email OTP" button AJAX call
 *  - Auto-submit on 6-digit TOTP entry
 *  - Show code input after email is sent
 *
 * Globals: oosoft2faLogin  (localised via wp_localize_script)
 */

/* global oosoft2faLogin */
( function ( $ ) {
    'use strict';

    var cfg = oosoft2faLogin || {};

    // -----------------------------------------------------------------------
    // Send email OTP
    // -----------------------------------------------------------------------

    $( '#oosoft-2fa-send-email-otp' ).on( 'click', function () {
        var $btn    = $( this ).prop( 'disabled', true ).text( cfg.i18n.sending );
        var $status = $( '#oosoft-2fa-email-otp-status' ).removeClass( 'success error' );

        $.post( cfg.ajaxUrl, {
            action : 'oosoft_2fa_send_email_otp',
            nonce  : cfg.nonce,
        } )
        .done( function ( response ) {
            if ( response.success ) {
                $status.addClass( 'success' ).text( cfg.i18n.codeSent );
                $( '#oosoft-2fa-email-code-wrap' ).slideDown( 200 );
                $( '#oosoft-2fa-email-submit-wrap' ).slideDown( 200 );
                $( '#otp_code' ).prop( 'required', true ).focus();
            } else {
                $status.addClass( 'error' ).text( response.data.message || cfg.i18n.sendFailed );
            }
        } )
        .fail( function () {
            $status.addClass( 'error' ).text( cfg.i18n.sendFailed );
        } )
        .always( function () {
            $btn.prop( 'disabled', false ).text( 'Resend code' );
        } );
    } );

    // -----------------------------------------------------------------------
    // Auto-submit on 6-digit TOTP code entry
    // -----------------------------------------------------------------------

    $( '#otp_code' ).on( 'input', function () {
        var $input = $( this );
        // Only auto-submit for numeric TOTP/email codes.
        if ( $input.attr( 'maxlength' ) === '6' ) {
            var val = $input.val().replace( /\D/g, '' ).slice( 0, 6 );
            $input.val( val );
            if ( val.length === 6 ) {
                $( '#oosoft2faform' ).submit();
            }
        }
    } );

    // -----------------------------------------------------------------------
    // Prevent double-submit
    // -----------------------------------------------------------------------

    $( '#oosoft2faform' ).on( 'submit', function () {
        $( '#wp-submit' ).prop( 'disabled', true );
    } );

}( jQuery ) );
