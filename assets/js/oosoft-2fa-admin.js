/**
 * Admin JS — OOSOFT 2FA Security
 *
 * Handles:
 *  - TOTP setup wizard (QR code display, confirmation)
 *  - TOTP disable
 *  - Backup code generation
 *  - Secret copy-to-clipboard
 *
 * Depends on:  jQuery (bundled with WordPress)
 *              qrcodejs.min.js (davidshimjs/qrcodejs — battle-tested QR library)
 * Globals:     oosoft2faAdmin  (localised via wp_localize_script)
 */

/* global oosoft2faAdmin, oosoft2faProfileUserId, QRCode */
( function ( $ ) {
    'use strict';

    var admin  = oosoft2faAdmin || {};
    var userId = ( typeof oosoft2faProfileUserId !== 'undefined' ) ? oosoft2faProfileUserId : 0;

    // -----------------------------------------------------------------------
    // TOTP setup
    // -----------------------------------------------------------------------

    $( '#oosoft-2fa-start-totp' ).on( 'click', function () {
        var $btn = $( this ).prop( 'disabled', true ).text( '…' );

        $.post( admin.ajaxUrl, {
            action : 'oosoft_2fa_setup_totp',
            nonce  : admin.nonce,
        } )
        .done( function ( response ) {
            if ( ! response.success ) {
                var msg = ( response.data && response.data.message ) ? response.data.message : 'Error — check server logs.';
                $( '#oosoft-2fa-confirm-msg' ).css( 'color', '#c0392b' ).text( msg );
                $btn.prop( 'disabled', false ).text( 'Set up authenticator app' );
                return;
            }

            var data   = response.data;
            var secret = data.secret;
            var uri    = data.uri;

            // Display the secret key.
            $( '#oosoft-2fa-secret-display' ).text( secret.replace( /(.{4})/g, '$1 ' ).trim() );

            // Render the QR code client-side via qrcodejs (davidshimjs library).
            var $qr = $( '#oosoft-2fa-qr-code' ).empty();
            var qrContainer = $qr[0];
            if ( typeof QRCode !== 'undefined' ) {
                new QRCode( qrContainer, {
                    text:         uri,
                    width:        256,
                    height:       256,
                    correctLevel: QRCode.CorrectLevel.M
                } );
            } else {
                // Fallback link when library is unavailable.
                // jQuery .attr() safely encodes the URI — no string concatenation into HTML.
                var $link = $( '<a>' )
                    .attr( 'href', uri )
                    .attr( 'target', '_blank' )
                    .attr( 'rel', 'noopener noreferrer' )
                    .text( 'Open in authenticator app' );
                $qr.empty().append( $link );
            }

            $( '#oosoft-2fa-totp-wizard' ).slideDown( 200 );
            $btn.hide();
        } )
        .fail( function ( xhr ) {
            var msg = 'Server error (HTTP ' + xhr.status + '). Check PHP error log for details.';
            $( '#oosoft-2fa-totp-wizard' ).show();
            $( '#oosoft-2fa-confirm-msg' ).css( 'color', '#c0392b' ).text( msg );
            $btn.prop( 'disabled', false ).text( 'Set up authenticator app' );
        } );
    } );

    // Confirm TOTP code.
    $( '#oosoft-2fa-confirm-totp' ).on( 'click', function () {
        var code = $( '#oosoft-2fa-confirm-code' ).val().replace( /\D/g, '' );
        if ( code.length !== 6 ) {
            $( '#oosoft-2fa-confirm-msg' ).css( 'color', '#c0392b' ).text( 'Please enter a 6-digit code.' );
            return;
        }

        var $btn = $( this ).prop( 'disabled', true ).text( '…' );

        $.post( admin.ajaxUrl, {
            action : 'oosoft_2fa_confirm_totp',
            nonce  : admin.nonce,
            code   : code,
        } )
        .done( function ( response ) {
            if ( response.success ) {
                $( '#oosoft-2fa-confirm-msg' ).css( 'color', '#1e7e34' ).text( response.data.message );
                // Reload to refresh the profile section state.
                setTimeout( function () { window.location.reload(); }, 1200 );
            } else {
                $( '#oosoft-2fa-confirm-msg' ).css( 'color', '#c0392b' ).text( response.data.message );
                $btn.prop( 'disabled', false ).text( 'Verify and enable' );
            }
        } )
        .fail( function () {
            alert( 'Network error.' );
            $btn.prop( 'disabled', false ).text( 'Verify and enable' );
        } );
    } );

    // -----------------------------------------------------------------------
    // TOTP disable
    // -----------------------------------------------------------------------

    $( '#oosoft-2fa-disable-totp' ).on( 'click', function () {
        if ( ! confirm( admin.i18n.confirmDisable ) ) {
            return;
        }

        var $btn = $( this ).prop( 'disabled', true );
        var data = {
            action : 'oosoft_2fa_disable_totp',
            nonce  : admin.nonce,
        };
        if ( userId ) {
            data.user_id = userId;
        }

        $.post( admin.ajaxUrl, data )
        .done( function ( response ) {
            if ( response.success ) {
                window.location.reload();
            } else {
                alert( response.data.message || 'Error.' );
                $btn.prop( 'disabled', false );
            }
        } )
        .fail( function () {
            alert( 'Network error.' );
            $btn.prop( 'disabled', false );
        } );
    } );

    // -----------------------------------------------------------------------
    // Backup codes
    // -----------------------------------------------------------------------

    $( '#oosoft-2fa-gen-backup' ).on( 'click', function () {
        if ( ! confirm( admin.i18n.confirmRegenerate ) ) {
            return;
        }

        var $btn = $( this ).prop( 'disabled', true ).text( '…' );

        $.post( admin.ajaxUrl, {
            action : 'oosoft_2fa_gen_backup',
            nonce  : admin.nonce,
        } )
        .done( function ( response ) {
            if ( ! response.success ) {
                alert( response.data.message || 'Error.' );
                $btn.prop( 'disabled', false );
                return;
            }

            var $list = $( '#oosoft-2fa-backup-codes-list' ).empty();
            $.each( response.data.codes, function ( i, code ) {
                $list.append( '<li>' + $( '<span>' ).text( code ).html() + '</li>' );
            } );

            $( '#oosoft-2fa-backup-codes-display' ).slideDown( 200 );
            $btn.prop( 'disabled', false ).text( 'Regenerate backup codes' );
        } )
        .fail( function ( xhr ) {
            alert( 'Server error (HTTP ' + xhr.status + '). Check PHP error log.' );
            $btn.prop( 'disabled', false );
        } );
    } );

    // -----------------------------------------------------------------------
    // Copy secret to clipboard
    // -----------------------------------------------------------------------

    $( '#oosoft-2fa-copy-secret' ).on( 'click', function () {
        var $btn    = $( this );
        var secret  = $( '#oosoft-2fa-secret-display' ).text().replace( /\s/g, '' );

        if ( navigator.clipboard && window.isSecureContext ) {
            navigator.clipboard.writeText( secret ).then( function () {
                $btn.text( admin.i18n.copied );
                setTimeout( function () { $btn.text( admin.i18n.copySecret ); }, 2000 );
            } );
        } else {
            // Fallback for non-HTTPS environments.
            var $temp = $( '<textarea>' ).val( secret ).appendTo( 'body' ).select();
            document.execCommand( 'copy' );
            $temp.remove();
            $btn.text( admin.i18n.copied );
            setTimeout( function () { $btn.text( admin.i18n.copySecret ); }, 2000 );
        }
    } );

    // Auto-advance TOTP confirm input after 6 digits.
    $( '#oosoft-2fa-confirm-code' ).on( 'input', function () {
        var val = $( this ).val().replace( /\D/g, '' ).slice( 0, 6 );
        $( this ).val( val );
        if ( val.length === 6 ) {
            $( '#oosoft-2fa-confirm-totp' ).trigger( 'click' );
        }
    } );

    // -----------------------------------------------------------------------
    // Crypto diagnostics (settings page)
    // -----------------------------------------------------------------------

    $( '#oosoft-2fa-run-diagnostics' ).on( 'click', function () {
        var $btn = $( this ).prop( 'disabled', true ).text( 'Running…' );
        var $out = $( '#oosoft-2fa-diag-output' );

        $.post( admin.ajaxUrl, {
            action : 'oosoft_2fa_diagnose',
            nonce  : admin.nonce,
        } )
        .done( function ( response ) {
            if ( ! response.success ) {
                $out.text( 'Request failed: ' + JSON.stringify( response ) ).show();
                $btn.prop( 'disabled', false ).text( 'Run Crypto Diagnostics' );
                return;
            }
            var lines = [];
            $.each( response.data, function ( key, val ) {
                var icon = ( val === true || ( typeof val === 'string' && val.indexOf( 'OK' ) === 0 ) )
                    ? '✅' : ( val === false ? '❌' : '⚠️ ' );
                lines.push( icon + ' ' + key + ': ' + JSON.stringify( val ) );
            } );
            $out.text( lines.join( '\n' ) ).show();
            $btn.prop( 'disabled', false ).text( 'Run Crypto Diagnostics' );
        } )
        .fail( function ( xhr ) {
            $out.text( 'HTTP ' + xhr.status + ' — check PHP error log.' ).show();
            $btn.prop( 'disabled', false ).text( 'Run Crypto Diagnostics' );
        } );
    } );

}( jQuery ) );
