=== OOSOFT 2FA Security ===
Contributors: oosofttech
Tags: two-factor authentication, 2fa, totp, otp, security
Requires at least: 6.0
Tested up to: 6.9
Stable tag: 1.0.2
Requires PHP: 8.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Enterprise-grade Two-Factor Authentication for WordPress with TOTP, Email OTP, backup codes, and role-based enforcement.

== Description ==

OOSOFT 2FA Security adds robust two-factor authentication to your WordPress site. Protect every login with a second verification step using a TOTP authenticator app (Google Authenticator, Authy, etc.) or a one-time code sent to your email address.

**Key Features:**

* **TOTP Authenticator App** — compatible with Google Authenticator, Authy, Microsoft Authenticator, and any RFC 6238-compliant app.
* **Email OTP** — sends a time-limited one-time code to the user's registered email address.
* **Backup Codes** — generate single-use recovery codes so users are never locked out.
* **Role-Based Enforcement** — require 2FA for specific roles (e.g. administrators) while leaving it optional for others.
* **Rate Limiting** — brute-force protection with configurable attempt limits and lockout periods.
* **Security Logs** — detailed event logging with filterable admin view and automatic pruning.
* **Encrypted Secret Storage** — TOTP secrets are encrypted at rest using libsodium (preferred) or AES-256-GCM/CBC via OpenSSL.
* **HKDF Key Derivation** — encryption keys are derived from your WordPress secret keys; no raw key material is stored.

== Installation ==

1. Upload the `oosoft-2fa-security` folder to the `/wp-content/plugins/` directory.
2. Activate the plugin through the **Plugins** menu in WordPress.
3. Go to **Settings > 2FA Security** to configure enforcement rules and options.
4. Users can set up their preferred 2FA method from their **Profile** page.

== Frequently Asked Questions ==

= Which authenticator apps are supported? =

Any app that supports the TOTP standard (RFC 6238), including Google Authenticator, Authy, Microsoft Authenticator, and 1Password.

= What happens if a user loses their authenticator app? =

Users can log in with one of their backup codes. Administrators can also disable 2FA for a user from the Users list.

= Is TOTP secret storage secure? =

Yes. Secrets are encrypted with AES-256 (libsodium secretbox preferred, OpenSSL AES-256-GCM/CBC as fallback) before being stored in the database. Encryption keys are derived from your site's unique WordPress secret keys via HKDF-SHA256.

= Does this plugin work with WooCommerce or custom login forms? =

The plugin intercepts WordPress's core authentication pipeline, so it works with any theme or plugin that uses `wp_signon()` or the standard login form.

== Screenshots ==

1. Two-factor authentication challenge screen shown after password login.
2. User profile section for managing 2FA methods and backup codes.
3. Admin settings page with role enforcement and rate limiting configuration.
4. Admin security logs page.

== Changelog ==

= 1.0.2 =
* Improved escaping and security hardening throughout.
* Removed deprecated load_plugin_textdomain() call (WordPress 4.6+ auto-loads translations).
* Added HKDF key derivation fallback warning when WordPress secret keys are not configured.

= 1.0.1 =
* Fixed QR code scanning compatibility with major authenticator apps.
* Switched to proven qrcodejs library for QR generation.

= 1.0.0 =
* Initial release.

== Upgrade Notice ==

= 1.0.2 =
Security hardening release. Update recommended for all users.
