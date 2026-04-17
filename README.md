# OOSOFT 2FA Security

> Enterprise-grade Two-Factor Authentication for WordPress

[![WordPress](https://img.shields.io/badge/WordPress-6.0%2B-blue?logo=wordpress)](https://wordpress.org)
[![PHP](https://img.shields.io/badge/PHP-8.0%2B-777BB4?logo=php)](https://php.net)
[![License](https://img.shields.io/badge/license-GPL--2.0--or--later-green)](https://www.gnu.org/licenses/gpl-2.0.html)
[![Version](https://img.shields.io/badge/version-1.0.2-orange)]()

A production-ready Two-Factor Authentication plugin that protects WordPress accounts with TOTP (Google Authenticator / Authy), Email OTP fallback, backup codes, brute-force rate limiting, and full audit logging — all built with zero external PHP dependencies.

---

## Features

- **TOTP (RFC 6238)** — Works with Google Authenticator, Authy, Microsoft Authenticator, and any TOTP-compatible app
- **Email OTP fallback** — One-time code sent to the user's registered email address
- **Backup codes** — 10 single-use recovery codes generated on demand
- **Role-based enforcement** — Force 2FA for specific roles (e.g. Administrator, Editor)
- **Rate limiting** — Configurable lockout after N failed attempts within a time window
- **Audit logging** — Every authentication event logged to a custom DB table with IP, user agent, and timestamp
- **Encrypted secret storage** — TOTP secrets encrypted at rest using libsodium (AES-256-GCM via OpenSSL as fallback)
- **Replay protection** — Each TOTP time-step can only be used once
- **Per-user opt-in** — Users on non-forced roles can optionally enable 2FA themselves
- **Proxy-aware IP detection** — Optional Cloudflare / load-balancer header support (`CF-Connecting-IP`, `X-Forwarded-For`)
- **Zero external PHP dependencies** — No Composer packages required; QR code rendered client-side via bundled JS library

---

## Requirements

| Requirement | Minimum |
|---|---|
| WordPress | 6.0 |
| PHP | 8.0 |
| Encryption | libsodium **or** OpenSSL with AES-256-GCM (or AES-256-CBC + HMAC) |

---

## Installation

### From source

```bash
git clone https://github.com/oosoft-tech/oosoft-2fa-security.git
cp -r oosoft-2fa-security /path/to/wordpress/wp-content/plugins/
```

Then activate via **WordPress Admin → Plugins → OOSOFT 2FA Security → Activate**.

### Manual upload

1. Download the repository as a ZIP
2. Go to **Plugins → Add New → Upload Plugin**
3. Upload the ZIP and activate

---

## Configuration

### Global settings

Navigate to **2FA Security → Settings** in the WordPress admin menu.

| Setting | Default | Description |
|---|---|---|
| Enable 2FA Plugin | ✓ | Master on/off switch |
| Force 2FA for Roles | — | Select roles that must configure 2FA |
| Allow Email OTP Fallback | ✓ | Enable email-based OTP as a second method |
| Email OTP Expiry | 600s | How long an emailed code remains valid |
| Max Failed Attempts | 5 | Attempts before lockout |
| Failure Window | 300s | Rolling window for counting failures |
| Lockout Duration | 900s | How long an account is locked after too many failures |
| Log Retention | 90 days | How long audit log entries are kept |
| Trust Proxy Headers | ✗ | Enable for Cloudflare or load-balanced setups |

### Per-user setup

Users configure their own 2FA from **Users → Profile** (or **Edit User** for admins):

1. Click **Set up authenticator app**
2. Scan the QR code with Google Authenticator, Authy, etc.
3. Enter the 6-digit code to confirm and activate
4. Optionally generate backup codes

---

## How It Works

### Login flow

```
User submits username + password
        │
        ▼
WordPress authenticates credentials
        │
        ▼
Does user have 2FA enabled?
   No  ──► Normal login
   Yes ──► Show 2FA challenge page
              │
              ├─ TOTP code (authenticator app)
              ├─ Email OTP ("Send code to email")
              └─ Backup code
                    │
                    ▼
              Code verified?
                Yes ──► Login granted + session created
                No  ──► Rate limiter checks, log attempt, show error
```

### TOTP implementation

- RFC 6238 (TOTP) built on RFC 4226 (HOTP)
- HMAC-SHA1, 30-second time step, 6-digit codes
- ±1 window (90-second tolerance for clock drift)
- Replay protection: each accepted time-step is recorded and rejected if reused

### Secret encryption

Secrets are encrypted before storage in `wp_usermeta`:

1. **libsodium** (`sodium_crypto_secretbox`) — preferred when the `sodium` PHP extension is loaded
2. **OpenSSL AES-256-GCM** — used when GCM is available without libsodium
3. **OpenSSL AES-256-CBC + HMAC-SHA256** — fallback for older OpenSSL builds

The encryption key is derived from `AUTH_KEY` + `SECURE_AUTH_SALT` (from `wp-config.php`).

---

## File Structure

```
oosoft-2fa-security/
├── oosoft-2fa-security.php          # Plugin bootstrap & constants
├── admin/
│   ├── class-oosoft-2fa-admin.php   # Admin menus, settings, AJAX handlers
│   └── views/
│       ├── admin-settings.php       # Settings page template
│       ├── admin-logs.php           # Audit log viewer template
│       └── user-profile.php         # Profile page 2FA section
├── includes/
│   ├── class-oosoft-2fa-core.php          # Main hook registration
│   ├── class-oosoft-2fa-totp.php          # TOTP (RFC 6238) implementation
│   ├── class-oosoft-2fa-email-otp.php     # Email OTP generation & verification
│   ├── class-oosoft-2fa-backup-codes.php  # Backup code generation & verification
│   ├── class-oosoft-2fa-crypto.php        # Encryption / decryption / Base32
│   ├── class-oosoft-2fa-rate-limiter.php  # Brute-force protection
│   ├── class-oosoft-2fa-logger.php        # Audit logging
│   ├── class-oosoft-2fa-user-manager.php  # User state helpers
│   └── class-oosoft-2fa-qrcode.php        # Pure-PHP QR code (SVG, internal use)
├── public/
│   ├── class-oosoft-2fa-public.php        # Login challenge hooks & AJAX
│   └── views/
│       └── challenge-form.php             # 2FA challenge page template
└── assets/
    ├── css/
    │   ├── oosoft-2fa-admin.css
    │   └── oosoft-2fa-login.css
    └── js/
        ├── oosoft-2fa-admin.js            # Profile page interactions
        ├── oosoft-2fa-login.js            # Login challenge interactions
        └── qrcodejs.min.js                # QR code renderer (davidshimjs/qrcodejs, MIT)
```

---

## Security

- All AJAX endpoints protected with WordPress nonces (`check_ajax_referer`)
- All output escaped with `esc_html`, `esc_attr`, `esc_url`
- All database queries use `$wpdb->prepare()` with parameterised placeholders
- TOTP secrets never stored in plaintext — always encrypted at rest
- `sodium_memzero` used to wipe sensitive key material from memory after use
- Rate limiter blocks brute-force against both TOTP and email OTP channels
- Replay protection prevents reuse of an already-accepted TOTP time-step

### Reporting vulnerabilities

Please **do not** open a public GitHub issue for security vulnerabilities. Email **security@oosoft.co.in** with details. We aim to respond within 48 hours.

---

## Audit Log Events

| Event | Level | Description |
|---|---|---|
| `totp_enabled` | INFO | User successfully configured TOTP |
| `totp_disabled` | WARNING | TOTP removed from user account |
| `totp_verified` | INFO | Successful TOTP login |
| `totp_failed` | WARNING | Invalid TOTP code entered |
| `totp_replay_attempt` | WARNING | Previously-used time-step submitted |
| `email_otp_sent` | INFO | OTP email dispatched |
| `email_otp_verified` | INFO | Email OTP accepted |
| `email_otp_failed` | WARNING | Invalid email OTP entered |
| `backup_code_used` | INFO | Backup code consumed |
| `backup_code_failed` | WARNING | Invalid backup code entered |
| `rate_limit_exceeded` | ERROR | Account locked due to too many failures |
| `backup_codes_generated` | INFO | New set of backup codes created |

---

## Crypto Diagnostics

If setup fails with *"Could not generate secret"*, run the built-in diagnostics tool:

**2FA Security → Settings → Run Crypto Diagnostics**

This checks `random_bytes`, libsodium, OpenSSL GCM/CBC, HMAC, a full encrypt/decrypt round-trip, and Base32 encoding — and reports exactly which component is unavailable on your server.

---

## Compatibility

| App | TOTP | QR Scan |
|---|---|---|
| Google Authenticator (iOS / Android) | ✅ | ✅ |
| Authy | ✅ | ✅ |
| Microsoft Authenticator | ✅ | ✅ |
| 1Password | ✅ | ✅ |
| Bitwarden | ✅ | ✅ |
| Any RFC 6238-compliant app | ✅ | ✅ |

---

## Third-Party Libraries

| Library | Author | License | Usage |
|---|---|---|---|
| [qrcodejs](https://github.com/davidshimjs/qrcodejs) | Shim Sangmin | MIT | Client-side QR code rendering |

---

## License

OOSOFT 2FA Security is released under the [GNU General Public License v2.0 or later](https://www.gnu.org/licenses/gpl-2.0.html).

---

## Author

**OOSOFT Technology** — [oosoft.co.in](https://oosoft.co.in)
