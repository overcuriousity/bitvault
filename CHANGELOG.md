# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions are CalVer `YYYY.M.N`.

## [2026.11.1]

### Changed

- A paste that is one web address no longer redirects. It opens its page, which shows the address with a copy button and a "Go to URL" button, so following it is your choice and nobody can hide a target behind your instance's address. `?view` is no longer needed and is ignored.

## [2026.11.0]

This is a rewrite and a fresh start. There is no compatibility with 1.6.0: no data migration, the URLs differ, the configuration is a new TOML file and the API is new. Start with an empty data directory.

### Changed

- Rewritten to the overcuriousity dev manifest v2026.11.0: axum, Askama, htmx, SQLite via sqlx, a strict content security policy and the manifest's design tokens.
- Configuration is a TOML file (`--config`) with `BITVAULT__SECTION__KEY` environment overrides and `*_FILE` variants for secrets. See `config.example.toml`.
- Releases ship offline bundles for x86_64 and aarch64 (musl) with `install.sh`, a systemd unit, an nginx template and checksums. Docker images are no longer published.
- Port and bind address are now one `bind` key (`BITVAULT_PORT`, `BITVAULT_BIND`); `public_url`, `short_url` and `data_dir` replace `BITVAULT_PUBLIC_PATH`, `BITVAULT_SHORT_PATH` and `BITVAULT_DATA_DIR`.
- `BITVAULT_NO_LISTING` became `listing`, `BITVAULT_HIGHLIGHTSYNTAX` became `highlight`, and `BITVAULT_ETERNAL_PASTA` became `never` in `expiry_choices` and `max_expiry`.
- `BITVAULT_ENABLE_READONLY`, `BITVAULT_ENCRYPTION_CLIENT_SIDE` and `BITVAULT_ENCRYPTION_SERVER_SIDE` became entries in `privacy_levels`; `BITVAULT_MAX_FILE_SIZE_UNENCRYPTED_MB` and `BITVAULT_MAX_FILE_SIZE_ENCRYPTED_MB` became `max_file_mb` and `max_secret_file_mb`.
- The admin password has no default; without one there is no admin page.
- BitVault must be served over https from one public host: a non-loopback `bind` needs an https `public_url`, and requests for any other host name are refused. `insecure_http = true` opts out for private networks (any host name, no HSTS, no Secret pastes); see the README.
- `editable` now means the "Allow editing" checkbox is shown and pre-checked on new pastes, and it sets the API default.
- Text is limited to 1 MiB per paste.
- Read-only pastes take no password: anyone with the address reads them, nobody changes or deletes them, and only the administrator can remove one.
- A private or secret paste asks for its password once. The opened page deletes it (and changes a private one) without asking again.
- The expiries 2, 4, 8 and 16 years exist again, but only as opt-in through `expiry_choices`.

### Added

- Secret file encryption: files in a Secret paste are encrypted in the browser.
- Three-word canonical URLs: every paste lives at `/{three-words}`.
- A secret paste's page shows its ciphertext and the salt, iteration count, IV, associated data and tag that decrypt it in another tool.
- The privacy menu groups the levels by encryption: not encrypted, encrypted on the server, end-to-end encrypted.
- A generated OpenAPI document at `/api/v1/openapi.json`, and an API reference at `/docs` rendered from it on the server, with a `curl` line for each call.
- Per-address rate limits: creates 30 per minute (burst 10), other API calls 120 (burst 30), wrong passwords (the uploader password included) 10 (burst 5), and lookups of words that match no paste 20 (burst 10), so unlisted pastes cannot be enumerated.
- After creating on the web you see the new paste with its words, address, Copy link, Share, QR code and delete; creating on the home page shows upload progress and you can paste images from the clipboard.
- One box on the home page: text or a link becomes a new paste, and three words (or a pasted link to a paste here) open the paste they name, with Enter. The words may be separated by spaces or hyphens, run together, or cut to their first four letters; Tab completes a word. The options fold away until the box holds text.
- Add `?view` to a link's address to see where it goes before following it.
- Syntax "Automatic" (the default) detects the language from the first line, such as a shebang; code gets line numbers.
- Copy text and Share (where the browser has it) on paste pages; raw text, link and QR stay in one toolbar.
- File downloads send `Content-Length` and resume with byte ranges, except in private pastes and zip downloads.
- `install.sh --sha256 <checksum>` refuses a bundle that does not match the release's `SHA256SUMS`.
- The admin table shows 50 pastes a page; its totals still cover every paste.
- Files other than raster images download as `application/octet-stream`, whatever their name.
- Guide and API in the navigation, help links on the create form, a version footer, and an admin settings summary.

### Removed

- `BITVAULT_BASIC_AUTH_USERNAME` and `BITVAULT_BASIC_AUTH_PASSWORD` (HTTP Basic Auth).
- `BITVAULT_ADMIN_USERNAME` (there is one admin, with a password only).
- `BITVAULT_API_KEY` (the API needs no key).
- `BITVAULT_PRIVATE` and `BITVAULT_READONLY` (private and read-only instance modes).
- `BITVAULT_JSON_DB` (SQLite only) and `BITVAULT_HASH_IDS` (three-word addresses only).
- `BITVAULT_CUSTOM_CSS`, `BITVAULT_PURE_HTML` and `BITVAULT_WIDE` (one design, one layout).
- `BITVAULT_HIDE_HEADER`, `BITVAULT_HIDE_FOOTER`, `BITVAULT_HIDE_LOGO` and `BITVAULT_FOOTER_TEXT`.
- `BITVAULT_THREADS` (the runtime sizes itself).
- `BITVAULT_GC_DAYS`. Expired pastes are purged within a minute, but it also deleted pastes that nobody had read for that many days; there is no replacement.
- `BITVAULT_ENABLE_BURN_AFTER` (burn after reading is always available; `default_burn_after` sets the default) and `BITVAULT_NO_FILE_UPLOAD`.
- The Docker image, `compose.yaml`, `.env` and `docker-setup.sh`.
