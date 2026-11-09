# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions are CalVer `YYYY.M.N`.

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

### Added

- Secret file encryption: files in a Secret paste are encrypted in the browser.
- Three-word canonical URLs: every paste lives at `/{three-words}`.
- A generated OpenAPI document at `/api/v1/openapi.json` with Swagger UI at `/docs`.

### Removed

- `BITVAULT_BASIC_AUTH_USERNAME` and `BITVAULT_BASIC_AUTH_PASSWORD` (HTTP Basic Auth).
- `BITVAULT_ADMIN_USERNAME` (there is one admin, with a password only).
- `BITVAULT_API_KEY` (the API needs no key).
- `BITVAULT_PRIVATE` and `BITVAULT_READONLY` (private and read-only instance modes).
- `BITVAULT_JSON_DB` (SQLite only) and `BITVAULT_HASH_IDS` (three-word addresses only).
- `BITVAULT_CUSTOM_CSS`, `BITVAULT_PURE_HTML` and `BITVAULT_WIDE` (one design, one layout).
- `BITVAULT_HIDE_HEADER`, `BITVAULT_HIDE_FOOTER`, `BITVAULT_HIDE_LOGO` and `BITVAULT_FOOTER_TEXT`.
- `BITVAULT_THREADS` (the runtime sizes itself) and `BITVAULT_GC_DAYS` (expired pastes are purged within a minute).
- `BITVAULT_ENABLE_BURN_AFTER` (burn after reading is always available; `default_burn_after` sets the default) and `BITVAULT_NO_FILE_UPLOAD`.
- The Docker image, `compose.yaml`, `.env` and `docker-setup.sh`.
