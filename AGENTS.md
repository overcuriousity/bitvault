# AGENTS.md

BitVault is a self-hosted pastebin, file drop and URL shortener whose pastes are addressed by three BIP39 words, for people who run their own small server.

## Rules

Follows overcuriousity dev manifest v2026.11.0 (principles and stack; no oc-kit or oc-check):
https://github.com/overcuriousity/overcuriousity-dev-manifest/tree/v2026.11.0/manifest

- Profile: everyday.
- Read the manifest files in number order before changing UI, security or ops.
- Before declaring work done, run `manifest/99-review-checklist.md` by hand; there is no `oc-check`.
- bitvault depends on no manifest code. Its security layer (`security.rs`, `ratelimit.rs`), config, asset serving and page shell are its own.
- The design files in `assets/vendor/oc/` are copied unmodified from the manifest; `assets/vendor/oc/SOURCE.md` names the tag and the source path of each file. Updating means a deliberate re-copy from a newer tag.

## Deliberate exceptions to the manifest

1. Delete is immediate and permanent, without undo or typed confirmation (`40-interaction.md`).
2. Binding to `0.0.0.0` is allowed, with an https `public_url` (or `insecure_http`, see #8); the default stays `127.0.0.1` (`70-ops.md` "binds 127.0.0.1").
3. Vendored Swagger UI keeps its own styling apart from token overrides (`10-visual.md` literal colours).
4. Secret pastes use PBKDF2 in the browser because Argon2 would need `wasm-unsafe-eval`.
5. No dependency on `oc-kit`; the design files are copied at `v2026.11.0` and the security layer is bitvault's own (`50-stack.md` "depend on `oc-kit` by CalVer tag").
6. No `oc-check` in CI or tests (`70-ops.md` CI contents, `80-code.md` rendered-page `oc-check` test). The narrower inline-style, inline-script and handler check in `tests/rendered.rs` and the console CSP check remain; literal colours rely on review.
7. Theme and text size are stored in `localStorage` for the admin too, not server-side (`10-visual.md` "store the choice per user"); a single in-memory admin session has nowhere durable to keep them.
8. Opt-in plain HTTP (`insecure_http`), off by default: any Host, an `http://` `public_url`, origins checked against the request's own Host, no HSTS, a `bitvault-admin` cookie without `Secure`, `Referrer-Policy: same-origin` so our own form posts keep their Origin, and no Secret pastes (`70-ops.md` "NEVER an insecure LAN mode"). Since any host name is answered, a web page can reach the instance through DNS rebinding, and cross-site posts without cookies are not blocked. It restores 1.6.0's LAN use by the owner's decision; start-up logs a warning.
9. Larger type and controls than the kit tokens, and one centred content column with the top bar aligned to it, by the owner's decision (`10-visual.md` type scale). The overrides live at the top of `assets/css/app.css`; the copied files stay unmodified.

## Layout

- `src/domain/` all paste rules, as plain functions over `&AppState`.
- `src/web/` Askama pages and `src/api/` the REST API (utoipa): thin adapters over the domain.
- `src/security.rs`, `src/ratelimit.rs`, `src/config.rs`, `src/deployment.rs`, `src/assets.rs`: security layer, config, asset serving.
- `templates/` Askama templates; `assets/css`, `assets/js` bitvault's own; `assets/vendor/` copied files.
- `migrations/` SQLite schema; `.sqlx/` the committed offline query data.
- `tests/` integration tests on real SQLite in temp dirs; `tests/fixtures/` interop fixtures shared with the JS tests.
- `deploy/`, `install.sh`, `scripts/` ops; `config.example.toml` documents every key.

## Commands

- `cargo fmt --all --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all-features` (the `test-hooks` feature, enabled by a self dev-dependency, adds the browser-format decoders the tests need)
- `node --test 'assets/js/*.test.mjs'`
- `cargo deny check`
- `cargo sqlx prepare -- --all-targets --all-features` after changing any `sqlx::query!`; commit `.sqlx/`.
- `BITVAULT_WRITE_FIXTURES=1 node --test 'assets/js/crypto.test.mjs'` regenerates the JS interop fixture; commit it only on purpose.
- `sh scripts/third-party.sh > THIRD-PARTY-LICENSES` after dependency changes (needs `cargo-about`).
