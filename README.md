<img src=".github/logo.png" alt="BitVault" width="96">

# BitVault

A self-hosted pastebin, file drop and URL shortener. Every paste lives at three BIP39 words, such as `/happy-apple-banana`. One static binary, SQLite, no telemetry.

- Text, files and short links, with syntax highlighting, QR codes and a REST API.
- Privacy levels: public, unlisted, read-only, private (encrypted on the server) and secret (encrypted in your browser, so the server never sees the key).
- Expiry, burn after reading, optional editing and one optional admin.

BitVault is a maintained fork of [Microbin](https://github.com/szabodanika/microbin). Version 2026.11.0 is a rewrite with no compatibility with 1.6.0 data, URLs, configuration or API; see the [changelog](CHANGELOG.md).

## Install

Download the offline bundle for your CPU from the [latest release](https://github.com/overcuriousity/bitvault/releases/latest), then:

```sh
sh install.sh --archive bitvault-<version>-x86_64-unknown-linux-musl-offline.tar.gz            # ~/.local/bin
sh install.sh --archive bitvault-<version>-x86_64-unknown-linux-musl-offline.tar.gz --system  # as root: systemd service
```

The installer works offline, checks every file against `SHA256SUMS` and never calls sudo itself. [AIRGAP.md](AIRGAP.md) covers TLS, secrets and building without network.

## Run behind nginx

BitVault listens on `127.0.0.1:8080` and expects a reverse proxy to terminate TLS. Use [`deploy/nginx.conf`](deploy/nginx.conf) (it is also in the bundle) and set `public_url` to the address users type. Uploads stream through nginx, so keep `client_max_body_size` at `max_file_mb` plus one.

## Configuration

Copy [`config.example.toml`](config.example.toml) and pass it with `--config`. Every key is optional and documented there. Environment variables override the file as `BITVAULT__SECTION__KEY`, and a `_FILE` suffix reads a secret from a file.

## API

The API needs no key. Browse it at `/docs` on your instance, or fetch `/api/v1/openapi.json`. When you upload with `multipart/form-data`, send `privacy` and the other text fields before the `file` parts. If the server sets an uploader password, send it in `X-Uploader-Password`.

## Build from source

```sh
git clone https://github.com/overcuriousity/bitvault && cd bitvault
SQLX_OFFLINE=true cargo build --release
./target/release/bitvault --config config.example.toml
```

## Licence

[GPL-3.0-only](LICENSE). The original Microbin project was published by Dániel Szabó under the BSD-3-Clause licence ([ORIGINALLICENSE.txt](ORIGINALLICENSE.txt)). Third-party licences are in [THIRD-PARTY-LICENSES](THIRD-PARTY-LICENSES).
