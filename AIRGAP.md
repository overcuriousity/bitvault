# Airgapped install

Every release can be installed on a machine with no network access. 
## What to carry across

Download these from the release page on a connected machine:

| File | Purpose |
|---|---|
| `bitvault-<version>-x86_64-unknown-linux-musl-offline.tar.gz` (or `aarch64`) | static binary, `install.sh`, systemd unit, nginx template, example config, licences, `SHA256SUMS` |
| `install.sh` | the installer, also inside each bundle |
| `SHA256SUMS` | checksums of the release files |
| `bitvault-<version>-src-vendored.tar.gz` | optional: source with every dependency vendored, to build without network |

Check the downloads before you carry them across:

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

The release also carries build-provenance attestations. On a connected machine, check them with `gh attestation verify <file> --repo overcuriousity/bitvault`.

## Install

The installer never uses the network and never calls `sudo`.

For your user only, into `~/.local/bin`:

```sh
sh install.sh --archive bitvault-<version>-x86_64-unknown-linux-musl-offline.tar.gz
```

As a system service, run as root. This installs to `/usr/local/bin`, sets up a hardened systemd unit and creates `/etc/bitvault/config.toml`:

```sh
sh install.sh --archive bitvault-<version>-x86_64-unknown-linux-musl-offline.tar.gz --system
```

The installer checks every file against the bundle's `SHA256SUMS`. If any file has changed, it stops with "Checksum mismatch".

## TLS on an airgapped network

BitVault never terminates TLS itself. It listens on `127.0.0.1:8080`, and nginx on the same machine serves https. Plain http over the network is not supported: the admin cookie is `Secure`, and Secret pastes need WebCrypto, which browsers allow only on https or localhost.

Use either of these:
- A certificate from your local CA. This is best: browsers trust it once the CA is installed on each client.
- A self-signed certificate. Browsers will warn until each client trusts it.

```sh
openssl req -x509 -newkey rsa:3072 -sha256 -days 825 -nodes \
  -keyout /etc/ssl/private/vault.lan.key -out /etc/ssl/certs/vault.lan.pem \
  -subj "/CN=vault.lan" -addext "subjectAltName=DNS:vault.lan"
```

Keep secrets out of `config.toml`; it is world-readable so the service's dynamic user can read it. Put the admin password in a root-only file and hand it to the service as a credential:

```sh
printf '%s' 'the-admin-password' | install -m 0600 /dev/stdin /etc/bitvault/admin-password
systemctl edit bitvault   # add the two lines below under [Service]
# LoadCredential=admin-password:/etc/bitvault/admin-password
# Environment=BITVAULT__APP__ADMIN_PASSWORD_FILE=%d/admin-password
```

The uploader password works the same way (`BITVAULT__APP__UPLOADER_PASSWORD_FILE`).

Then:
1. Copy `nginx.conf` from the bundle (also in `~/.local/share/bitvault/` or `/usr/local/share/bitvault/`) to `/etc/nginx/conf.d/bitvault.conf`. Replace `vault.example.org` and the certificate paths, then reload nginx.
2. Set the address users type in `/etc/bitvault/config.toml`:

   ```toml
   public_url = "https://vault.lan"
   ```

BitVault refuses to start if `public_url` is not https, except for `localhost`.

## Build from source without network

```sh
tar -xzf bitvault-<version>-src-vendored.tar.gz
cd bitvault-<version>
SQLX_OFFLINE=true cargo build --release --offline --locked
```

The archive's `.cargo/config.toml` points Cargo at the bundled `vendor/` directory. Fonts, icons and htmx are already inside the source tree.

## First start

```sh
systemctl enable --now bitvault
curl -s http://127.0.0.1:8080/api/v1/health
```

The health check answers `{"status":"ok", ...}`. Data lives in `/var/lib/bitvault` for the system service. A restart signs the admin out.
