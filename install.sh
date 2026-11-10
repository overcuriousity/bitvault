#!/bin/sh
# Offline installer for a bitvault bundle. Never uses the network and never calls sudo.
set -eu

usage() {
  echo "Usage: install.sh --archive FILE [--sha256 HEX] [--system] [--prefix DIR]" >&2
  exit 2
}

archive=""
expected=""
system=0
prefix=""
while [ $# -gt 0 ]; do
  case "$1" in
    --archive) [ $# -ge 2 ] || usage; archive=$2; shift 2 ;;
    --sha256) [ $# -ge 2 ] || usage; expected=$2; shift 2 ;;
    --system) system=1; shift ;;
    --prefix) [ $# -ge 2 ] || usage; prefix=$2; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown option: $1" >&2; usage ;;
  esac
done
[ -n "$archive" ] || usage
if [ "$system" -eq 1 ]; then
  [ -z "$prefix" ] || { echo "--prefix cannot be combined with --system, which always installs to /usr/local." >&2; exit 2; }
  prefix=/usr/local
elif [ -z "$prefix" ]; then
  [ -n "${HOME:-}" ] || { echo "HOME is not set; pass --prefix DIR to say where to install." >&2; exit 2; }
  prefix="$HOME/.local"
fi
[ -f "$archive" ] || { echo "Archive not found: $archive" >&2; exit 1; }

if [ "$system" -eq 1 ] && [ "$(id -u)" -ne 0 ]; then
  echo "Run as root for --system; this script never calls sudo." >&2
  exit 1
fi

# The bundle's own SHA256SUMS only shows damage: whoever alters a bundle can rewrite it too.
# A checksum from the release's SHA256SUMS, obtained apart from the bundle, shows tampering.
if [ -n "$expected" ]; then
  actual=$(sha256sum "$archive" | cut -d' ' -f1)
  if [ "$actual" != "$(printf '%s' "$expected" | tr 'A-F' 'a-f')" ]; then
    echo "The archive does not match --sha256. Download it again and compare with the release's SHA256SUMS." >&2
    exit 1
  fi
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tar -C "$work" -xzf "$archive"
set -- "$work"/*/
if [ $# -ne 1 ] || [ ! -d "$1" ]; then
  echo "The archive should contain exactly one directory." >&2
  exit 1
fi
bundle=${1%/}

cd "$bundle"
if ! sha256sum -c --quiet SHA256SUMS > "$work/check.log" 2>&1; then
  bad=$(grep -v ': OK$' "$work/check.log" | head -n 1 | cut -d: -f1)
  echo "Checksum mismatch: ${bad:-SHA256SUMS}. The bundle is damaged." >&2
  exit 1
fi

app=$(head -n 1 name)
case "$app" in
  ''|*[!a-z0-9_-]*) echo "The bundle names an invalid app: $app" >&2; exit 1 ;;
esac

mkdir -p "$prefix/bin"
install -m 0755 "$app" "$prefix/bin/$app"
echo "Installed $prefix/bin/$app"

if [ "$system" -eq 1 ]; then
  install -m 0644 "$app.service" "/etc/systemd/system/$app.service"
  mkdir -p "/etc/$app"
  if [ ! -f "/etc/$app/config.toml" ]; then
    # World-readable because the service runs as a dynamic user; secrets go through LoadCredential=.
    install -m 0644 config.example.toml "/etc/$app/config.toml"
    echo "Wrote /etc/$app/config.toml; set public_url before starting. Keep secrets out of it (see AIRGAP.md)."
  fi
  echo "Installed /etc/systemd/system/$app.service. Start it with: systemctl daemon-reload && systemctl enable --now $app"
fi

doc="$prefix/share/$app"
mkdir -p "$doc"
for f in nginx.conf AIRGAP.md THIRD-PARTY-LICENSES config.example.toml; do
  [ -f "$f" ] && install -m 0644 "$f" "$doc/$f"
done
echo "Reverse proxy template: $doc/nginx.conf"
