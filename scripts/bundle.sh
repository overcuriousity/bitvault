#!/bin/sh
# Builds the offline release bundles from the musl binaries in DIST/bin:
# one archive per target (binary, install files, licences, SHA256SUMS) plus a vendored source archive.
# Usage: bundle.sh APP VERSION DIST, run from the repository root.
# Paths can be overridden: INSTALL_SH, SERVICE, NGINX, AIRGAP, CONFIG. TARGETS limits the targets built.
set -eu

app=$1
version=$2
dist=$3
install_sh=${INSTALL_SH:-install.sh}
service=${SERVICE:-deploy/bitvault.service}
nginx=${NGINX:-deploy/nginx.conf}
airgap=${AIRGAP:-AIRGAP.md}
config=${CONFIG:-config.example.toml}
targets=${TARGETS:-"x86_64-unknown-linux-musl aarch64-unknown-linux-musl"}
out="$dist/out"
mkdir -p "$out"

mkdir -p "$dist/src/.cargo"
git archive --format=tar HEAD | tar -C "$dist/src" -xf -
# The printed source replacement points at the build path; inside the archive it is ./vendor.
cargo vendor --locked --versioned-dirs "$dist/src/vendor" | sed 's|^directory = .*|directory = "vendor"|' > "$dist/src/.cargo/config.toml"
tar -C "$dist" -czf "$out/$app-$version-src-vendored.tar.gz" --transform "s|^src|$app-$version|" src

sh scripts/third-party.sh > "$dist/THIRD-PARTY-LICENSES"

for target in $targets; do
  name="$app-$version-$target"
  dir="$dist/$name"
  mkdir -p "$dir"
  install -m 0755 "$dist/bin/bin-$target/$app" "$dir/$app"
  printf '%s\n' "$app" > "$dir/name"
  sed "s/@APP@/$app/g" "$service" > "$dir/$app.service"
  cp "$nginx" "$dir/nginx.conf"
  cp "$airgap" "$dir/AIRGAP.md"
  cp "$config" "$dir/config.example.toml"
  cp "$dist/THIRD-PARTY-LICENSES" "$dir/THIRD-PARTY-LICENSES"
  cp "$install_sh" "$dir/install.sh"
  (cd "$dir" && sha256sum -- * | grep -v ' SHA256SUMS$' > SHA256SUMS)
  tar -C "$dist" -czf "$out/$name-offline.tar.gz" "$name"
done
cp "$install_sh" "$out/install.sh"
(cd "$out" && sha256sum -- *.tar.gz install.sh > SHA256SUMS)
