#!/bin/sh
# Writes THIRD-PARTY-LICENSES to stdout: the Rust crates (cargo-about), then the copied design files.
set -eu

cargo about generate --locked about.hbs

cat <<'NOTICE'


-------------------------------------------------------------------------------
Copied design files and vendored browser code

- Atkinson Hyperlegible Next and JetBrains Mono (woff2): SIL Open Font License 1.1, texts below.
- Lucide icons: ISC, text below.
- htmx: Zero-Clause BSD (0BSD), text below.
- Design CSS and JavaScript from overcuriousity-dev-manifest v2026.11.0: MIT OR Apache-2.0,
  Copyright (c) 2026 overcuriousity.
NOTICE

cat <<'END_OF_MIT_TEXT'


==== overcuriousity-dev-manifest design CSS and JavaScript (MIT) ====

MIT License

Copyright (c) 2026 overcuriousity

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
END_OF_MIT_TEXT

for f in \
  assets/vendor/oc/fonts/OFL-AtkinsonHyperlegibleNext.txt \
  assets/vendor/oc/fonts/OFL-JetBrainsMono.txt \
  assets/vendor/oc/icons/LICENSE-lucide.txt \
  assets/vendor/oc/htmx/LICENSE-htmx.txt; do
  printf '\n\n==== %s ====\n\n' "$f"
  cat "$f"
done
