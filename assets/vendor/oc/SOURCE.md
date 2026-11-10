# Copied design files

Copied unmodified from overcuriousity/overcuriousity-dev-manifest, tag v2026.11.0. Updating means a deliberate re-copy from a newer tag.

| Path here (under assets/vendor/oc/) | Source path in the manifest repository |
|---|---|
| css/00-tokens.css | crates/oc-kit/assets/css/00-tokens.css |
| css/10-base.css | crates/oc-kit/assets/css/10-base.css |
| css/20-layout.css | crates/oc-kit/assets/css/20-layout.css |
| css/30-components.css | crates/oc-kit/assets/css/30-components.css |
| css/40-tables.css | crates/oc-kit/assets/css/40-tables.css |
| css/50-touch.css | crates/oc-kit/assets/css/50-touch.css |
| css/profile-everyday.css | crates/oc-kit/assets/css/profile-everyday.css |
| fonts/OFL-AtkinsonHyperlegibleNext.txt | crates/oc-kit/assets/fonts/OFL-AtkinsonHyperlegibleNext.txt |
| fonts/OFL-JetBrainsMono.txt | crates/oc-kit/assets/fonts/OFL-JetBrainsMono.txt |
| fonts/atkinson-next-400.woff2 | crates/oc-kit/assets/fonts/atkinson-next-400.woff2 |
| fonts/atkinson-next-500.woff2 | crates/oc-kit/assets/fonts/atkinson-next-500.woff2 |
| fonts/atkinson-next-600.woff2 | crates/oc-kit/assets/fonts/atkinson-next-600.woff2 |
| fonts/jetbrains-mono-400.woff2 | crates/oc-kit/assets/fonts/jetbrains-mono-400.woff2 |
| htmx/LICENSE-htmx.txt | crates/oc-kit/assets/vendor/LICENSE-htmx.txt |
| htmx/htmx.min.js | crates/oc-kit/assets/vendor/htmx.min.js |
| icons/LICENSE-lucide.txt | crates/oc-kit/assets/icons/LICENSE-lucide.txt |
| icons/a-large-small.svg | crates/oc-kit/assets/icons/a-large-small.svg |
| icons/check.svg | crates/oc-kit/assets/icons/check.svg |
| icons/chevron-down.svg | crates/oc-kit/assets/icons/chevron-down.svg |
| icons/chevron-right.svg | crates/oc-kit/assets/icons/chevron-right.svg |
| icons/circle-check.svg | crates/oc-kit/assets/icons/circle-check.svg |
| icons/circle-question-mark.svg | bitvault addition from Lucide 1.70.0 (lucide-icons/lucide, icons/circle-question-mark.svg), ISC |
| icons/circle-x.svg | crates/oc-kit/assets/icons/circle-x.svg |
| icons/copy.svg | crates/oc-kit/assets/icons/copy.svg |
| icons/download.svg | crates/oc-kit/assets/icons/download.svg |
| icons/eye-off.svg | crates/oc-kit/assets/icons/eye-off.svg |
| icons/eye.svg | crates/oc-kit/assets/icons/eye.svg |
| icons/file.svg | bitvault addition from Lucide 1.70.0 (lucide-icons/lucide, icons/file.svg), ISC |
| icons/info.svg | crates/oc-kit/assets/icons/info.svg |
| icons/key-round.svg | crates/oc-kit/assets/icons/key-round.svg |
| icons/languages.svg | bitvault addition from Lucide 1.70.0 (lucide-icons/lucide, icons/languages.svg), ISC |
| icons/link.svg | crates/oc-kit/assets/icons/link.svg |
| icons/list.svg | crates/oc-kit/assets/icons/list.svg |
| icons/log-out.svg | crates/oc-kit/assets/icons/log-out.svg |
| icons/monitor.svg | crates/oc-kit/assets/icons/monitor.svg |
| icons/moon.svg | crates/oc-kit/assets/icons/moon.svg |
| icons/pencil.svg | crates/oc-kit/assets/icons/pencil.svg |
| icons/plus.svg | crates/oc-kit/assets/icons/plus.svg |
| icons/qr-code.svg | bitvault addition from Lucide 1.70.0 (lucide-icons/lucide, icons/qr-code.svg), ISC |
| icons/settings.svg | crates/oc-kit/assets/icons/settings.svg |
| icons/share-2.svg | crates/oc-kit/assets/icons/share-2.svg |
| icons/sun.svg | crates/oc-kit/assets/icons/sun.svg |
| icons/trash-2.svg | crates/oc-kit/assets/icons/trash-2.svg |
| icons/triangle-alert.svg | crates/oc-kit/assets/icons/triangle-alert.svg |
| icons/upload.svg | bitvault addition from Lucide 1.70.0 (lucide-icons/lucide, icons/upload.svg), ISC |
| icons/user.svg | crates/oc-kit/assets/icons/user.svg |
| icons/x.svg | crates/oc-kit/assets/icons/x.svg |
| js/busy.js | crates/oc-kit/assets/js/busy.js |
| js/copy.js | crates/oc-kit/assets/js/copy.js |
| js/dialog.js | crates/oc-kit/assets/js/dialog.js |
| js/keys.js | crates/oc-kit/assets/js/keys.js |
| js/menu.js | crates/oc-kit/assets/js/menu.js |
| js/notices.js | crates/oc-kit/assets/js/notices.js |
| js/theme.js | crates/oc-kit/assets/js/theme.js |

The four bitvault additions (file, languages, qr-code, upload) were checked against Lucide release tag 1.70.0, commit b826f0c527e1498f5e46f41ca0277ccab144bf31 (2026-11-05): their shapes match that tag element for element. Only the wrapping `<svg>` attributes differ, rewritten to the manifest's icon format (`class="oc-icon"`, `aria-hidden`, `focusable`, no width, height or stroke-width).

Not copied: prefs.js (it posts to the kit's server endpoint; bitvault has its own assets/js/prefs.js), live.js and htmx-ext-sse.js (no SSE in bitvault).
