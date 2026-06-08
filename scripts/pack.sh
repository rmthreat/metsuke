#!/usr/bin/env bash
# Build a Chrome Web Store-ready zip (and optionally an unpacked dir) for Metsuke.
# Bundles only the runtime files; docs/, tests/, .idea/, .git/ are excluded.
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

version="$(node -e "process.stdout.write(require('./manifest.json').version)")"
out_dir="dist"
stage="${out_dir}/metsuke-v${version}"
zip_path="${out_dir}/metsuke-v${version}.zip"

# Runtime files that must ship in the package.
files=(
  manifest.json
  detector.js
  content.js
  background.js
  popup.html
  popup.js
  popup.css
  icons
  _locales
)

# Validate all locale JSON before packaging.
for locale_file in _locales/*/messages.json; do
  node -e "JSON.parse(require('fs').readFileSync('${locale_file}','utf8'))" \
    || { echo "Invalid JSON: ${locale_file}" >&2; exit 1; }
done

rm -rf "${stage}" "${zip_path}"
mkdir -p "${stage}"
cp -R "${files[@]}" "${stage}/"

# Strip macOS cruft, then zip with stored paths relative to the stage dir.
find "${stage}" -name '.DS_Store' -delete
( cd "${stage}" && zip -rqX "../$(basename "${zip_path}")" . )

echo "Packed: ${zip_path}"
echo "Unpacked dir (for chrome://extensions 'Load unpacked'): ${stage}"
