#!/usr/bin/env bash
set -euo pipefail

UPLOAD_DIR="../kev-dash-pages-upload"

echo "PatchSignal Pages deploy helper"
echo "1. Validating Actor Activity data"
python3 tools/validate_actor_activity.py

echo "2. Recreating clean upload folder: ${UPLOAD_DIR}"
rm -rf "${UPLOAD_DIR}"
mkdir -p "${UPLOAD_DIR}"

echo "3. Copying public Pages assets only"
rsync -av \
  --exclude='.git/' \
  --exclude='.github/' \
  --exclude='.wrangler/' \
  --exclude='worker/' \
  --exclude='feed/' \
  --exclude='node_modules/' \
  --exclude='.venv/' \
  --exclude='__pycache__/' \
  --exclude='.pytest_cache/' \
  --exclude='.env*' \
  --exclude='*.log' \
  --exclude='.DS_Store' \
  --exclude='README.md' \
  --exclude='SECURITY.md' \
  --exclude='.gitignore' \
  --exclude='.assetsignore' \
  --include='/index.html' \
  --include='/about.html' \
  --include='/sources.html' \
  --include='/actor-activity.html' \
  --include='/security-contact.html' \
  --include='/style.css' \
  --include='/script.js' \
  --include='/assets/***' \
  --include='/data/***' \
  --include='/.well-known/***' \
  --include='/_headers' \
  --include='/robots.txt' \
  --include='/.nojekyll' \
  --include='/kev_enriched.json' \
  --include='/combined_enriched.json' \
  --include='/last_updated.txt' \
  --exclude='*' \
  ./ "${UPLOAD_DIR}/"

echo "4. Checking upload folder for files larger than 25 MiB"
oversized_files="$(find "${UPLOAD_DIR}" -type f -size +25M -print)"

if [[ -n "${oversized_files}" ]]; then
  echo "Found files larger than Cloudflare Pages' 25 MiB per-file limit:"
  echo "${oversized_files}"
  echo "Aborting before deploy."
  exit 1
fi

echo "5. No oversized files found"
echo "6. Deploying clean upload folder to Cloudflare Pages"
npx wrangler pages deploy "${UPLOAD_DIR}" --project-name kev-dash

echo "Deploy command completed"
