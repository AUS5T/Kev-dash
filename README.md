# PatchSignal

PatchSignal is a public vulnerability intelligence dashboard for prioritizing known exploited vulnerabilities using enriched severity, likelihood, and remediation context.

PatchSignal is an independent dashboard. It is not affiliated with or endorsed by CISA, NIST/NVD, FIRST, or any other data provider.

## Live URLs

Frontend:

- <https://patchsignal.org>
- <https://kev-dash.pages.dev>

Worker/data API:

- <https://kev-dash-r2-test.austm999.workers.dev>

## Architecture

- Cloudflare Pages serves the static frontend.
- Cloudflare Worker serves public JSON/text data from R2.
- R2 stores generated dashboard data files.
- Worker cron refreshes feeds every 3 hours.
- A manual admin update route exists and is protected by `ADMIN_TOKEN`.

Current production dashboard data is served by the Worker from R2.

Public data files served by the Worker/R2 path:

- `kev_enriched.json`
- `combined_enriched.json`
- `last_updated.txt`

## Data Sources

PatchSignal starts with the CISA Known Exploited Vulnerabilities catalog, then enriches KEV items with public data from:

- CISA KEV
- NVD/NIST CVE and CVSS details
- FIRST EPSS

The dashboard combines CVSS, EPSS, descriptions, due dates, ransomware indicators, and rule-based triage tags to make KEV prioritization easier to scan.

## Dashboard Features

- Summary cards
- Search, filters, sorting, and pagination
- Column visibility controls
- `Why this matters` triage tags
- Expandable Details row per CVE
- Copy CVE
- Copy summary
- Copy investigation query
- Open NVD
- Dark/light mode
- About and Data Sources pages

## Frontend Asset Versioning

`index.html` references frontend assets with version query strings:

```html
style.css?v=20260630-1
script.js?v=20260630-1
```

When `script.js` or `style.css` changes, bump the version in `index.html`.

This helps prevent users from being stuck on stale cached JavaScript or CSS after a deployment because the browser sees a new asset URL.

## Deployment Workflow

Frontend:

```bash
git push origin main
```

Cloudflare Pages deploys frontend changes automatically from `main`.

Worker:

```bash
cd worker
npx wrangler deploy
```

Use a Worker deploy for route, cron, R2, CORS, or feed/update logic changes.

## Useful Verification Commands

Check that the custom-domain HTML references the expected asset versions:

```bash
curl -sL "https://patchsignal.org?v=$(date +%s)" | grep -n "style.css\\|script.js"
```

Check that deployed JavaScript includes current dashboard behavior:

```bash
curl -sL "https://patchsignal.org/script.js?v=20260630-1" | grep -n "Copy investigation query\\|appendDetailSection"
```

Check the Worker timestamp:

```bash
curl https://kev-dash-r2-test.austm999.workers.dev/last_updated.txt
```

Check CORS for the custom domain:

```bash
curl -i -H "Origin: https://patchsignal.org" https://kev-dash-r2-test.austm999.workers.dev/last_updated.txt
```

Check frontend response headers:

```bash
curl -I https://patchsignal.org
```

## Security Notes

- The admin update route requires `ADMIN_TOKEN`.
- Do not use wildcard CORS for admin routes.
- Public data routes use an explicit CORS origin allowlist.
- Unknown Worker routes return `404`.
- Frontend rendering should remain XSS-safe: use DOM APIs and `textContent`, not `innerHTML`, for feed data.
- Basic security headers are configured in `_headers`.
- Secrets, tokens, credentials, and private config should never be committed.

## Local Preview

```bash
python3 -m http.server 8000
```

Then open:

```text
http://localhost:8000
```

## Maintenance Checklist

- If frontend JS/CSS changes: bump the asset version in `index.html`.
- If Worker CORS origins change: update the Worker allowlist and deploy the Worker.
- If feed/update logic changes: deploy the Worker.
- If static frontend changes: push `main` and verify the Cloudflare Pages deployment.
- After deployment: verify both the custom domain and the Pages URL.

## Project Structure

```text
Kev-dash
|-- index.html
|-- about.html
|-- sources.html
|-- style.css
|-- script.js
|-- _headers
|-- kev_enriched.json          # Legacy/static fallback data, not production source of truth
|-- combined_enriched.json     # Legacy/static fallback data, not production source of truth
|-- last_updated.txt           # Legacy/static fallback timestamp, not production source of truth
|-- worker/
|   |-- wrangler.toml
|   `-- src/
|-- feed/
`-- .github/workflows/update-feeds.yml  # Legacy/optional manual backfill workflow
```
