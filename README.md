# Kev-dash

**Known Exploited Vulnerabilities dashboard** - a static HTML/CSS/JS dashboard for reviewing CISA KEV entries enriched with CVSS, EPSS, vendor/product, due date, and description data.

Live dashboard: [https://kev-dash.pages.dev/](https://kev-dash.pages.dev/)

This is a private consolidated repository. The deployed Cloudflare Pages dashboard and its static data files are publicly served.

## Features

- Sortable and filterable vulnerability table
- Search by CVE ID, vendor, or product
- Severity, date range, and attack vector filters
- CVSS score, version, and vector display
- EPSS score and percentile display
- CSV export for reporting and triage
- Dark mode toggle
- Collapsible long descriptions and CVSS vectors
- Last-updated timestamp display

## How It Works

Kev-dash uses a cache-first generator workflow built around the CISA KEV catalog.

- CISA KEV is the source of truth for the CVEs included in the dashboard.
- Existing `kev_enriched.json` data is used as a cache to preserve prior enrichment and avoid unnecessary refetching.
- NVD is used for exact-CVE fallback enrichment when cached CVSS, vector, vendor/product, or description data is missing or stale.
- EPSS is fetched only for targeted KEV CVEs, with batching fixed for targeted updates.
- Broad NVD date-window polling is no longer part of the normal workflow.
- Broad `nvd_data.json` support is optional only and is not required for normal updates.

The dashboard serves these data files:

- `kev_enriched.json`
- `combined_enriched.json`
- `last_updated.txt`

Cloudflare Worker, R2, and KV scheduled updates are future improvements, not current behavior.

## Manual Update

Feed updates are run manually through GitHub Actions:

- Workflow: `.github/workflows/update-feeds.yml`
- Action name: **Update Feeds**
- Trigger: manual dispatch from the GitHub Actions tab

The workflow regenerates the dashboard data files and updates the timestamp. It does not run as an hourly scheduled job.

## Hosting

The dashboard is hosted on Cloudflare Pages:

[https://kev-dash.pages.dev/](https://kev-dash.pages.dev/)

GitHub Pages is no longer the primary hosting target.

## Project Structure

```text
Kev-dash
|-- index.html                 # Dashboard UI
|-- style.css                  # Light/dark visual styling
|-- script.js                  # Data loading, filtering, sorting, pagination, export
|-- kev_enriched.json          # Primary enriched KEV data served by the dashboard
|-- combined_enriched.json     # Consolidated enriched data served by the dashboard
|-- last_updated.txt           # Timestamp displayed by the dashboard
|-- .github/workflows/update-feeds.yml
```

## Credits

- CISA Known Exploited Vulnerabilities catalog
- NVD CVE, CVSS, vendor/product, and description data
- FIRST.org EPSS exploitation likelihood data
- GitHub Actions for manual feed generation
- Cloudflare Pages for static hosting
