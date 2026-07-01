# PatchSignal Deployment

PatchSignal uses Cloudflare Pages for the static frontend and a separate Cloudflare Worker/R2 path for dashboard runtime data.

Do not deploy the repo root directly with:

```bash
npx wrangler pages deploy . --project-name kev-dash
```

That command points Wrangler at every local file under the repo root. This repo can contain local/generated source data such as `feed/nvd_data.json`, which is about 100 MiB and exceeds Cloudflare Pages' 25 MiB per-file asset limit. That file is not a Pages asset.

## Safe Pages Deploy

Use:

```bash
bash deploy-pages.sh
```

The script recreates a clean upload folder at:

```text
../kev-dash-pages-upload
```

It copies only public site assets into that folder, checks for files larger than 25 MiB, and deploys the clean folder with:

```bash
npx wrangler pages deploy ../kev-dash-pages-upload --project-name kev-dash
```

## Included in Pages Upload

The Pages upload is intended to include:

- `index.html`
- `about.html`
- `sources.html`
- `actor-activity.html`
- `style.css`
- `script.js`
- `assets/`
- `data/`
- `_headers`
- `robots.txt`
- `.nojekyll`
- `kev_enriched.json`
- `combined_enriched.json`
- `last_updated.txt`

## Excluded from Pages Upload

The upload intentionally excludes:

- `.git/`
- `.github/`
- `.wrangler/`
- `worker/`
- `feed/`
- `node_modules/`
- `.venv/`
- `__pycache__/`
- `.pytest_cache/`
- `.env*`
- `*.log`
- `.DS_Store`
- `README.md`
- `SECURITY.md`
- `.gitignore`
- `.assetsignore`

## Data Architecture

The main dashboard is a static frontend, but its runtime vulnerability data is served from the Worker/R2 endpoint. The frontend fetches dashboard data from the Worker, not from `feed/nvd_data.json`.

The `feed/` directory contains local/generated feed tooling and source/cache data. `feed/nvd_data.json` stays local/generated and should not be uploaded to Cloudflare Pages.

The Actor Activity page uses the small public static file:

```text
data/actor_cve_links.json
```

The current expected response is:

```json
[]
```

## After Deploy

Check:

- <https://patchsignal.org/>
- <https://patchsignal.org/actor-activity>
- <https://patchsignal.org/data/actor_cve_links.json>

The current Actor Activity data response should be:

```json
[]
```

## Worker Deploys

Worker/R2 deploys are separate from Pages deploys. If Worker routes, cron behavior, R2 bindings, CORS, or feed-update logic changes, deploy from the `worker/` directory instead of using the Pages deploy script.
