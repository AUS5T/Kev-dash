# Security Guide

PatchSignal is a public vulnerability intelligence dashboard. It displays public vulnerability data only. The repository and deployment process must not contain secrets, credentials, private customer data, or internal-only notes.

## Reporting Security Issues

Security issues affecting PatchSignal.org, the PatchSignal frontend, the Worker/R2 routes, or this repository should be reported through GitHub private vulnerability reporting once it is enabled for the repository.

Do not include sensitive exploit details, working payloads, private credentials, or non-public vulnerability details in public issues, screenshots, commits, logs, pull request comments, or discussions.

This security reporting path is for issues affecting PatchSignal itself. General CVE corrections, source-data updates, and threat actor attribution submissions should be handled through the project's normal data review process, not as security vulnerabilities in PatchSignal.

## Secrets Handling

Do not commit API keys, tokens, credentials, or secrets.

`ADMIN_TOKEN` must be stored as a Cloudflare Worker secret. It must not be placed in `wrangler.toml`, JavaScript, HTML, screenshots, logs, or committed config.

## Worker Route Rules

Public `GET` routes may serve public vulnerability data only.

Public routes must not trigger writes, updates, or admin behavior. Manual update/admin routes must require authentication. Unknown routes should return `404`.

## Frontend Rendering Rules

Treat upstream vulnerability data as untrusted.

Render feed data as text, not HTML. Avoid `innerHTML` for third-party data. Validate CVE IDs before creating external links. External links should use `rel="noopener noreferrer"`.

## Deployment Notes

Cloudflare Pages serves the frontend. Cloudflare Worker handles public data routes and scheduled refreshes.

Frontend changes deploy through Cloudflare Pages. Worker route or cron changes require:

```bash
cd worker
wrangler deploy
```

The dashboard timestamp shows the most recent completed KEV check.

## Security Headers

Basic browser hardening headers are configured through `_headers`.

Content Security Policy should be added carefully later because inline scripts and external resources may need to be handled first.

## Files That Should Not Be Committed

- Local backup images
- Local generated feed archives
- API outputs not intended for the repo
- Secrets or token files
