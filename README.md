# PatchSignal

PatchSignal is a public vulnerability intelligence dashboard for prioritizing known exploited vulnerabilities using severity, exploit-likelihood, remediation, and activity context.

Live site: <https://patchsignal.org>

PatchSignal is an independent project. It is not affiliated with or endorsed by CISA, NIST/NVD, FIRST, or any other data provider.

## What It Tracks

The main dashboard focuses on known exploited vulnerabilities and presents:

- CVE identifiers, affected vendors, and products
- CVSS severity, score, version, and vector details when available
- EPSS score and percentile
- CISA KEV date-added and due-date context
- Known ransomware-use indicators when available from source data
- Short triage tags and expandable details for investigation workflow

## Threat Actor CVE Activity

PatchSignal also includes a standalone Actor Activity page for source-backed relationships between named threat actors or groups and CVEs.

This page is intentionally conservative. General exploitation in the wild, ransomware-associated exploitation, and named actor attribution are different intelligence states. Actor-to-CVE attribution is uncommon, so the page is designed to track only confirmed or credibly reported public-source relationships.

## Data Methodology

PatchSignal starts with the CISA Known Exploited Vulnerabilities catalog and enriches records with public vulnerability intelligence, including NVD/NIST CVE and CVSS data and FIRST EPSS likelihood data.

Dashboard runtime data is served through the PatchSignal Worker/R2 data path. The Actor Activity page uses a small public static JSON file in `data/`.

Source data belongs to the respective source providers. PatchSignal enriches and presents public data for research, learning, and personal security workflow support.

## Security Reporting

Security issues affecting PatchSignal.org, the frontend, Worker/R2 routes, or this repository should follow the guidance in [SECURITY.md](SECURITY.md).

Do not include sensitive exploit details, working payloads, private credentials, or non-public vulnerability details in public issues or pull requests.

## Maintainer Notes

Deployment and operational notes are in [DEPLOYMENT.md](DEPLOYMENT.md). In particular, direct repo-root Pages uploads are intentionally avoided because local/generated feed files are not public Pages assets.
