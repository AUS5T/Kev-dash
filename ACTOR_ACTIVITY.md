# Actor Activity Data

`data/actor_cve_links.json` contains approved public records only. Each record should describe a reviewed, source-backed relationship between a named threat actor or group and a CVE.

GitHub Issues may be used for actor attribution suggestions, CVE corrections, and source updates. Suggestions are not automatically published. A maintainer must review the source, confidence level, relationship wording, and evidence summary before a record is added to the public JSON file.

Actor-to-CVE attribution should be handled conservatively. General exploitation in the wild, ransomware-associated exploitation, and named actor attribution are different intelligence states and should not be merged unless the source supports that claim.

Future automation should create unpublished candidate records only. Automated matches, summaries, or confidence guesses must not publish directly to `data/actor_cve_links.json`.

## Candidate Queue

Unreviewed leads belong in a local candidate queue, not in the public approved-record file. Candidate records may come from manual research, GitHub Issues, or future automation, but they are review material only and are not public attribution claims.

Use `review/actor_activity_candidates.example.json` as the trackable empty example. A real local queue should use:

```text
review/actor_activity_candidates.json
```

Candidate records must be reviewed before they become approved records in `data/actor_cve_links.json`. Automation should create candidates only, and candidate files should not be deployed as public site data.

Validate candidate files with:

```bash
python3 tools/validate_actor_activity_candidates.py review/actor_activity_candidates.example.json
```

## Discovery Inputs

Future discovery automation should use explicit review inputs that define where it may look and what actor or group strings it may search for.

`review/source_watchlist.example.json` is the safe-to-track example for source watchlists. Source watchlists define allowed public sources for future discovery work, such as government advisories, vendor blogs, security research, CERT pages, and security news sources.

`review/actor_aliases.example.json` is the safe-to-track example for actor alias lists. Actor alias lists define display names, aliases, actor types, and avoid terms that future automation may use for matching.

These files are discovery inputs, not public attribution claims. Real local versions may be kept private if desired:

```text
review/source_watchlist.json
review/actor_aliases.json
```

Automation must still write only to unpublished candidate records. Human review is required before any candidate becomes an approved public record.

Validate discovery input examples with:

```bash
python3 tools/validate_actor_activity_sources.py review/source_watchlist.example.json
python3 tools/validate_actor_aliases.py review/actor_aliases.example.json
```

Before deploying approved Actor Activity changes, run:

```bash
python3 tools/validate_actor_activity.py
```
