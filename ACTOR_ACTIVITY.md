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

Before deploying approved Actor Activity changes, run:

```bash
python3 tools/validate_actor_activity.py
```
