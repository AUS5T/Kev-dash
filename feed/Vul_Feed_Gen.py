import os
import json
import time
import random
import requests
import datetime
from requests.adapters import HTTPAdapter, Retry
from feedgen.feed import FeedGenerator
from collections import Counter

ARCHIVE_FILE = "cves_archive.json"
KEV_OUTPUT_FILE = "kev_enriched.json"
COMBINED_OUTPUT_FILE = "combined_enriched.json"
CACHED_NVD_FIELDS = (
    "cvssScore",
    "cvssSeverity",
    "cvssVector",
    "cvssVersion",
    "description",
)

# Correct v2 endpoint: plural `cves` and query param `cveId`
NVD_LOOKUP_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Keep apiKey if present; add a polite User-Agent per NVD guidance
NVD_API_KEY = os.getenv("NVD_API_KEY")
HEADERS = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
HEADERS.setdefault("User-Agent", "vul-feed-gen/1.0 (contact: security@example.com)")
HEADERS.setdefault("Accept", "application/json")

# Env-tunable knobs
FALLBACK_BUDGET = int(os.getenv("NVD_FALLBACK_BUDGET", "40"))   # max single-CVE lookups per run
BASE_SLEEP = float(os.getenv("NVD_FALLBACK_DELAY_BASE", "0.3")) # base delay between attempts

# ---------- Networking helpers ----------

def _nvd_session():
    """Session with retries for 429/5xx and exponential backoff."""
    retries = Retry(
        total=3,                    # reduced for speed
        backoff_factor=0.5,         # 0.5s, 1s, 2s
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"]
    )
    sess = requests.Session()
    sess.headers.update(HEADERS)
    sess.mount("https://", HTTPAdapter(max_retries=retries))
    return sess

def chunked(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]

# ---------- EPSS ----------

def load_epss_targeted(cve_ids):
    """Fetch EPSS only for KEV CVEs (faster)."""
    print(f"Fetching targeted EPSS scores for {len(cve_ids)} CVEs...")
    epss_map = {}
    base = "https://api.first.org/data/v1/epss"
    try:
        with requests.Session() as s:
            for chunk in chunked(list(set(cve_ids)), 200):
                params = {"cve": ",".join(chunk)}
                r = s.get(base, params=params, timeout=30)
                time.sleep(0.2)
                r.raise_for_status()
                for row in r.json().get("data", []):
                    epss_map[row["cve"]] = row
        print(f"Loaded EPSS scores for {len(epss_map)} CVEs (targeted).")
    except Exception as e:
        print(f"Error loading EPSS data: {e}")
    return epss_map

# ---------- KEV/NVD fetching ----------

def fetch_kev():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        response = requests.get(url)
        response.raise_for_status()
        kev_data = response.json().get("vulnerabilities", [])
        print(f"Loaded {len(kev_data)} CVEs from CISA KEV feed.")
        return kev_data
    except Exception as e:
        print(f"Error fetching KEV data: {e}")
        return []

def load_local_nvd_data():
    try:
        with open("nvd_data.json", "r") as f:
            return json.load(f).get("vulnerabilities", [])
    except FileNotFoundError:
        print("Optional local nvd_data.json not found; using cache and exact-CVE NVD fallback.")
        return []
    except Exception as e:
        print(f"Error loading NVD JSON file: {e}")
        return []

def load_existing_kev_cache():
    try:
        with open(KEV_OUTPUT_FILE, "r") as f:
            existing = json.load(f)
    except FileNotFoundError:
        print(f"No existing {KEV_OUTPUT_FILE} cache found.")
        return {}
    except Exception as e:
        print(f"Error loading {KEV_OUTPUT_FILE} cache: {e}")
        return {}

    cache = {
        item.get("cveID"): item
        for item in existing
        if isinstance(item, dict) and item.get("cveID")
    }
    print(f"Loaded {len(cache)} cached KEV records from {KEV_OUTPUT_FILE}.")
    return cache

def has_cached_nvd_enrichment(cached):
    if not cached:
        return False

    cvss_score = cached.get("cvssScore")
    description = cached.get("description")
    has_cvss = cvss_score not in (None, "", "N/A") and "<a " not in str(cvss_score)
    has_description = description not in (None, "", "N/A")
    return has_cvss or has_description

def get_cached_nvd_enrichment(cached):
    cached_fields = {
        field: cached.get(field, "N/A")
        for field in CACHED_NVD_FIELDS
    }
    return {
        "cvss": {
            "cvssScore": cached_fields["cvssScore"],
            "cvssSeverity": cached_fields["cvssSeverity"],
            "cvssVector": cached_fields["cvssVector"],
            "cvssVersion": cached_fields["cvssVersion"],
        },
        "description": cached_fields["description"],
    }

def extract_cvss_data(metrics):
    versions_priority = [
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0")
    ]
    for key, version in versions_priority:
        metric_list = metrics.get(key, [])
        if not metric_list:
            continue
        for metric in metric_list:
            cvss_data = metric.get("cvssData", metric)
            score = cvss_data.get("baseScore")
            if score is not None:
                return {
                    "cvssScore": score,
                    "cvssVector": cvss_data.get("vectorString", "N/A"),
                    "cvssSeverity": cvss_data.get(
                        "baseSeverity",
                        f"Legacy ({version})" if version == "2.0" else "N/A",
                    ),
                    "cvssVersion": version,
                }
    return {
        "cvssScore": "N/A",
        "cvssVector": "N/A",
        "cvssSeverity": "N/A",
        "cvssVersion": "N/A",
    }

# Hardened fallback using /cves/2.0?cveId=... with budget, Retry-After, and jitter
def fetch_cvss_from_nvd_api(cve_id):
    cve = (cve_id or "").strip().upper()
    if not cve.startswith("CVE-"):
        print(f"[fallback] Skipping invalid CVE id: {cve_id!r}")
        return extract_cvss_data({}), []

    # respect per-run budget
    if fetch_cvss_from_nvd_api.budget <= 0:
        # Quietly skip to keep run fast and avoid 429 storms
        return extract_cvss_data({}), []
    fetch_cvss_from_nvd_api.budget -= 1

    sess = _nvd_session()
    resp = None
    tries = 3
    for attempt in range(1, tries + 1):
        try:
            resp = sess.get(NVD_LOOKUP_URL, params={"cveId": cve}, timeout=30)
            if resp.status_code == 429:
                # Respect Retry-After if present; otherwise exponential + jitter
                retry_after = resp.headers.get("Retry-After")
                if retry_after is not None:
                    wait = max(2.0, float(retry_after))
                else:
                    wait = (BASE_SLEEP * (2 ** (attempt - 1))) + random.uniform(0, 0.25)
                print(f"[fallback] 429 for {cve}; sleeping {wait:.2f}s (attempt {attempt}/{tries})")
                time.sleep(wait)
                continue

            resp.raise_for_status()
            data = resp.json()
            if data.get("totalResults", 0) == 0:
                return extract_cvss_data({}), []
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return extract_cvss_data({}), []
            cve_obj = vulns[0].get("cve", {})
            metrics = cve_obj.get("metrics", {})
            descriptions = cve_obj.get("descriptions", []) or []
            # Friendly pacing
            time.sleep(random.uniform(0.05, 0.15))
            return extract_cvss_data(metrics), descriptions

        except requests.RequestException as e:
            status = getattr(resp, "status_code", "?")
            if attempt == tries:
                print(f"Failed fallback NVD API fetch for {cve}: {e} (HTTP {status})")
                break
            wait = (BASE_SLEEP * (2 ** (attempt - 1))) + random.uniform(0, 0.25)
            print(f"[fallback] Error for {cve} (HTTP {status}), retrying in {wait:.2f}s...")
            time.sleep(wait)

    # On failure, return N/A gracefully
    return extract_cvss_data({}), []

# initialize static attribute
fetch_cvss_from_nvd_api.budget = FALLBACK_BUDGET

# ---------- Enrichment and output ----------

def enrich_kev_with_cvss(kev_entries, nvd_data, epss_map, kev_cache):
    enriched = []
    nvd_map = {
        item["cve"].get("id", item["cve"].get("CVE_data_meta", {}).get("ID", ""))
        : item
        for item in nvd_data
        if "cve" in item
    }

    for kev in kev_entries:
        cve_id = kev.get("cveID")
        nvd_entry = nvd_map.get(cve_id)
        cached = kev_cache.get(cve_id)

        if has_cached_nvd_enrichment(cached):
            cached_enrichment = get_cached_nvd_enrichment(cached)
            cvss = cached_enrichment["cvss"]
            description = cached_enrichment["description"]
        elif nvd_entry:
            metrics = nvd_entry.get("cve", {}).get("metrics", {})
            descriptions = nvd_entry.get("cve", {}).get("descriptions", [])
            cvss = extract_cvss_data(metrics)
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"), "N/A"
            )
        else:
            cvss, descriptions = fetch_cvss_from_nvd_api(cve_id)
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"), "N/A"
            )

        if cvss["cvssScore"] == "N/A":
            cvss["cvssScore"] = (
                f'<a href="https://nvd.nist.gov/vuln/detail/{cve_id}" target="_blank">N/A</a>'
            )

        epss_entry = epss_map.get(cve_id, {})
        epss_score = float(epss_entry.get("epss", 0)) if "epss" in epss_entry else "N/A"
        epss_percentile = (
            float(epss_entry.get("percentile", 0))
            if "percentile" in epss_entry
            else "N/A"
        )

        enriched.append(
            {
                "cveID": cve_id,
                "vendor": kev.get("vendorProject"),
                "product": kev.get("product"),
                "vulnerabilityName": kev.get("vulnerabilityName"),
                "requiredAction": kev.get("requiredAction"),
                "dueDate": kev.get("dueDate"),
                "dateAdded": kev.get("dateAdded"),
                "cvssScore": cvss["cvssScore"],
                "cvssSeverity": cvss["cvssSeverity"],
                "cvssVector": cvss["cvssVector"],
                "cvssVersion": cvss["cvssVersion"],
                "epssScore": epss_score,
                "epssPercentile": epss_percentile,
                "description": description,
                "notes": kev.get("notes", ""),
                "source": "KEV",
            }
        )

    print(f"Enriched {len(enriched)} KEV entries with CVSS, EPSS, and descriptions.")
    if FALLBACK_BUDGET > 0:
        used = FALLBACK_BUDGET - fetch_cvss_from_nvd_api.budget
        print(f"[fallback] NVD single-CVE lookups used: {used}/{FALLBACK_BUDGET}")
    return enriched

def save_enriched_kev(enriched):
    with open(KEV_OUTPUT_FILE, "w") as f:
        json.dump(enriched, f, indent=2)
    print(f"Saved {KEV_OUTPUT_FILE}")

    if os.getenv("SKIP_RSS", "0") == "1":
        print("Skipping RSS generation (SKIP_RSS=1).")
        return

    fg = FeedGenerator()
    fg.title("Known Exploited Vulnerabilities (CISA KEV)")
    fg.link(
        href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        rel="alternate",
    )
    fg.description("Enriched CISA KEV feed with CVSS and EPSS scores")
    fg.language("en")

    for item in enriched:
        fe = fg.add_entry()
        fe.title(f"{item['cveID']} - {item['cvssSeverity']} ({item['cvssScore']})")
        fe.link(href=f"https://nvd.nist.gov/vuln/detail/{item['cveID']}")
        fe.description(item.get("vulnerabilityName", ""))
        fe.content(
            f"""
<p><strong>Vendor:</strong> {item['vendor']}</p>
<p><strong>Product:</strong> {item['product']}</p>
<p><strong>CVSS:</strong> {item['cvssSeverity']} ({item['cvssScore']})</p>
<p><strong>EPSS:</strong> {item['epssScore']} ({item['epssPercentile']})</p>
<p><strong>Due Date:</strong> {item['dueDate']}</p>
<p><strong>Description:</strong> {item['description']}</p>
<p><strong>Required Action:</strong> {item['requiredAction']}</p>
<p><strong>Notes:</strong> {item['notes']}</p>
""",
            type="html",
        )

    fg.rss_file("kev_enriched.xml")
    print("Saved kev_enriched.xml")

def update_combined_feed():
    print(f"Starting KEV enrichment at {datetime.datetime.utcnow().isoformat()}")
    kev = fetch_kev()
    if not kev:
        return
    kev_cache = load_existing_kev_cache()
    nvd = load_local_nvd_data()

    kev_ids = [k.get("cveID") for k in kev if k.get("cveID")]
    epss = load_epss_targeted(kev_ids)  # targeted EPSS
    print(f"DEBUG: EPSS entries loaded: {len(epss)}")

    def audit_cvss_versions(nvd_data):
        counter = Counter()
        for item in nvd_data:
            for k in item.get("cve", {}).get("metrics", {}):
                if k.startswith("cvssMetricV"):
                    counter[k] += 1
        print("CVSS versions found in NVD data:")
        for version, count in counter.items():
            print(f"  {version}: {count}")

    audit_cvss_versions(nvd)

    enriched = enrich_kev_with_cvss(kev, nvd, epss, kev_cache)
    save_enriched_kev(enriched)

    with open(COMBINED_OUTPUT_FILE, "w") as f:
        json.dump(enriched, f, indent=2)
    print(f"Saved {COMBINED_OUTPUT_FILE}")

if __name__ == "__main__":
    update_combined_feed()
