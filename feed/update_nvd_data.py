import os
import json
import time
import requests
from datetime import datetime, timedelta

# === Config ===
NVD_API_KEY = os.getenv("NVD_API_KEY")
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OUTPUT_FILE = "nvd_data.json"
HEADERS = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
LOOKBACK_DAYS = 30
MAX_RETRIES = 3
REQUEST_TIMEOUT = (10, 60)

# === Fetch CVEs in 30-day chunks ===
def fetch_recent_cves():
    print(f"\n🔄 Fetching CVEs from the last {LOOKBACK_DAYS} days in 30-day chunks from NVD...", flush=True)

    all_results = []
    page_size = 2000

    end = datetime.utcnow()
    start = end - timedelta(days=LOOKBACK_DAYS)

    while start < end:
        chunk_start = start.isoformat(timespec='seconds') + "Z"
        chunk_end_dt = min(start + timedelta(days=30), end)
        chunk_end = chunk_end_dt.isoformat(timespec='seconds') + "Z"
        print(f" 📆 Fetching from {chunk_start} to {chunk_end}", flush=True)

        start_index = 0
        while True:
            params = {
                "startIndex": start_index,
                "resultsPerPage": page_size,
                "pubStartDate": chunk_start,
                "pubEndDate": chunk_end
            }

            data = None
            for attempt in range(1, MAX_RETRIES + 1):
                try:
                    print(
                        f"  🔎 Requesting page startIndex={start_index} "
                        f"(attempt {attempt}/{MAX_RETRIES})",
                        flush=True,
                    )
                    response = requests.get(
                        BASE_URL,
                        headers=HEADERS,
                        params=params,
                        timeout=REQUEST_TIMEOUT,
                    )
                    if response.status_code == 404:
                        print(f"❌ 404 Not Found: Skipping range {chunk_start} → {chunk_end}", flush=True)
                        break
                    response.raise_for_status()
                    data = response.json()
                    break
                except requests.exceptions.HTTPError as e:
                    print(f"⚠️ HTTP error fetching page startIndex={start_index}: {e}", flush=True)
                    if attempt == MAX_RETRIES:
                        raise SystemExit(
                            f"Failed to fetch NVD page startIndex={start_index} "
                            f"after {MAX_RETRIES} attempts."
                        ) from e
                    print("⏳ Retrying in 10 seconds...", flush=True)
                    time.sleep(10)
                except requests.exceptions.RequestException as e:
                    print(f"⚠️ Network error fetching page startIndex={start_index}: {e}", flush=True)
                    if attempt == MAX_RETRIES:
                        raise SystemExit(
                            f"Failed to fetch NVD page startIndex={start_index} "
                            f"after {MAX_RETRIES} attempts."
                        ) from e
                    print("⏳ Retrying in 10 seconds...", flush=True)
                    time.sleep(10)

            if data is None:
                break

            items = data.get("vulnerabilities", [])
            if not items:
                print("  ⚠️ No items returned, breaking loop for this chunk.", flush=True)
                break

            all_results.extend(items)
            print(f"  📦 Retrieved {len(items)} CVEs (total: {len(all_results)})", flush=True)
            time.sleep(1)

            if len(items) < page_size:
                break

            start_index += page_size

        start += timedelta(days=30)

    return all_results

# === Save to File ===
def save_to_file(data):
    with open(OUTPUT_FILE, "w") as f:
        json.dump({"vulnerabilities": data}, f, indent=2)
    print(f"\n💾 Saved {len(data)} CVEs to {OUTPUT_FILE}", flush=True)

# === Main ===
if __name__ == "__main__":
    if not NVD_API_KEY:
        print("⚠️ WARNING: No NVD_API_KEY set. You may hit rate limits.", flush=True)
    cves = fetch_recent_cves()
    save_to_file(cves)
