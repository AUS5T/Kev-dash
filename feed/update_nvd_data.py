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

# === Fetch CVEs in 30-day chunks for last 180 days ===
def fetch_recent_cves():
    print("\n🔄 Fetching CVEs in 30-day chunks from NVD...")

    all_results = []
    page_size = 2000

    end = datetime.utcnow()
    start = end - timedelta(days=180)

    while start < end:
        chunk_start = start.isoformat(timespec='seconds') + "Z"
        chunk_end_dt = min(start + timedelta(days=30), end)
        chunk_end = chunk_end_dt.isoformat(timespec='seconds') + "Z"
        print(f" 📆 Fetching from {chunk_start} to {chunk_end}")

        start_index = 0
        while True:
            params = {
                "startIndex": start_index,
                "resultsPerPage": page_size,
                "pubStartDate": chunk_start,
                "pubEndDate": chunk_end
            }

            try:
                response = requests.get(BASE_URL, headers=HEADERS, params=params, timeout=30)
                if response.status_code == 404:
                    print(f"❌ 404 Not Found: Skipping range {chunk_start} → {chunk_end}")
                    break
                response.raise_for_status()
                data = response.json()
            except requests.exceptions.HTTPError as e:
                print(f"⚠️ HTTP error {e} → Skipping this range.")
                break
            except Exception as e:
                print(f"⚠️ Network error fetching page {start_index} → {e}")
                print("⏳ Retrying in 10 seconds...")
                time.sleep(10)
                continue

            items = data.get("vulnerabilities", [])
            if not items:
                print("  ⚠️ No items returned, breaking loop for this chunk.")
                break

            all_results.extend(items)
            print(f"  📦 Retrieved {len(items)} CVEs (total: {len(all_results)})")

            if len(items) < page_size:
                break

            start_index += page_size
            time.sleep(1.2)  # Respect NVD rate limit

        start += timedelta(days=30)

    return all_results

# === Save to File ===
def save_to_file(data):
    with open(OUTPUT_FILE, "w") as f:
        json.dump({"vulnerabilities": data}, f, indent=2)
    print(f"\n💾 Saved {len(data)} CVEs to {OUTPUT_FILE}")

# === Main ===
if __name__ == "__main__":
    if not NVD_API_KEY:
        print("⚠️ WARNING: No NVD_API_KEY set. You may hit rate limits.")
    cves = fetch_recent_cves()
    save_to_file(cves)
