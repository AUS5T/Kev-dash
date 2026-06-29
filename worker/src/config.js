export const TEST_OBJECT_KEY = "test-r2.txt";
export const PAGES_ORIGIN = "https://kev-dash.pages.dev";
export const CISA_KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
export const EPSS_API_URL = "https://api.first.org/data/v1/epss";
export const NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
export const EPSS_BATCH_SIZE = 75;
export const NVD_FALLBACK_CAP = 10;
export const ALLOWED_CORS_ORIGINS = new Set([
  "https://kev-dash.pages.dev",
  "http://localhost:8000",
]);

export const DATA_FILES = [
  {
    key: "kev_enriched.json",
    contentType: "application/json; charset=utf-8",
  },
  {
    key: "combined_enriched.json",
    contentType: "application/json; charset=utf-8",
  },
  {
    key: "last_updated.txt",
    contentType: "text/plain; charset=utf-8",
  },
];
