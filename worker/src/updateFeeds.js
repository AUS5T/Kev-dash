import { CISA_KEV_URL } from "./config.js";
import { getR2Object, hasKevDataBinding } from "./r2.js";

const KEV_CACHE_KEY = "kev_enriched.json";

export async function runUpdateFeedsReadOnlySkeleton(env) {
  const warnings = [];

  if (!hasKevDataBinding(env)) {
    return {
      status: 500,
      body: {
        ok: false,
        mode: "read-only-skeleton",
        error: "Missing R2 binding: KEV_DATA",
        cacheRecordsLoaded: 0,
        cisaKevRecordsLoaded: 0,
        wouldWrite: false,
        wouldFetchEpss: false,
        wouldFetchNvd: false,
        warnings,
      },
    };
  }

  const cacheObject = await getR2Object(env, KEV_CACHE_KEY);

  if (!cacheObject) {
    return {
      status: 404,
      body: {
        ok: false,
        mode: "read-only-skeleton",
        error: `R2 cache object not found: ${KEV_CACHE_KEY}`,
        cacheRecordsLoaded: 0,
        cisaKevRecordsLoaded: 0,
        wouldWrite: false,
        wouldFetchEpss: false,
        wouldFetchNvd: false,
        warnings,
      },
    };
  }

  let cacheRecords;
  try {
    cacheRecords = await cacheObject.json();
  } catch (error) {
    return {
      status: 500,
      body: {
        ok: false,
        mode: "read-only-skeleton",
        error: `Failed to parse R2 cache object ${KEV_CACHE_KEY} as JSON.`,
        detail: error instanceof Error ? error.message : String(error),
        cacheRecordsLoaded: 0,
        cisaKevRecordsLoaded: 0,
        wouldWrite: false,
        wouldFetchEpss: false,
        wouldFetchNvd: false,
        warnings,
      },
    };
  }

  if (!Array.isArray(cacheRecords)) {
    return {
      status: 500,
      body: {
        ok: false,
        mode: "read-only-skeleton",
        error: `R2 cache object ${KEV_CACHE_KEY} must be a JSON array.`,
        cacheRecordsLoaded: 0,
        cisaKevRecordsLoaded: 0,
        wouldWrite: false,
        wouldFetchEpss: false,
        wouldFetchNvd: false,
        warnings,
      },
    };
  }

  const cisaResponse = await fetch(CISA_KEV_URL, {
    headers: {
      accept: "application/json",
    },
  });

  if (!cisaResponse.ok) {
    return {
      status: 502,
      body: {
        ok: false,
        mode: "read-only-skeleton",
        error: "Failed to fetch live CISA KEV feed.",
        cisaStatus: cisaResponse.status,
        cacheRecordsLoaded: cacheRecords.length,
        cisaKevRecordsLoaded: 0,
        wouldWrite: false,
        wouldFetchEpss: false,
        wouldFetchNvd: false,
        warnings,
      },
    };
  }

  let cisaData;
  try {
    cisaData = await cisaResponse.json();
  } catch (error) {
    return {
      status: 502,
      body: {
        ok: false,
        mode: "read-only-skeleton",
        error: "Failed to parse live CISA KEV feed as JSON.",
        detail: error instanceof Error ? error.message : String(error),
        cacheRecordsLoaded: cacheRecords.length,
        cisaKevRecordsLoaded: 0,
        wouldWrite: false,
        wouldFetchEpss: false,
        wouldFetchNvd: false,
        warnings,
      },
    };
  }

  const cisaVulnerabilities = cisaData?.vulnerabilities;

  if (!Array.isArray(cisaVulnerabilities)) {
    return {
      status: 502,
      body: {
        ok: false,
        mode: "read-only-skeleton",
        error: "Live CISA KEV feed did not contain a vulnerabilities array.",
        cacheRecordsLoaded: cacheRecords.length,
        cisaKevRecordsLoaded: 0,
        wouldWrite: false,
        wouldFetchEpss: false,
        wouldFetchNvd: false,
        warnings,
      },
    };
  }

  return {
    status: 200,
    body: {
      ok: true,
      mode: "read-only-skeleton",
      cacheRecordsLoaded: cacheRecords.length,
      cisaKevRecordsLoaded: cisaVulnerabilities.length,
      wouldWrite: false,
      wouldFetchEpss: false,
      wouldFetchNvd: false,
      warnings,
    },
  };
}
