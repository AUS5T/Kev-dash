import {
  CISA_KEV_URL,
  EPSS_API_URL,
  EPSS_BATCH_SIZE,
  NVD_CVE_API_URL,
  NVD_FALLBACK_CAP,
} from "./config.js";
import { getR2Object, hasKevDataBinding, putR2Object } from "./r2.js";

const KEV_CACHE_KEY = "kev_enriched.json";
const COMBINED_OUTPUT_KEY = "combined_enriched.json";
const LAST_UPDATED_KEY = "last_updated.txt";
const JSON_CONTENT_TYPE = "application/json; charset=utf-8";
const TEXT_CONTENT_TYPE = "text/plain; charset=utf-8";
const N_A = "N/A";

export async function runManualUpdateFeeds(env) {
  const warnings = [];

  if (!hasKevDataBinding(env)) {
    return errorResult(500, "Missing R2 binding: KEV_DATA", {
      warnings,
    });
  }

  const cacheResult = await loadCacheRecords(env, warnings);
  if (!cacheResult.ok) {
    return cacheResult;
  }

  const cacheRecords = cacheResult.cacheRecords;
  const cisaResult = await fetchCisaKev(warnings);
  if (!cisaResult.ok) {
    cisaResult.body.cacheRecordsLoaded = cacheRecords.length;
    return cisaResult;
  }

  if (!env.NVD_API_KEY) {
    warnings.push("NVD_API_KEY is not set; exact-CVE NVD fallback will run without an API key and may be rate limited.");
  }

  const cisaRecords = cisaResult.cisaRecords;
  const cacheByCve = new Map(
    cacheRecords
      .filter((item) => item && typeof item === "object" && item.cveID)
      .map((item) => [item.cveID, item]),
  );
  const cveIds = cisaRecords.map((item) => item?.cveID).filter(Boolean);

  const epss = await fetchEpssForCves(cveIds, warnings);
  const nvd = {
    fallbackCap: NVD_FALLBACK_CAP,
    attempted: 0,
    succeeded: 0,
    failed: 0,
    skippedDueToCap: 0,
  };

  const generated = [];

  for (const kev of cisaRecords) {
    const cveID = kev.cveID;
    const cached = cacheByCve.get(cveID) || {};
    const enrichment = await resolveNvdEnrichment(cveID, cached, env, nvd, warnings);
    const epssFields = resolveEpssFields(cveID, cached, epss.map);

    generated.push({
      cveID,
      vendor: kev.vendorProject ?? null,
      product: kev.product ?? null,
      vulnerabilityName: kev.vulnerabilityName ?? null,
      requiredAction: kev.requiredAction ?? null,
      dueDate: kev.dueDate ?? null,
      dateAdded: kev.dateAdded ?? null,
      knownRansomwareCampaignUse: kev.knownRansomwareCampaignUse ?? cached.knownRansomwareCampaignUse ?? null,
      cvssScore: enrichment.cvssScore,
      cvssSeverity: enrichment.cvssSeverity,
      cvssVector: enrichment.cvssVector,
      cvssVersion: enrichment.cvssVersion,
      epssScore: epssFields.epssScore,
      epssPercentile: epssFields.epssPercentile,
      description: enrichment.description,
      notes: kev.notes ?? cached.notes ?? "",
      source: "KEV",
    });
  }

  if (!Array.isArray(generated) || generated.length === 0) {
    return errorResult(500, "Generated kev_enriched.json was empty or invalid.", {
      cacheRecordsLoaded: cacheRecords.length,
      cisaKevRecordsLoaded: cisaRecords.length,
      warnings,
      epss,
      nvd,
    });
  }

  const lastUpdated = `${new Date().toISOString()}\n`;
  const kevJson = JSON.stringify(generated, null, 2);
  const combinedJson = JSON.stringify(generated, null, 2);
  const outputsToWrite = [
    {
      key: KEV_CACHE_KEY,
      body: kevJson,
      contentType: JSON_CONTENT_TYPE,
    },
    {
      key: COMBINED_OUTPUT_KEY,
      body: combinedJson,
      contentType: JSON_CONTENT_TYPE,
    },
    {
      key: LAST_UPDATED_KEY,
      body: lastUpdated,
      contentType: TEXT_CONTENT_TYPE,
    },
  ];

  for (const output of outputsToWrite) {
    await putR2Object(env, output.key, output.body, output.contentType);
  }

  return {
    status: 200,
    body: {
      ok: true,
      mode: "manual-update",
      cacheRecordsLoaded: cacheRecords.length,
      cisaKevRecordsLoaded: cisaRecords.length,
      generatedRecords: generated.length,
      epss: {
        chunks: epss.chunks,
        recordsLoaded: epss.recordsLoaded,
        failed: epss.failed,
        chunksFailed: epss.chunksFailed,
        warnings: epss.warnings,
      },
      nvd,
      outputs: outputsToWrite.map((output) => ({
        key: output.key,
        bytes: new TextEncoder().encode(output.body).byteLength,
      })),
      warnings,
    },
  };
}

async function loadCacheRecords(env, warnings) {
  const cacheObject = await getR2Object(env, KEV_CACHE_KEY);

  if (!cacheObject) {
    return errorResult(404, `R2 cache object not found: ${KEV_CACHE_KEY}`, {
      warnings,
    });
  }

  let cacheRecords;
  try {
    cacheRecords = await cacheObject.json();
  } catch (error) {
    return errorResult(500, `Failed to parse R2 cache object ${KEV_CACHE_KEY} as JSON.`, {
      detail: errorMessage(error),
      warnings,
    });
  }

  if (!Array.isArray(cacheRecords)) {
    return errorResult(500, `R2 cache object ${KEV_CACHE_KEY} must be a JSON array.`, {
      warnings,
    });
  }

  return {
    ok: true,
    cacheRecords,
  };
}

async function fetchCisaKev(warnings) {
  let response;
  try {
    response = await fetch(CISA_KEV_URL, {
      headers: {
        accept: "application/json",
      },
    });
  } catch (error) {
    return errorResult(502, "Failed to fetch live CISA KEV feed.", {
      detail: errorMessage(error),
      warnings,
    });
  }

  if (!response.ok) {
    return errorResult(502, "Failed to fetch live CISA KEV feed.", {
      cisaStatus: response.status,
      warnings,
    });
  }

  let cisaData;
  try {
    cisaData = await response.json();
  } catch (error) {
    return errorResult(502, "Failed to parse live CISA KEV feed as JSON.", {
      detail: errorMessage(error),
      warnings,
    });
  }

  const cisaRecords = cisaData?.vulnerabilities;

  if (!Array.isArray(cisaRecords) || cisaRecords.length === 0) {
    return errorResult(502, "Live CISA KEV feed did not contain a non-empty vulnerabilities array.", {
      warnings,
    });
  }

  return {
    ok: true,
    cisaRecords,
  };
}

async function fetchEpssForCves(cveIds, warnings) {
  const uniqueCves = [...new Set(cveIds.filter(Boolean))];
  const chunks = chunked(uniqueCves, EPSS_BATCH_SIZE);
  const map = new Map();
  const epssWarnings = [];
  let chunksFailed = 0;

  for (const chunk of chunks) {
    const params = new URLSearchParams({
      cve: chunk.join(","),
      limit: String(chunk.length),
    });

    try {
      const response = await fetch(`${EPSS_API_URL}?${params.toString()}`, {
        headers: {
          accept: "application/json",
        },
      });

      if (!response.ok) {
        chunksFailed += 1;
        const warning = `EPSS chunk failed with HTTP ${response.status} for ${chunk.length} CVEs.`;
        epssWarnings.push(warning);
        warnings.push(warning);
        continue;
      }

      const data = await response.json();
      const rows = Array.isArray(data?.data) ? data.data : [];

      if (rows.length < chunk.length / 2) {
        const warning = `EPSS returned ${rows.length} rows for ${chunk.length} requested CVEs.`;
        epssWarnings.push(warning);
        warnings.push(warning);
      }

      for (const row of rows) {
        if (row?.cve) {
          map.set(row.cve, row);
        }
      }
    } catch (error) {
      chunksFailed += 1;
      const warning = `EPSS chunk fetch failed: ${errorMessage(error)}`;
      epssWarnings.push(warning);
      warnings.push(warning);
    }
  }

  return {
    map,
    chunks: chunks.length,
    chunksFailed,
    recordsLoaded: map.size,
    failed: chunks.length > 0 && chunksFailed === chunks.length,
    warnings: epssWarnings,
  };
}

async function resolveNvdEnrichment(cveID, cached, env, nvd, warnings) {
  if (hasCachedNvdEnrichment(cached)) {
    return cachedNvdFields(cached);
  }

  if (nvd.attempted >= NVD_FALLBACK_CAP) {
    nvd.skippedDueToCap += 1;
    return cachedNvdFields(cached);
  }

  nvd.attempted += 1;

  const result = await fetchNvdExactCve(cveID, env);

  if (!result.ok) {
    nvd.failed += 1;
    warnings.push(`NVD fallback failed for ${cveID}: ${result.error}`);
    return cachedNvdFields(cached);
  }

  nvd.succeeded += 1;
  return result.enrichment;
}

async function fetchNvdExactCve(cveID, env) {
  if (!cveID || !cveID.startsWith("CVE-")) {
    return {
      ok: false,
      error: "invalid CVE ID",
    };
  }

  const params = new URLSearchParams({
    cveId: cveID,
  });
  const headers = {
    accept: "application/json",
    "user-agent": "kev-dash-worker/1.0",
  };

  if (env.NVD_API_KEY) {
    headers.apiKey = env.NVD_API_KEY;
  }

  let response;
  try {
    response = await fetch(`${NVD_CVE_API_URL}?${params.toString()}`, {
      headers,
    });
  } catch (error) {
    return {
      ok: false,
      error: errorMessage(error),
    };
  }

  if (!response.ok) {
    return {
      ok: false,
      error: `HTTP ${response.status}`,
    };
  }

  let data;
  try {
    data = await response.json();
  } catch (error) {
    return {
      ok: false,
      error: `invalid JSON: ${errorMessage(error)}`,
    };
  }

  const cveObject = data?.vulnerabilities?.[0]?.cve;
  if (!cveObject) {
    return {
      ok: false,
      error: "no matching CVE returned",
    };
  }

  const cvss = extractCvssData(cveObject.metrics || {});
  const description =
    (cveObject.descriptions || []).find((item) => item?.lang === "en")?.value || N_A;

  return {
    ok: true,
    enrichment: {
      ...cvss,
      description,
    },
  };
}

function extractCvssData(metrics) {
  const versions = [
    ["cvssMetricV40", "4.0"],
    ["cvssMetricV31", "3.1"],
    ["cvssMetricV30", "3.0"],
    ["cvssMetricV2", "2.0"],
  ];

  for (const [key, version] of versions) {
    const metricList = metrics?.[key];
    if (!Array.isArray(metricList)) {
      continue;
    }

    for (const metric of metricList) {
      const cvssData = metric?.cvssData || metric;
      const score = cvssData?.baseScore;

      if (score !== undefined && score !== null) {
        return {
          cvssScore: score,
          cvssSeverity:
            cvssData?.baseSeverity ||
            metric?.baseSeverity ||
            (version === "2.0" ? `Legacy (${version})` : N_A),
          cvssVector: cvssData?.vectorString || N_A,
          cvssVersion: version,
        };
      }
    }
  }

  return {
    cvssScore: N_A,
    cvssSeverity: N_A,
    cvssVector: N_A,
    cvssVersion: N_A,
  };
}

function resolveEpssFields(cveID, cached, epssMap) {
  const epssEntry = epssMap.get(cveID);

  if (epssEntry) {
    return {
      epssScore: parseNumberOrNa(epssEntry.epss),
      epssPercentile: parseNumberOrNa(epssEntry.percentile),
    };
  }

  return {
    epssScore: cached.epssScore ?? N_A,
    epssPercentile: cached.epssPercentile ?? N_A,
  };
}

function hasCachedNvdEnrichment(cached) {
  return hasUsableCvss(cached) && hasUsableDescription(cached);
}

function hasUsableCvss(cached) {
  const score = cached?.cvssScore;
  return score !== undefined && score !== null && score !== "" && score !== N_A && !String(score).includes("<a ");
}

function hasUsableDescription(cached) {
  const description = cached?.description;
  return description !== undefined && description !== null && description !== "" && description !== N_A;
}

function cachedNvdFields(cached) {
  return {
    cvssScore: cached.cvssScore ?? N_A,
    cvssSeverity: cached.cvssSeverity ?? N_A,
    cvssVector: cached.cvssVector ?? N_A,
    cvssVersion: cached.cvssVersion ?? N_A,
    description: cached.description ?? N_A,
  };
}

function parseNumberOrNa(value) {
  const parsed = Number.parseFloat(value);
  return Number.isFinite(parsed) ? parsed : N_A;
}

function chunked(items, size) {
  const chunks = [];
  for (let index = 0; index < items.length; index += size) {
    chunks.push(items.slice(index, index + size));
  }
  return chunks;
}

function errorResult(status, error, extra = {}) {
  return {
    status,
    body: {
      ok: false,
      mode: "manual-update",
      error,
      cacheRecordsLoaded: extra.cacheRecordsLoaded ?? 0,
      cisaKevRecordsLoaded: extra.cisaKevRecordsLoaded ?? 0,
      generatedRecords: 0,
      epss: extra.epss ?? {
        chunks: 0,
        recordsLoaded: 0,
        failed: false,
        chunksFailed: 0,
        warnings: [],
      },
      nvd: extra.nvd ?? {
        fallbackCap: NVD_FALLBACK_CAP,
        attempted: 0,
        succeeded: 0,
        failed: 0,
        skippedDueToCap: 0,
      },
      outputs: [],
      warnings: extra.warnings ?? [],
      ...(extra.detail ? { detail: extra.detail } : {}),
      ...(extra.cisaStatus ? { cisaStatus: extra.cisaStatus } : {}),
    },
  };
}

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}
