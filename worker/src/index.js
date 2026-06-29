const TEST_OBJECT_KEY = "test-r2.txt";
const PAGES_ORIGIN = "https://kev-dash.pages.dev";
const SEED_FILES = [
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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/test-r2") {
      return handleTestR2(env);
    }

    if (url.pathname === "/seed-from-repo") {
      return handleSeedFromRepo(request, env);
    }

    return jsonResponse(
      {
        ok: true,
        message: "Kev-dash R2 test Worker. Use /test-r2 for connectivity or /seed-from-repo with an admin token to seed R2.",
      },
      200,
    );
  },
};

async function handleTestR2(env) {
  if (!env.KEV_DATA) {
    return jsonResponse(
      {
        ok: false,
        error: "Missing R2 binding: KEV_DATA",
      },
      500,
    );
  }

  // Connectivity test only. This does not generate KEV data, update the
  // dashboard, fetch external APIs, or touch production JSON objects.
  const writtenAt = new Date().toISOString();
  const body = `Kev-dash R2 connectivity test\nwritten_at=${writtenAt}\n`;

  await env.KEV_DATA.put(TEST_OBJECT_KEY, body, {
    httpMetadata: {
      contentType: "text/plain; charset=utf-8",
    },
  });

  const object = await env.KEV_DATA.get(TEST_OBJECT_KEY);

  if (!object) {
    return jsonResponse(
      {
        ok: false,
        error: `Wrote ${TEST_OBJECT_KEY}, but could not read it back.`,
      },
      500,
    );
  }

  return jsonResponse(
    {
      ok: true,
      bucketBinding: "KEV_DATA",
      bucketName: "kev-dash-data",
      key: TEST_OBJECT_KEY,
      writtenAt,
      readBack: await object.text(),
    },
    200,
  );
}

async function handleSeedFromRepo(request, env) {
  if (request.method !== "POST") {
    return jsonResponse(
      {
        ok: false,
        error: "Method not allowed. Use POST.",
      },
      405,
    );
  }

  const authError = requireAdminToken(request, env);
  if (authError) {
    return authError;
  }

  if (!env.KEV_DATA) {
    return jsonResponse(
      {
        ok: false,
        error: "Missing R2 binding: KEV_DATA",
      },
      500,
    );
  }

  // Admin-only bootstrap endpoint.
  // This copies the current static dashboard data from Cloudflare Pages into R2.
  // It does not run cron, generate feeds, or call CISA/NVD/EPSS APIs.
  const seeded = [];

  for (const file of SEED_FILES) {
    const sourceUrl = `${PAGES_ORIGIN}/${file.key}`;
    const response = await fetch(sourceUrl, {
      headers: {
        accept: file.contentType,
      },
    });

    if (!response.ok) {
      return jsonResponse(
        {
          ok: false,
          error: `Failed to fetch ${sourceUrl}`,
          status: response.status,
          seeded,
        },
        502,
      );
    }

    const body = await response.arrayBuffer();

    await env.KEV_DATA.put(file.key, body, {
      httpMetadata: {
        contentType: file.contentType,
      },
    });

    seeded.push({
      key: file.key,
      sourceUrl,
      contentType: file.contentType,
      bytes: body.byteLength,
    });
  }

  return jsonResponse(
    {
      ok: true,
      bucketBinding: "KEV_DATA",
      bucketName: "kev-dash-data",
      sourceOrigin: PAGES_ORIGIN,
      seeded,
    },
    200,
  );
}

function requireAdminToken(request, env) {
  if (!env.ADMIN_TOKEN) {
    return jsonResponse(
      {
        ok: false,
        error: "Missing ADMIN_TOKEN secret.",
      },
      500,
    );
  }

  const expected = `Bearer ${env.ADMIN_TOKEN}`;
  const actual = request.headers.get("authorization") || "";

  if (actual !== expected) {
    return jsonResponse(
      {
        ok: false,
        error: "Unauthorized.",
      },
      401,
    );
  }

  return null;
}

function jsonResponse(payload, status) {
  return new Response(JSON.stringify(payload, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}
