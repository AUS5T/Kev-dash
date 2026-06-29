import { DATA_FILES, PAGES_ORIGIN, TEST_OBJECT_KEY } from "./config.js";
import {
  applyCorsHeaders,
  handlePublicCorsPreflight,
  jsonResponse,
  jsonResponseWithCors,
  requireAdminToken,
} from "./http.js";
import { getR2Object, hasKevDataBinding, putR2Object } from "./r2.js";
import { runUpdateFeedsReadOnlySkeleton } from "./updateFeeds.js";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/test-r2") {
      return handleTestR2(env);
    }

    if (url.pathname === "/seed-from-repo") {
      return handleSeedFromRepo(request, env);
    }

    if (url.pathname === "/admin/update-feeds") {
      return handleUpdateFeeds(request, env);
    }

    const publicFile = findDataFile(url.pathname);
    if (publicFile) {
      return handlePublicR2Read(request, env, publicFile);
    }

    return jsonResponse(
      {
        ok: true,
        message: "Kev-dash R2 test Worker. Use /test-r2, /seed-from-repo, or one of the public data file paths.",
      },
      200,
    );
  },
};

async function handleTestR2(env) {
  if (!hasKevDataBinding(env)) {
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

  await putR2Object(env, TEST_OBJECT_KEY, body, "text/plain; charset=utf-8");

  const object = await getR2Object(env, TEST_OBJECT_KEY);

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

  if (!hasKevDataBinding(env)) {
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

  for (const file of DATA_FILES) {
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

    await putR2Object(env, file.key, body, file.contentType);

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

async function handleUpdateFeeds(request, env) {
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

  const result = await runUpdateFeedsReadOnlySkeleton(env);
  return jsonResponse(result.body, result.status);
}

async function handlePublicR2Read(request, env, file) {
  if (request.method === "OPTIONS") {
    return handlePublicCorsPreflight(request);
  }

  if (request.method !== "GET") {
    return jsonResponseWithCors(
      request,
      {
        ok: false,
        error: "Method not allowed. Use GET.",
      },
      405,
    );
  }

  if (!hasKevDataBinding(env)) {
    return jsonResponseWithCors(
      request,
      {
        ok: false,
        error: "Missing R2 binding: KEV_DATA",
      },
      500,
    );
  }

  // Read-only testing endpoint. This only serves the explicitly allowed
  // dashboard data objects from R2 and does not expose bucket listings.
  const object = await getR2Object(env, file.key);

  if (!object) {
    return jsonResponseWithCors(
      request,
      {
        ok: false,
        error: "R2 object not found.",
        key: file.key,
      },
      404,
    );
  }

  const headers = new Headers();
  headers.set("content-type", file.contentType);
  headers.set("cache-control", "no-store");
  applyCorsHeaders(request, headers);
  if (object.httpEtag) {
    headers.set("etag", object.httpEtag);
  }

  return new Response(object.body, {
    status: 200,
    headers,
  });
}

function findDataFile(pathname) {
  const key = pathname.startsWith("/") ? pathname.slice(1) : pathname;
  return DATA_FILES.find((file) => file.key === key) || null;
}
