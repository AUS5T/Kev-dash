import { ALLOWED_CORS_ORIGINS } from "./config.js";

export function jsonResponse(payload, status) {
  return new Response(JSON.stringify(payload, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

export function jsonResponseWithCors(request, payload, status) {
  const headers = new Headers();
  headers.set("content-type", "application/json; charset=utf-8");
  headers.set("cache-control", "no-store");
  applyCorsHeaders(request, headers);

  return new Response(JSON.stringify(payload, null, 2), {
    status,
    headers,
  });
}

export function handlePublicCorsPreflight(request) {
  const headers = new Headers();
  headers.set("cache-control", "no-store");
  applyCorsHeaders(request, headers);

  if (!headers.has("access-control-allow-origin")) {
    return jsonResponse(
      {
        ok: false,
        error: "CORS origin not allowed.",
      },
      403,
    );
  }

  headers.set("access-control-allow-methods", "GET, OPTIONS");
  headers.set("access-control-allow-headers", "content-type");
  headers.set("access-control-max-age", "0");

  return new Response(null, {
    status: 204,
    headers,
  });
}

export function applyCorsHeaders(request, headers) {
  const origin = request.headers.get("origin");

  if (!origin || !ALLOWED_CORS_ORIGINS.has(origin)) {
    return;
  }

  headers.set("access-control-allow-origin", origin);
  headers.set("vary", "Origin");
}

export function requireAdminToken(request, env) {
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
