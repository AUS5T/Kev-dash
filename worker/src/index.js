const TEST_OBJECT_KEY = "test-r2.txt";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname !== "/test-r2") {
      return jsonResponse(
        {
          ok: true,
          message: "Kev-dash R2 connectivity test Worker. Use /test-r2 to write and read a test object.",
        },
        200,
      );
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
  },
};

function jsonResponse(payload, status) {
  return new Response(JSON.stringify(payload, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}
