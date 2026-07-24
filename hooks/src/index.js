/**
 * Hidden webhook ingress for non-public projects.
 * Browser GETs return 404. POSTs accept payloads (optional secret + optional upstream forward).
 *
 * Secrets (wrangler secret put …):
 *   WEBHOOK_SECRET  — if set, require Authorization: Bearer <secret> or X-Webhook-Secret
 *   UPSTREAM_URL    — if set, forward the POST body/headers to this URL (e.g. Make)
 */

const HIDDEN = new Response(null, { status: 404 });

function authorized(request, env) {
  const secret = env.WEBHOOK_SECRET;
  if (!secret) return true;

  const auth = request.headers.get("Authorization") || "";
  if (auth === `Bearer ${secret}`) return true;

  const header = request.headers.get("X-Webhook-Secret") || "";
  return header === secret;
}

async function forward(request, upstreamUrl) {
  const headers = new Headers(request.headers);
  headers.delete("host");
  headers.delete("cf-connecting-ip");
  headers.delete("cf-ray");
  headers.delete("authorization");
  headers.delete("x-webhook-secret");

  return fetch(upstreamUrl, {
    method: "POST",
    headers,
    body: await request.arrayBuffer(),
  });
}

export default {
  async fetch(request, env) {
    if (request.method !== "POST") {
      return HIDDEN;
    }

    if (!authorized(request, env)) {
      return new Response(JSON.stringify({ error: "unauthorized" }), {
        status: 401,
        headers: { "content-type": "application/json" },
      });
    }

    if (env.UPSTREAM_URL) {
      try {
        const upstream = await forward(request, env.UPSTREAM_URL);
        const body = await upstream.arrayBuffer();
        return new Response(body, {
          status: upstream.status,
          headers: {
            "content-type":
              upstream.headers.get("content-type") || "application/json",
          },
        });
      } catch (err) {
        return new Response(
          JSON.stringify({ error: "upstream_failed", message: String(err) }),
          {
            status: 502,
            headers: { "content-type": "application/json" },
          }
        );
      }
    }

    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  },
};
