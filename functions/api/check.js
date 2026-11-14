export async function onRequestGet({ request, env }) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/(?:^|;\s*)admin_session=(\d+)\.([A-Za-z0-9_-]+)/);

  if (!match) {
    return new Response(
      JSON.stringify({ loggedIn: false }),
      { status: 401, headers: { "Content-Type": "application/json" } }
    );
  }

  const expires = Number(match[1]);
  const token = match[2];

  if (!Number.isSafeInteger(expires) || expires < Date.now()) {
    return new Response(
      JSON.stringify({ loggedIn: false }),
      { status: 401, headers: { "Content-Type": "application/json" } }
    );
  }

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(env.ADMIN_PASSWORD),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const signature = Uint8Array.from(
    atob(token.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - token.length % 4) % 4)),
    c => c.charCodeAt(0)
  );

  const valid = await crypto.subtle.verify(
    "HMAC",
    key,
    signature,
    new TextEncoder().encode(String(expires))
  );

  return new Response(
    JSON.stringify({ loggedIn: valid }),
    {
      status: valid ? 200 : 401,
      headers: { "Content-Type": "application/json" }
    }
  );
}
