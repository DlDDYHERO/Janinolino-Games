export async function onRequestPost({ request, env }) {
  try {
    const { password } = await request.json();

    if (!env.ADMIN_PASSWORD || password !== env.ADMIN_PASSWORD) {
      return new Response(
        JSON.stringify({ success: false, message: "Falsches Passwort" }),
        {
          status: 401,
          headers: { "Content-Type": "application/json" }
        }
      );
    }

    const expires = Date.now() + 3600000;

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(env.ADMIN_PASSWORD),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const signature = await crypto.subtle.sign(
      "HMAC",
      key,
      new TextEncoder().encode(String(expires))
    );

    const token = btoa(
      String.fromCharCode(...new Uint8Array(signature))
    ).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");

    return new Response(
      JSON.stringify({ success: true }),
      {
        headers: {
          "Content-Type": "application/json",
          "Set-Cookie": `admin_session=${expires}.${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=3600`
        }
      }
    );
  } catch {
    return new Response(
      JSON.stringify({ success: false, message: "Ungültige Anfrage" }),
      { status: 400 }
    );
  }
}
