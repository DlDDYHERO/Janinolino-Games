async function isAdmin(request, env) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/(?:^|;\s*)admin_session=(\d+)\.([A-Za-z0-9_-]+)/);

  if (!match || !env.ADMIN_PASSWORD) return false;

  const expires = Number(match[1]);
  if (!Number.isSafeInteger(expires) || expires < Date.now()) return false;

  try {
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(env.ADMIN_PASSWORD),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );

    const token = match[2];
    const signature = Uint8Array.from(
      atob(token.replace(/-/g, "+").replace(/_/g, "/") +
        "=".repeat((4 - token.length % 4) % 4)),
      c => c.charCodeAt(0)
    );

    return await crypto.subtle.verify(
      "HMAC",
      key,
      signature,
      new TextEncoder().encode(String(expires))
    );
  } catch {
    return false;
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

async function readGame(request) {
  const data = await request.json();

  if (
    typeof data.name !== "string" ||
    !data.name.trim() ||
    data.name.length > 150 ||
    typeof data.category !== "string" ||
    !data.category.trim() ||
    data.category.length > 200 ||
    !["Im Besitz", "Durchgespielt", "Auf Wishlist"].includes(data.status)
  ) {
    return null;
  }

  return {
    name: data.name.trim(),
    appid: String(data.appid || "").trim(),
    category: data.category.trim(),
    status: data.status
  };
}

export async function onRequestGet({ env }) {
  try {
    const result = await env.DB.prepare(
      "SELECT id, name, appid, category, status FROM games ORDER BY id"
    ).all();

    return json(result.results);
  } catch {
    return json({ error: "Datenbankfehler" }, 500);
  }
}

export async function onRequestPost({ request, env }) {
  if (!(await isAdmin(request, env))) return json({ error: "Nicht angemeldet" }, 401);

  try {
    const game = await readGame(request);
    if (!game) return json({ error: "Ungültige Spieldaten" }, 400);

    const result = await env.DB.prepare(
      "INSERT INTO games (name, appid, category, status) VALUES (?, ?, ?, ?)"
    ).bind(game.name, game.appid, game.category, game.status).run();

    return json({ success: true, id: result.meta.last_row_id });
  } catch {
    return json({ error: "Spiel konnte nicht gespeichert werden" }, 500);
  }
}

export async function onRequestPut({ request, env }) {
  if (!(await isAdmin(request, env))) return json({ error: "Nicht angemeldet" }, 401);

  try {
    const data = await request.json();
    const id = Number(data.id);
    const game = await readGame(new Request(request.url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data)
    }));

    if (!Number.isSafeInteger(id) || id < 1 || !game) {
      return json({ error: "Ungültige Spieldaten" }, 400);
    }

    await env.DB.prepare(
      "UPDATE games SET name = ?, appid = ?, category = ?, status = ? WHERE id = ?"
    ).bind(game.name, game.appid, game.category, game.status, id).run();

    return json({ success: true });
  } catch {
    return json({ error: "Spiel konnte nicht geändert werden" }, 500);
  }
}

export async function onRequestDelete({ request, env }) {
  if (!(await isAdmin(request, env))) return json({ error: "Nicht angemeldet" }, 401);

  try {
    const data = await request.json();
    const id = Number(data.id);

    if (!Number.isSafeInteger(id) || id < 1) {
      return json({ error: "Ungültige Spiel-ID" }, 400);
    }

    await env.DB.prepare("DELETE FROM games WHERE id = ?").bind(id).run();

    return json({ success: true });
  } catch {
    return json({ error: "Spiel konnte nicht gelöscht werden" }, 500);
  }
}
