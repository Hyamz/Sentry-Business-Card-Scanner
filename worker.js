// Sentry's Card Scanner - server (Cloudflare Worker)
//
// Keeps the Anthropic API key out of the public web pages, signs staff in,
// and runs the admin centre's user management.
//
// Setup (Worker > Settings > Bindings / Variables and Secrets):
//   KV namespace binding  USERS              (create a KV namespace, bind it as USERS)
//   ANTHROPIC_API_KEY     Secret             key from console.anthropic.com
//   ADMIN_PASSWORD        Secret             password for the built-in "admin" login
//   SESSION_SECRET        Secret             any long random text (signs logins)
//   D1 database binding   DB                 (create a D1 database, bind it as DB; the table is made automatically)
//   MODEL                 Text, optional     defaults to claude-sonnet-5-5

const ALLOWED_ORIGIN = "https://hyamz.github.io";
const DEFAULT_MODEL = "claude-sonnet-5-5";
const MAX_IMAGE_BYTES = 5 * 1024 * 1024;
const SESSION_DAYS = 30;
const MAX_FAILS = 5;
const LOCK_MINUTES = 15;
const PBKDF2_ITER = 100000;

const PROMPT = `The image is a photo of a business card. Extract the contact details printed on it.
Reply with only one JSON object in exactly this shape (use "" for anything not on the card, never guess):
{"name":"","title":"","company":"","phone":"","mobile":"","email":"","website":"","address":"","socials":[{"network":"","url":""}],"notes":""}
Rules: "phone" is the main office/direct line, "mobile" a mobile/cell number; keep numbers as printed including country code. "socials" lists LinkedIn, X/Twitter, Instagram, Facebook, YouTube, TikTok or WhatsApp handles or URLs shown on the card; network must be one of: LinkedIn, X / Twitter, Instagram, Facebook, YouTube, TikTok, WhatsApp, Other. "website" is the company site. "notes" holds any other useful text (fax, second email, department, tagline) in one short line.`;

/* ---------- helpers ---------- */
const enc = new TextEncoder();
const b64u = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromB64u = s => { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; return Uint8Array.from(atob(s), c => c.charCodeAt(0)); };

function cors() {
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };
}
const reply = (status, body) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...cors() } });

function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0;
}
async function sha(s) { return new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s || ""))); }
async function sameText(a, b) { return !!b && equalBytes(await sha(a), await sha(b)); }

async function hashSecret(secret, saltB64) {
  const salt = saltB64 ? fromB64u(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITER }, key, 256);
  return { salt: b64u(salt), hash: b64u(bits) };
}

async function hmac(env, data) {
  const key = await crypto.subtle.importKey("raw", enc.encode(env.SESSION_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64u(await crypto.subtle.sign("HMAC", key, enc.encode(data)));
}
async function makeToken(env, user) {
  const payload = b64u(enc.encode(JSON.stringify({ u: user.username, v: user.tokenVersion || 0, exp: Date.now() + SESSION_DAYS * 864e5 })));
  return payload + "." + await hmac(env, payload);
}

const cleanUsername = u => String(u || "").trim().toLowerCase();
const validUsername = u => /^[a-z0-9._-]{2,32}$/.test(u);
function checkSecret(type, secret) {
  if (type === "pin") return /^\d{4,8}$/.test(secret) ? null : "A PIN must be 4 to 8 digits.";
  if (type === "password") return String(secret).length >= 8 ? null : "A password must be at least 8 characters.";
  return "Choose password or PIN.";
}
const getUser = (env, u) => env.USERS.get("user:" + u, "json");
const putUser = (env, user) => env.USERS.put("user:" + user.username, JSON.stringify(user));
const publicUser = u => ({
  username: u.username, name: u.name || "", role: u.role, type: u.type, disabled: !!u.disabled,
  createdAt: u.createdAt, lastLogin: u.lastLogin || null, scans: u.scans || 0,
  canDelete: u.role === "admin" || !!u.canDelete,
  lockedUntil: u.lockedUntil && u.lockedUntil > Date.now() ? u.lockedUntil : null,
});

// Built-in recovery admin. Always works with ADMIN_PASSWORD; can't be deleted.
const BUILTIN = { username: "admin", name: "Administrator", role: "admin", type: "password", builtin: true, tokenVersion: 0 };

async function authed(request, env) {
  const m = (request.headers.get("Authorization") || "").match(/^Bearer (.+)\.(.+)$/);
  if (!m) return null;
  if (!equalBytes(enc.encode(await hmac(env, m[1])), enc.encode(m[2]))) return null;
  let p; try { p = JSON.parse(new TextDecoder().decode(fromB64u(m[1]))); } catch { return null; }
  if (!p || p.exp < Date.now()) return null;
  if (p.u === "admin") return p.v === 0 ? { ...BUILTIN } : null;
  const user = await getUser(env, p.u);
  if (!user || user.disabled || (user.tokenVersion || 0) !== p.v) return null;
  return user;
}

function firstJson(text) {
  const t = String(text || "").trim();
  try { return JSON.parse(t); } catch {}
  const f = t.match(/```(?:json)?\s*([\s\S]*?)```/); if (f) { try { return JSON.parse(f[1]); } catch {} }
  const s = t.indexOf("{"), e = t.lastIndexOf("}");
  if (s >= 0 && e > s) { try { return JSON.parse(t.slice(s, e + 1)); } catch {} }
  return null;
}

/* ---------- routes ---------- */
async function login(env, body) {
  const username = cleanUsername(body.username), secret = String(body.secret || "");
  if (!username || !secret) return reply(400, { error: "missing" });

  if (username === "admin") {
    const st = (await env.USERS.get("builtin:admin", "json")) || {};
    if (st.lockedUntil && st.lockedUntil > Date.now()) return reply(423, { error: "locked", until: st.lockedUntil });
    if (!(await sameText(secret, env.ADMIN_PASSWORD))) {
      st.fails = (st.fails || 0) + 1;
      if (st.fails >= MAX_FAILS) { st.lockedUntil = Date.now() + LOCK_MINUTES * 6e4; st.fails = 0; }
      await env.USERS.put("builtin:admin", JSON.stringify(st));
      return st.lockedUntil && st.lockedUntil > Date.now() ? reply(423, { error: "locked", until: st.lockedUntil }) : reply(401, { error: "bad_login", left: MAX_FAILS - st.fails });
    }
    if (st.fails || st.lockedUntil) await env.USERS.put("builtin:admin", JSON.stringify({}));
    return reply(200, { token: await makeToken(env, BUILTIN), user: publicUser(BUILTIN) });
  }

  const user = await getUser(env, username);
  if (!user) { await hashSecret(secret); return reply(401, { error: "bad_login" }); } // same work either way
  if (user.disabled) return reply(403, { error: "disabled" });
  if (user.lockedUntil && user.lockedUntil > Date.now()) return reply(423, { error: "locked", until: user.lockedUntil });

  const { hash } = await hashSecret(secret, user.salt);
  if (!equalBytes(enc.encode(hash), enc.encode(user.hash))) {
    user.fails = (user.fails || 0) + 1;
    if (user.fails >= MAX_FAILS) { user.lockedUntil = Date.now() + LOCK_MINUTES * 6e4; user.fails = 0; }
    await putUser(env, user);
    return user.lockedUntil && user.lockedUntil > Date.now()
      ? reply(423, { error: "locked", until: user.lockedUntil })
      : reply(401, { error: "bad_login", left: MAX_FAILS - user.fails });
  }
  user.fails = 0; user.lockedUntil = null; user.lastLogin = Date.now();
  await putUser(env, user);
  return reply(200, { token: await makeToken(env, user), user: publicUser(user) });
}

async function scan(env, user, body) {
  const mediaType = String(body.mediaType || ""), image = String(body.image || "");
  if (!/^image\/(jpeg|png|webp|gif)$/.test(mediaType) || !/^[A-Za-z0-9+/=]+$/.test(image)) return reply(400, { error: "bad_image" });
  if (image.length * 0.75 > MAX_IMAGE_BYTES) return reply(413, { error: "image_too_large" });

  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "x-api-key": env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json" },
    body: JSON.stringify({
      model: env.MODEL || DEFAULT_MODEL,
      max_tokens: 1024,
      messages: [{ role: "user", content: [
        { type: "image", source: { type: "base64", media_type: mediaType, data: image } },
        { type: "text", text: PROMPT },
      ] }],
    }),
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    console.log("Anthropic API error", res.status, detail.slice(0, 500));
    const code = res.status === 401 ? "bad_api_key" : res.status === 429 ? "rate_limited"
      : res.status === 400 && /credit/i.test(detail) ? "no_credit" : "upstream_error";
    return reply(502, { error: code });
  }
  const data = await res.json();
  const card = firstJson((data.content || []).filter(b => b.type === "text").map(b => b.text).join(""));
  if (!card || typeof card !== "object") return reply(502, { error: "unreadable" });
  if (!user.builtin) { user.scans = (user.scans || 0) + 1; user.lastScan = Date.now(); await putUser(env, user); }
  return reply(200, { card });
}

async function listUsers(env) {
  const out = []; let cursor;
  do {
    const page = await env.USERS.list({ prefix: "user:", cursor });
    const users = await Promise.all(page.keys.map(k => env.USERS.get(k.name, "json")));
    users.filter(Boolean).forEach(u => out.push(publicUser(u)));
    cursor = page.list_complete ? null : page.cursor;
  } while (cursor);
  out.sort((a, b) => (a.name || a.username).localeCompare(b.name || b.username));
  return reply(200, { users: out });
}

async function createUser(env, me, body) {
  const username = cleanUsername(body.username);
  if (!validUsername(username)) return reply(400, { error: "bad_username", message: "Usernames are 2 to 32 letters, numbers, dots, dashes or underscores." });
  if (username === "admin") return reply(400, { error: "reserved", message: "That username is reserved." });
  if (await getUser(env, username)) return reply(409, { error: "exists", message: "That username is already taken." });
  const type = body.type === "pin" ? "pin" : "password";
  const problem = checkSecret(type, String(body.secret || ""));
  if (problem) return reply(400, { error: "weak_secret", message: problem });
  const { salt, hash } = await hashSecret(String(body.secret));
  const user = {
    username, name: String(body.name || "").trim().slice(0, 80), role: body.role === "admin" ? "admin" : "user",
    type, salt, hash, tokenVersion: 0, createdAt: Date.now(), createdBy: me.username, scans: 0,
  };
  await putUser(env, user);
  return reply(200, { user: publicUser(user) });
}

async function updateUser(env, me, body) {
  const user = await getUser(env, cleanUsername(body.username));
  if (!user) return reply(404, { error: "not_found", message: "That user no longer exists." });
  if (typeof body.name === "string") user.name = body.name.trim().slice(0, 80);
  if (body.role === "admin" || body.role === "user") {
    if (user.username === me.username && body.role !== "admin") return reply(400, { error: "self", message: "You can't remove your own admin access." });
    user.role = body.role;
  }
  if (typeof body.disabled === "boolean") {
    if (user.username === me.username && body.disabled) return reply(400, { error: "self", message: "You can't disable your own account." });
    if (body.disabled && !user.disabled) user.tokenVersion = (user.tokenVersion || 0) + 1; // signs them out everywhere
    user.disabled = body.disabled;
  }
  if (body.secret) {
    const type = body.type === "pin" ? "pin" : body.type === "password" ? "password" : user.type;
    const problem = checkSecret(type, String(body.secret));
    if (problem) return reply(400, { error: "weak_secret", message: problem });
    Object.assign(user, await hashSecret(String(body.secret)), { type });
    user.tokenVersion = (user.tokenVersion || 0) + 1;
    user.fails = 0; user.lockedUntil = null;
  }
  if (body.unlock) { user.fails = 0; user.lockedUntil = null; }
  if (typeof body.canDelete === "boolean") user.canDelete = body.canDelete;
  await putUser(env, user);
  return reply(200, { user: publicUser(user) });
}

async function deleteUser(env, me, body) {
  const username = cleanUsername(body.username);
  if (username === me.username) return reply(400, { error: "self", message: "You can't delete your own account." });
  await env.USERS.delete("user:" + username);
  return reply(200, { ok: true });
}

/* ---------- shared contact list (D1) ---------- */
let tableReady = false;
async function ensureTable(env) {
  if (tableReady) return;
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS contacts (
    id TEXT PRIMARY KEY, data TEXT NOT NULL, photo TEXT,
    created_at INTEGER NOT NULL, created_by TEXT NOT NULL, created_by_name TEXT,
    updated_at INTEGER NOT NULL, updated_by TEXT)`).run();
  tableReady = true;
}
const FIELDS = ["name", "title", "company", "phone", "mobile", "email", "website", "address", "notes"];
const NETWORKS = ["LinkedIn", "X / Twitter", "Instagram", "Facebook", "YouTube", "TikTok", "WhatsApp", "Other"];
function cleanContact(c) {
  const out = {};
  for (const k of FIELDS) out[k] = String((c && c[k]) || "").trim().slice(0, k === "notes" || k === "address" ? 1000 : 300);
  out.socials = Array.isArray(c && c.socials) ? c.socials.slice(0, 10).map(x => ({
    network: NETWORKS.includes(x && x.network) ? x.network : "Other",
    url: String((x && x.url) || "").trim().slice(0, 300),
  })).filter(x => x.url) : [];
  return out;
}
const hasContent = c => !!(c.name || c.company || c.email || c.phone || c.mobile);
const validId = id => /^[A-Za-z0-9_-]{4,64}$/.test(String(id || ""));
const validPhoto = p => typeof p === "string" && /^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(p) && p.length < 400000;
const rowOut = r => ({
  id: r.id, ...JSON.parse(r.data), createdAt: r.created_at, createdBy: r.created_by,
  createdByName: r.created_by_name || r.created_by, updatedAt: r.updated_at, updatedBy: r.updated_by,
  hasPhoto: !!r.has_photo, ...(r.photo !== undefined ? { photo: r.photo || "" } : {}),
});

async function listContacts(env) {
  const { results } = await env.DB.prepare(
    "SELECT id, data, created_at, created_by, created_by_name, updated_at, updated_by, (photo IS NOT NULL AND photo != '') AS has_photo FROM contacts ORDER BY created_at DESC"
  ).all();
  return reply(200, { contacts: results.map(rowOut) });
}
async function getContact(env, body) {
  if (!validId(body.id)) return reply(400, { error: "bad_request" });
  const r = await env.DB.prepare("SELECT *, (photo IS NOT NULL AND photo != '') AS has_photo FROM contacts WHERE id = ?").bind(body.id).first();
  return r ? reply(200, { contact: rowOut(r) }) : reply(404, { error: "not_found", message: "That contact has been deleted." });
}
async function saveContact(env, me, body) {
  const c = body.contact || {};
  if (!validId(c.id)) return reply(400, { error: "bad_request" });
  const data = cleanContact(c);
  if (!hasContent(data)) return reply(400, { error: "empty", message: "Add at least a name, company, email or phone number." });
  const now = Date.now();
  const existing = await env.DB.prepare("SELECT created_by FROM contacts WHERE id = ?").bind(c.id).first();
  if (existing) {
    if (existing.created_by !== me.username && me.role !== "admin") return reply(403, { error: "not_yours", message: "Only the person who added this contact, or an admin, can edit it." });
    if (validPhoto(c.photo)) {
      await env.DB.prepare("UPDATE contacts SET data = ?, photo = ?, updated_at = ?, updated_by = ? WHERE id = ?").bind(JSON.stringify(data), c.photo, now, me.username, c.id).run();
    } else {
      await env.DB.prepare("UPDATE contacts SET data = ?, updated_at = ?, updated_by = ? WHERE id = ?").bind(JSON.stringify(data), now, me.username, c.id).run();
    }
  } else {
    const created = Number.isFinite(c.createdAt) && c.createdAt > 0 && c.createdAt <= now ? c.createdAt : now;
    await env.DB.prepare("INSERT INTO contacts (id, data, photo, created_at, created_by, created_by_name, updated_at, updated_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
      .bind(c.id, JSON.stringify(data), validPhoto(c.photo) ? c.photo : null, created, me.username, me.name || me.username, now, me.username).run();
  }
  return getContact(env, { id: c.id });
}
async function deleteContact(env, me, body) {
  if (!(me.role === "admin" || me.canDelete)) return reply(403, { error: "no_delete", message: "You don't have permission to delete from the shared list." });
  if (!validId(body.id)) return reply(400, { error: "bad_request" });
  await env.DB.prepare("DELETE FROM contacts WHERE id = ?").bind(body.id).run();
  return reply(200, { ok: true });
}
async function importContacts(env, me, body) {
  const list = Array.isArray(body.contacts) ? body.contacts.slice(0, 200) : [];
  const now = Date.now();
  const stmts = [];
  for (const c of list) {
    if (!validId(c.id)) continue;
    const data = cleanContact(c);
    if (!hasContent(data)) continue;
    const created = Number.isFinite(c.createdAt) && c.createdAt > 0 && c.createdAt <= now ? c.createdAt : now;
    stmts.push(env.DB.prepare("INSERT OR IGNORE INTO contacts (id, data, photo, created_at, created_by, created_by_name, updated_at, updated_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
      .bind(c.id, JSON.stringify(data), validPhoto(c.photo) ? c.photo : null, created, me.username, me.name || me.username, now, me.username));
  }
  let added = 0;
  if (stmts.length) {
    const res = await env.DB.batch(stmts);
    added = res.reduce((n, r) => n + ((r.meta && r.meta.changes) || 0), 0);
  }
  return reply(200, { added });
}

export default {
  async fetch(request, env) {
    try { return await handle(request, env); }
    catch (e) {
      console.log("Server error", e && e.stack || e);
      return reply(500, { error: "server_error", message: "Server error: " + ((e && e.message) || "unknown") });
    }
  },
};

async function handle(request, env) {
  {
    const origin = request.headers.get("Origin") || "";
    const path = new URL(request.url).pathname.replace(/\/+$/, "");

    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors() });
    if (request.method !== "POST") return reply(405, { error: "method_not_allowed" });
    if (origin !== ALLOWED_ORIGIN) return reply(403, { error: "forbidden_origin" });
    if (!env.USERS || !env.ANTHROPIC_API_KEY || !env.ADMIN_PASSWORD || !env.SESSION_SECRET) return reply(500, { error: "not_configured" });

    let body = {};
    try { body = await request.json(); } catch {}

    if (path === "/login") return login(env, body);

    const me = await authed(request, env);
    if (!me) return reply(401, { error: "signed_out" });

    if (path === "/me") return reply(200, { user: publicUser(me) });
    if (path === "/scan") return scan(env, me, body);
    if (path.startsWith("/contacts/")) {
      if (!env.DB) return reply(500, { error: "no_database" });
      await ensureTable(env);
      if (path === "/contacts/list") return listContacts(env);
      if (path === "/contacts/get") return getContact(env, body);
      if (path === "/contacts/save") return saveContact(env, me, body);
      if (path === "/contacts/delete") return deleteContact(env, me, body);
      if (path === "/contacts/import") return importContacts(env, me, body);
    }

    if (path.startsWith("/admin/")) {
      if (me.role !== "admin") return reply(403, { error: "not_admin" });
      if (path === "/admin/users") return listUsers(env);
      if (path === "/admin/create") return createUser(env, me, body);
      if (path === "/admin/update") return updateUser(env, me, body);
      if (path === "/admin/delete") return deleteUser(env, me, body);
    }
    return reply(404, { error: "not_found" });
  }
}
