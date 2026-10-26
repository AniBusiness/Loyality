// Multi-store loyalty backend on Cloudflare Workers + D1 (free plan friendly).
// Login = phone number first, then a customer-chosen password. No SMS/OTP, so nothing to pay for.
// Stamps can ONLY be added by store staff (store PIN) at the counter, never by customers.
const enc = new TextEncoder(), dec = new TextDecoder();
class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status } }
const fail = (s, m) => { throw new HttpError(s, m) };
const json = (d, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, "0")).join("");
const b64u = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64u = s => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
const hmacKey = secret => crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
// Keyed hash: PINs/passwords are hashed with a secret that lives only in Cloudflare (never in the database),
// so a leaked database alone cannot be used to guess PINs offline.
const kh = async (secret, text) => hex(await crypto.subtle.sign("HMAC", await hmacKey(secret), enc.encode(text)));
async function signJwt(payload, secret) {
  const h = b64u(enc.encode('{"alg":"HS256","typ":"JWT"}')), p = b64u(enc.encode(JSON.stringify(payload)));
  return `${h}.${p}.${b64u(await crypto.subtle.sign("HMAC", await hmacKey(secret), enc.encode(h + "." + p)))}`;
}
async function verifyJwt(token, secret) {
  const [h, p, s] = (token || "").split(".");
  if (!s || !(await crypto.subtle.verify("HMAC", await hmacKey(secret), unb64u(s), enc.encode(h + "." + p)))) fail(401, "Please sign in again");
  const d = JSON.parse(dec.decode(unb64u(p)));
  if (d.exp < Date.now() / 1000) fail(401, "Please sign in again");
  return d;
}
async function limit(env, key, max, sec) {
  const w = Math.floor(Date.now() / 1000 / sec);
  const r = await env.DB.prepare("INSERT INTO hits(k,w,n) VALUES(?,?,1) ON CONFLICT(k,w) DO UPDATE SET n=n+1 RETURNING n").bind(key, w).first();
  if (r.n > max) fail(429, "Too many attempts, please try again in a few minutes");
}

const pub = s => ({ slug: s.slug, name: s.name, emoji: s.emoji, goal: s.goal, color: s.color });
const getUser = (env, phone) => env.DB.prepare("SELECT * FROM users WHERE phone=?").bind(phone || "").first();
const getStore = async (env, slug) => (await env.DB.prepare("SELECT * FROM stores WHERE slug=?").bind(slug || "").first()) || fail(404, "Unknown store");

// Profile + this store's card + wallet of all the customer's cards. Only writes when the card is new.
async function view(env, phone, slug) {
  const [u, store] = await Promise.all([getUser(env, phone), getStore(env, slug)]);
  let c = await env.DB.prepare("SELECT * FROM cards WHERE phone=? AND store=?").bind(phone, slug).first();
  if (!c) { await env.DB.prepare("INSERT OR IGNORE INTO cards(phone,store) VALUES(?,?)").bind(phone, slug).run(); c = { stamps: 0, free_redeemed: 0 } }
  const [hist, wallet] = await Promise.all([
    env.DB.prepare("SELECT type, at FROM events WHERE phone=? AND store=? ORDER BY id DESC LIMIT 20").bind(phone, slug).all(),
    env.DB.prepare("SELECT s.slug, s.name, s.emoji, s.goal, s.color, c.stamps FROM cards c JOIN stores s ON s.slug=c.store WHERE c.phone=?").bind(phone).all(),
  ]);
  return {
    user: { phone, name: u.name, age: u.age, gender: u.gender, email: u.email }, store: pub(store),
    card: { stamps: c.stamps, freeRedeemed: c.free_redeemed, history: hist.results }, wallet: wallet.results,
  };
}

async function route(req, env) {
  const url = new URL(req.url), p = url.pathname, m = req.method, q = url.searchParams.get("store");
  const body = m === "POST" || m === "PUT" ? await req.json().catch(() => ({})) : {};
  const DB = env.DB, secret = env.JWT_SECRET || fail(500, "JWT_SECRET is not set");
  const ip = req.headers.get("cf-connecting-ip") || "x";
  const session = async phone => signJwt({ phone, exp: Math.floor(Date.now() / 1000) + 90 * 86400 }, secret);
  const storePin = (slug, pin) => kh(secret, `store:${slug}:${pin}`);
  const checkStorePin = async (store, pin) => {
    await limit(env, `pin:${ip}:${store.slug}`, 30, 600);
    if (store.pin !== await storePin(store.slug, String(pin || ""))) fail(403, "Wrong staff PIN for this store");
  };
  const validPhone = x => /^\d{10}$/.test(x || ""), validPassword = x => typeof x === "string" && x.length >= 4 && x.length <= 64;

  /* ---- Customer ---- */
  if (m === "GET" && p === "/api/store") return json({ store: pub(await getStore(env, q)) });

  // Step 1 of login: is this number already a customer? (rate-limited per IP)
  if (m === "POST" && p === "/api/auth/check") {
    await getStore(env, body.store); await limit(env, "check:" + ip, 30, 600);
    if (!validPhone(body.phone)) fail(400, "Enter a valid 10-digit number");
    const u = await getUser(env, body.phone);
    return json({ exists: !!u, reset: !!u && !u.pin_hash && u.reset_until > Date.now() });
  }

  if (m === "POST" && p === "/api/auth/signup") {
    const { phone, password, name, age, gender, email, store: slug } = body;
    await getStore(env, slug); await limit(env, "signup:" + ip, 10, 3600);
    if (!validPhone(phone)) fail(400, "Enter a valid 10-digit number");
    if (!validPassword(password)) fail(400, "Password must be at least 4 characters");
    if (!name?.trim() || !(age >= 5 && age <= 110) || !gender) fail(400, "Name, age and gender are required");
    if (await getUser(env, phone)) fail(409, "This number already has a card — sign in, or ask at the counter to reset your password");
    await DB.prepare("INSERT INTO users(phone,name,age,gender,email,pin_hash) VALUES(?,?,?,?,?,?)")
      .bind(phone, name.trim().slice(0, 60), age, gender, (email || "").trim().slice(0, 100) || null, await kh(secret, `pw:${phone}:${password}`)).run();
    return json({ token: await session(phone), ...(await view(env, phone, slug)) });
  }

  if (m === "POST" && p === "/api/auth/login") {
    const { phone, password, store: slug } = body;
    await getStore(env, slug); await limit(env, "login:" + ip, 30, 600);
    if (!validPhone(phone) || !validPassword(password)) fail(400, "Enter your number and password");
    const u = await getUser(env, phone), bad = () => fail(401, "Wrong password");
    if (!u) bad();
    if (u.locked_until > Date.now()) fail(429, `Too many wrong tries. Try again in ${Math.ceil((u.locked_until - Date.now()) / 60000)} min, or ask at the counter`);
    const h = await kh(secret, `pw:${phone}:${password}`);
    if (!u.pin_hash) { // counter reset the PIN: the customer may choose a new one within 15 minutes
      if (!(u.reset_until > Date.now())) fail(403, "Ask at the counter to reset your password");
      await DB.prepare("UPDATE users SET pin_hash=?, fails=0, locked_until=0, reset_until=NULL WHERE phone=?").bind(h, phone).run();
    } else if (u.pin_hash !== h) {
      // 5 wrong tries -> 30 min lock; every further wrong try locks again, doubling up to 24 h
      const f = u.fails + 1, lock = f >= 5 ? Date.now() + Math.min(30 * 60000 * 2 ** Math.floor(f / 5 - 1), 86400000) : 0;
      await DB.prepare("UPDATE users SET fails=?, locked_until=? WHERE phone=?").bind(f, lock, phone).run();
      bad();
    } else if (u.fails) await DB.prepare("UPDATE users SET fails=0, locked_until=0 WHERE phone=?").bind(phone).run();
    return json({ token: await session(phone), ...(await view(env, phone, slug)) });
  }

  if (m === "GET" && p === "/api/me") {
    const phone = (await verifyJwt((req.headers.get("authorization") || "").slice(7), secret)).phone;
    if (!(await getUser(env, phone))) fail(401, "Please sign in again");
    return json(await view(env, phone, q));
  }

  /* ---- Store staff (PIN is per store) ---- */
  if (m === "POST" && (p === "/api/staff/stamp" || p === "/api/staff/redeem")) {
    const type = p.endsWith("stamp") ? "stamp" : "redeem", slug = body.store, phone = body.phone, store = await getStore(env, slug);
    await checkStorePin(store, body.pin);
    if (!(await getUser(env, phone))) fail(404, "No customer with that number — ask them to create a card first");
    await DB.prepare("INSERT OR IGNORE INTO cards(phone,store) VALUES(?,?)").bind(phone, slug).run();
    const c = await DB.prepare("SELECT * FROM cards WHERE phone=? AND store=?").bind(phone, slug).first();
    if (type === "stamp" && c.stamps >= store.goal) fail(409, "Free item is waiting — redeem it first");
    if (type === "redeem" && c.stamps < store.goal) fail(409, "Customer hasn’t earned a free item yet");
    await DB.batch([
      DB.prepare(type === "stamp" ? "UPDATE cards SET stamps=stamps+1 WHERE phone=? AND store=?" : "UPDATE cards SET stamps=0, free_redeemed=free_redeemed+1 WHERE phone=? AND store=?").bind(phone, slug),
      DB.prepare("INSERT INTO events(phone,store,type) VALUES(?,?,?)").bind(phone, slug, type),
    ]);
    return json(await view(env, phone, slug));
  }
  if (m === "POST" && p === "/api/staff/reset-login") { // customer forgot PIN: staff taps reset, customer sets a new PIN on their phone
    const store = await getStore(env, body.store); await checkStorePin(store, body.pin);
    if (!(await getUser(env, body.phone))) fail(404, "No customer with that number");
    await DB.prepare("UPDATE users SET pin_hash=NULL, fails=0, locked_until=0, reset_until=? WHERE phone=?").bind(Date.now() + 15 * 60000, body.phone).run();
    return json({ ok: true });
  }
  if (m === "PUT" && p === "/api/store/settings") {
    const { store: slug, pin, name, emoji, color, goal, newPin } = body, store = await getStore(env, slug);
    await checkStorePin(store, pin);
    const g = Math.round(+goal);
    if (!name?.trim() || !(g >= 2 && g <= 20) || !/^#[0-9a-f]{6}$/i.test(color || "")) fail(400, "Enter a name, a goal between 2 and 20 and a valid colour");
    const pinH = /^\d{4,8}$/.test(newPin || "") ? await storePin(slug, newPin) : store.pin;
    await DB.batch([
      DB.prepare("UPDATE stores SET name=?, emoji=?, color=?, goal=?, pin=? WHERE slug=?").bind(name.trim(), (emoji || "").trim().slice(0, 8) || "⭐", color, g, pinH, slug),
      DB.prepare("UPDATE cards SET stamps=MIN(stamps,?) WHERE store=?").bind(g, slug),
    ]);
    return json({ store: pub(await getStore(env, slug)) });
  }
  if (m === "GET" && p === "/api/admin/stats") { // store owner analytics: header x-staff-pin
    const store = await getStore(env, q); await checkStorePin(store, req.headers.get("x-staff-pin"));
    const from = "FROM users u JOIN cards c ON c.phone=u.phone WHERE c.store=?", all = async sql => (await DB.prepare(sql).bind(q).all()).results;
    return json({
      totals: await DB.prepare(`SELECT COUNT(*) customers, ROUND(AVG(u.age),1) avgAge, SUM(c.free_redeemed) freeGiven ${from}`).bind(q).first(),
      byGender: await all(`SELECT u.gender, COUNT(*) n ${from} GROUP BY u.gender`),
      byAgeGroup: await all(`SELECT CASE WHEN u.age<18 THEN '<18' WHEN u.age<25 THEN '18-24' WHEN u.age<35 THEN '25-34' WHEN u.age<50 THEN '35-49' ELSE '50+' END grp, COUNT(*) n ${from} GROUP BY grp`),
      purchasesPerDay: await all("SELECT date(at) day, COUNT(*) n FROM events WHERE store=? AND type='stamp' GROUP BY day ORDER BY day DESC LIMIT 30"),
    });
  }

  /* ---- You, the software owner (header x-admin-key) ---- */
  if (p.startsWith("/api/super/")) {
    if (!env.ADMIN_KEY || req.headers.get("x-admin-key") !== env.ADMIN_KEY) fail(403, "Forbidden");
    if (m === "POST" && p === "/api/super/stores") {
      const { slug, name, emoji = "⭐", goal = 6, color = "#7c3aed", pin } = body;
      if (!/^[a-z0-9-]{2,40}$/.test(slug || "") || ["api", "admin", "public", "static", "assets"].includes(slug) || !name || !/^\d{4,8}$/.test(pin || "") || !/^#[0-9a-f]{6}$/i.test(color))
        fail(400, "slug (a-z0-9-), name, a 4-8 digit pin and a #rrggbb colour are required");
      if (await DB.prepare("SELECT 1 FROM stores WHERE slug=?").bind(slug).first()) fail(409, "That store name is already taken");
      await DB.prepare("INSERT INTO stores(slug,name,emoji,goal,color,pin) VALUES(?,?,?,?,?,?)").bind(slug, name, emoji, +goal, color, await storePin(slug, pin)).run();
      return json({ store: pub(await getStore(env, slug)), link: `/${slug}` });
    }
    if (m === "GET" && p === "/api/super/stores") return json({
      stores: (await DB.prepare("SELECT s.slug, s.name, s.goal, COUNT(c.phone) customers, COALESCE(SUM(c.free_redeemed),0) freeGiven FROM stores s LEFT JOIN cards c ON c.store=s.slug GROUP BY s.slug").all()).results,
      customersAtMultipleStores: (await DB.prepare("SELECT COUNT(*) n FROM (SELECT phone FROM cards GROUP BY phone HAVING COUNT(*)>1)").first()).n,
    });
  }
  fail(404, "Not found");
}

export default {
  async fetch(req, env) {
    try { return await route(req, env) }
    catch (e) { if (!(e instanceof HttpError)) console.error(e); return json({ error: e instanceof HttpError ? e.message : "Something went wrong" }, e.status || 500) }
  },
};
