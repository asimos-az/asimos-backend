import "dotenv/config";
import express from "express";
import cors from "cors";
import { createClient } from "@supabase/supabase-js";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";

const app = express();
app.use(cors());
app.use(express.json());

// Serve static assets from /public (e.g. /logo.png)
// Put your logo at: <project_root>/public/logo.png
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(path.join(__dirname, "..", "public")));

const PORT = process.env.PORT || 4000;

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SUPABASE_SERVICE_ROLE_KEY) {
  console.warn("Missing Supabase env vars. Please set SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY");
}

const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
});
const supabaseAnon = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
});

// Expo push notifications (optional)
// NOTE: To fully enable push, add `expo_push_token` TEXT column to `profiles` table.
// Example SQL:
//   alter table public.profiles add column if not exists expo_push_token text;
const EXPO_PUSH_ENDPOINT = "https://exp.host/--/api/v2/push/send";// Static Super Admin (for React Admin Panel)
// You can override these via env vars on Render.
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "admin@asimos.local";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin1234";
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || "change_me_super_secret";
const ADMIN_TOKEN_TTL_SEC = Number(process.env.ADMIN_TOKEN_TTL_SEC || 60 * 60 * 24 * 7); // 7 days

function b64urlJson(obj) {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}

function signAdminToken(payload) {
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const fullPayload = { ...payload, iat: now, exp: now + ADMIN_TOKEN_TTL_SEC };
  const part1 = b64urlJson(header);
  const part2 = b64urlJson(fullPayload);
  const data = `${part1}.${part2}`;
  const sig = crypto.createHmac("sha256", ADMIN_JWT_SECRET).update(data).digest("base64url");
  return `${data}.${sig}`;
}

function verifyAdminToken(token) {
  try {
    const parts = String(token || "").split(".");
    if (parts.length !== 3) return null;
    const [p1, p2, sig] = parts;
    const data = `${p1}.${p2}`;
    const expected = crypto.createHmac("sha256", ADMIN_JWT_SECRET).update(data).digest("base64url");
    if (sig.length !== expected.length) return null;
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
    const payload = JSON.parse(Buffer.from(p2, "base64url").toString("utf8"));
    const now = Math.floor(Date.now() / 1000);
    if (!payload?.exp || now >= payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

function requireAdmin(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  const payload = verifyAdminToken(token);
  if (!payload) return res.status(401).json({ error: "Unauthorized" });
  req.admin = payload;
  next();
}

async function logEvent(type, actorId, metadata) {
  try {
    // events table must exist (see supabase_migrations.sql)
    await supabaseAdmin.from("events").insert({
      type,
      actor_id: actorId || null,
      metadata: metadata || null,
    });
  } catch {
    // ignore if table doesn't exist or insert fails
  }
}

function chunk(arr, size) {
  const out = [];
  for (let i = 0; i < (arr?.length || 0); i += size) out.push(arr.slice(i, i + size));
  return out;
}

async function sendExpoPush(messages) {
  if (!messages?.length) return { ok: true, sent: 0 };

  // Expo recommends max 100 messages per request
  const batches = chunk(messages, 100);
  let sent = 0;

  for (const batch of batches) {
    const r = await fetch(EXPO_PUSH_ENDPOINT, {
      method: "POST",
      headers: {
        "Accept": "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(batch),
    });

    const data = await r.json().catch(() => null);
    if (!r.ok) {
      console.warn("Expo push send failed", r.status, data);
      continue;
    }
    sent += batch.length;
  }
  return { ok: true, sent };
}

async function insertNotifications(rows) {
  if (!rows?.length) return { ok: true, inserted: 0 };
  try {
    // Chunk to avoid payload limits
    const batches = chunk(rows, 500);
    let inserted = 0;
    for (const b of batches) {
      const { error } = await supabaseAdmin.from("notifications").insert(b);
      if (error) {
        const msg = String(error.message || "");
        // If table doesn't exist yet, don't break notification flow.
        if (/Could not find the table|schema cache|does not exist/i.test(msg)) {
          return { ok: false, warning: "notifications table missing" };
        }
        console.warn("insertNotifications failed", msg);
        continue;
      }
      inserted += b.length;
    }
    return { ok: true, inserted };
  } catch (e) {
    console.warn("insertNotifications exception", e?.message || e);
    return { ok: false };
  }
}

async function notifyNearbySeekers(job) {
  try {
    const lat = toNum(job?.location?.lat);
    const lng = toNum(job?.location?.lng);
    if (lat === null || lng === null) return { ok: false, reason: "no_job_location" };

    const radiusM = toNum(job?.notifyRadiusM) ?? 500;
    if (!Number.isFinite(radiusM) || radiusM <= 0) return { ok: false, reason: "invalid_radius" };

    // Fetch seekers in pages (covers large user counts)
    const all = [];
    const PAGE = 1000;
    for (let offset = 0; offset < 20000; offset += PAGE) {
      const { data, error } = await supabaseAdmin
        .from("profiles")
        .select("id, full_name, location, expo_push_token")
        .eq("role", "seeker")
        .range(offset, offset + PAGE - 1);

      if (error) {
        console.warn("notifyNearbySeekers: profile fetch failed", error.message);
        return { ok: false, reason: "profile_fetch_failed" };
      }
      if (!data || data.length === 0) break;

      // Pull tokens from the dedicated push_tokens table (preferred)
      const ids = data.map((x) => x.id).filter(Boolean);
      let tokenMap = new Map();
      if (ids.length) {
        const { data: tData } = await supabaseAdmin
          .from("push_tokens")
          .select("user_id, expo_push_token")
          .in("user_id", ids);
        for (const t of tData || []) tokenMap.set(t.user_id, t.expo_push_token);
      }

      all.push(
        ...data.map((p) => ({
          ...p,
          __push_token: tokenMap.get(p.id) || p.expo_push_token || null,
        }))
      );
      if (data.length < PAGE) break;
    }

    const messages = [];
    const notifRows = [];
    for (const p of all) {
      const token = p?.__push_token || p?.expo_push_token;
      if (!token || typeof token !== "string") continue;
      const pl = p?.location || null;
      const plat = toNum(pl?.lat);
      const plng = toNum(pl?.lng);
      if (plat === null || plng === null) continue;

      const d = haversineDistanceM(lat, lng, plat, plng);
      if (d <= radiusM) {
        const title = "Yaxınlıqda iş var";
        const body = job?.title ? `\"${job.title}\" üçün vakansiya var.` : "Sənin yaxınlığında yeni vakansiya var.";

        // Save to in-app inbox (best-effort)
        notifRows.push({
          user_id: p.id,
          title,
          body,
          data: { type: "job", jobId: job?.id || null },
        });

        messages.push({
          to: token,
          sound: "default",
          title,
          body,
          data: { type: "job", jobId: job?.id || null },
        });
      }
    }

    // Save notifications first (best-effort)
    await insertNotifications(notifRows);

    const res = await sendExpoPush(messages);
    return { ok: true, candidates: all.length || 0, notified: messages.length, sent: res.sent };
  } catch (e) {
    console.warn("notifyNearbySeekers error", e);
    return { ok: false, reason: "exception" };
  }
}

function toNum(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function haversineDistanceM(lat1, lon1, lat2, lon2) {
  const R = 6371000;
  const toRad = (d) => (d * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) *
    Math.sin(dLon / 2) * Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

function bbox(lat, lng, radiusM) {
  // Approx bounding box
  const latDelta = radiusM / 111320;
  const lngDelta = radiusM / (111320 * Math.cos((lat * Math.PI) / 180));
  return {
    minLat: lat - latDelta,
    maxLat: lat + latDelta,
    minLng: lng - lngDelta,
    maxLng: lng + lngDelta,
  };
}

function slugify(input) {
  return String(input || "")
    .trim()
    .toLowerCase()
    .replace(/['"]/g, "")
    .replace(/[^a-z0-9\s-]/g, "")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
}


const MS_DAY = 24 * 60 * 60 * 1000;

function normalizeJobType(jobType, isDaily) {
  const raw = String(jobType || "").trim().toLowerCase();
  if (raw === "temporary" || raw === "temp" || raw.includes("müvəqqəti") || raw.includes("muveqqeti")) return "temporary";
  if (raw === "permanent" || raw === "perm" || raw.includes("daimi")) return "permanent";
  return isDaily ? "temporary" : "permanent";
}

function computeExpiresAt(jobType, durationDays) {
  const now = Date.now();
  if (jobType === "temporary") {
    const days = Number(durationDays);
    return new Date(now + days * MS_DAY).toISOString();
  }
  return new Date(now + 28 * MS_DAY).toISOString();
}

async function cleanupExpiredJobs() {
  try {
    const nowIso = new Date().toISOString();
    // Delete jobs with explicit expiry
    await supabaseAdmin.from("jobs").delete().lte("expires_at", nowIso);

    // Backward-compat: if expires_at is missing, treat permanent jobs as 28-day TTL
    const cutoffIso = new Date(Date.now() - 28 * MS_DAY).toISOString();
    await supabaseAdmin.from("jobs").delete().is("expires_at", null).eq("is_daily", false).lte("created_at", cutoffIso);
    await supabaseAdmin.from("jobs").delete().is("expires_at", null).is("is_daily", null).lte("created_at", cutoffIso);
  } catch {
    // ignore (e.g., column doesn't exist yet)
  }
}


function profileToUser(profile, authUser) {
  return {
    id: profile?.id || authUser?.id,
    role: profile?.role,
    fullName: profile?.full_name || "",
    companyName: profile?.company_name || null,
    email: authUser?.email || null,
    phone: profile?.phone || null,
    location: profile?.location || null,
  };
}

async function getProfile(userId) {
  const { data, error } = await supabaseAdmin
    .from("profiles")
    .select("*")
    .eq("id", userId)
    .maybeSingle();

  if (error) throw new Error(error.message);
  return data;
}

async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Unauthorized" });

    // Validate token and get user
    const { data, error } = await supabaseAnon.auth.getUser(token);
    if (error || !data?.user) return res.status(401).json({ error: "Invalid token" });

    req.authUser = data.user;
    req.accessToken = token;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Unauthorized" });
  }
}

app.get("/health", (req, res) => res.json({ ok: true }));
// -------------------- Admin API --------------------
app.post("/admin/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "Missing fields" });

    const emailIn = String(email).trim().toLowerCase();
    const passIn = String(password).trim();
    const emailEnv = String(ADMIN_EMAIL || "").trim().toLowerCase();
    const passEnv = String(ADMIN_PASSWORD || "").trim();

    if (emailIn !== emailEnv || passIn !== passEnv) {
      await logEvent("admin_login_failed", null, { email });
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = signAdminToken({ sub: "admin", role: "super_admin", email: ADMIN_EMAIL });
    await logEvent("admin_login_success", null, { email: ADMIN_EMAIL });
    return res.json({ token, admin: { email: ADMIN_EMAIL, role: "super_admin" } });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

app.get("/admin/me", requireAdmin, (req, res) => {
  return res.json({ admin: { email: req.admin.email, role: req.admin.role } });
});

app.get("/admin/dashboard", requireAdmin, async (req, res) => {
  try {
    const { count: usersTotal } = await supabaseAdmin.from("profiles").select("*", { count: "exact", head: true });
    const { count: seekersTotal } = await supabaseAdmin.from("profiles").select("*", { count: "exact", head: true }).eq("role", "seeker");
    const { count: employersTotal } = await supabaseAdmin.from("profiles").select("*", { count: "exact", head: true }).eq("role", "employer");
    const { count: jobsTotal } = await supabaseAdmin.from("jobs").select("*", { count: "exact", head: true });

    // Events are optional until you run supabase_migrations.sql.
    // If the table doesn't exist yet, we still return dashboard counts.
    const evRes = await supabaseAdmin
      .from("events")
      .select("*")
      .order("created_at", { ascending: false })
      .limit(25);

    const evErrMsg = (evRes?.error?.message || "").toString();
    const eventsSetupRequired = /Could not find the table|schema cache/i.test(evErrMsg);
    const latestEvents = eventsSetupRequired ? [] : (evRes?.data || []);

    return res.json({
      usersTotal: usersTotal || 0,
      seekersTotal: seekersTotal || 0,
      employersTotal: employersTotal || 0,
      jobsTotal: jobsTotal || 0,
      latestEvents,
      eventsSetupRequired,
    });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

// Users (profiles)
app.get("/admin/users", requireAdmin, async (req, res) => {
  try {
    const q = (req.query.q || "").toString().trim();
    const role = (req.query.role || "").toString().trim();
    const limit = Math.min(200, Math.max(1, Number(req.query.limit || 50)));
    const offset = Math.max(0, Number(req.query.offset || 0));

    // NOTE: Some projects don't have profiles.updated_at (or even created_at).
    // Don't hard-depend on those columns; try a safe ordering and gracefully fall back.
    const buildBaseQuery = () => {
      let query = supabaseAdmin
        .from("profiles")
        .select("*")
        .range(offset, offset + limit - 1);

      if (role && ["seeker", "employer"].includes(role)) query = query.eq("role", role);
      if (q) {
        const safe = q.replaceAll(",", " ").trim();
        query = query.or(`full_name.ilike.%${safe}%,company_name.ilike.%${safe}%,phone.ilike.%${safe}%`);
      }
      return query;
    };

    // Try ordering by created_at first (common), otherwise no order.
    let { data, error } = await buildBaseQuery().order("created_at", { ascending: false });
    if (error && /does not exist/i.test(error.message || "")) {
      ({ data, error } = await buildBaseQuery());
    }
    if (error) return res.status(400).json({ error: error.message });
    return res.json({ items: data || [], limit, offset });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

app.patch("/admin/users/:id", requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const patch = req.body || {};

    const allowed = {
      role: patch.role,
      full_name: patch.full_name,
      company_name: patch.company_name,
      phone: patch.phone,
      location: patch.location,
      expo_push_token: patch.expo_push_token,
    };

    Object.keys(allowed).forEach((k) => allowed[k] === undefined && delete allowed[k]);

    if (allowed.role && !["seeker", "employer"].includes(allowed.role)) {
      return res.status(400).json({ error: "Invalid role" });
    }

    const { data, error } = await supabaseAdmin.from("profiles").update(allowed).eq("id", id).select("*").single();
    if (error) return res.status(400).json({ error: error.message });

    await logEvent("admin_user_updated", null, { target_user_id: id, patch: allowed });
    return res.json({ ok: true, user: data });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

app.delete("/admin/users/:id", requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;

    await supabaseAdmin.from("profiles").delete().eq("id", id);
    try { await supabaseAdmin.auth.admin.deleteUser(id); } catch {}

    await logEvent("admin_user_deleted", null, { target_user_id: id });
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

// Jobs
app.get("/admin/jobs", requireAdmin, async (req, res) => {
  try {
    const q = (req.query.q || "").toString().trim();
    const limit = Math.min(200, Math.max(1, Number(req.query.limit || 50)));
    const offset = Math.max(0, Number(req.query.offset || 0));

    let query = supabaseAdmin
      .from("jobs")
      .select("*")
      .order("created_at", { ascending: false })
      .range(offset, offset + limit - 1);

    if (q) {
      const safe = q.replaceAll(",", " ").trim();
      query = query.or(`title.ilike.%${safe}%,category.ilike.%${safe}%,description.ilike.%${safe}%`);
    }

    const { data, error } = await query;
    if (error) return res.status(400).json({ error: error.message });
    return res.json({ items: data || [], limit, offset });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

// Admin can create jobs from panel (same fields as mobile employer create)
// Required: created_by (employer user id), title
app.post("/admin/jobs", requireAdmin, async (req, res) => {
  try {
    const body = req.body || {};
    const title = String(body.title || "").trim();
    const created_by = body.created_by ? String(body.created_by).trim() : "";

    if (!title) return res.status(400).json({ error: "Title is required" });
    if (!created_by) return res.status(400).json({ error: "created_by (employer user id) is required" });

    // Validate employer exists
    const { data: emp, error: empErr } = await supabaseAdmin
      .from("profiles")
      .select("id, role")
      .eq("id", created_by)
      .single();
    if (empErr || !emp) return res.status(400).json({ error: "Employer user not found" });
    if (String(emp.role || "").toLowerCase() !== "employer") {
      return res.status(400).json({ error: "created_by must be an employer" });
    }

    const is_daily = !!body.is_daily;
    const notify_radius_m = body.notify_radius_m !== undefined && body.notify_radius_m !== null && body.notify_radius_m !== ""
      ? Number(body.notify_radius_m)
      : null;
    const location_lat = body.location_lat !== undefined && body.location_lat !== null && body.location_lat !== ""
      ? Number(body.location_lat)
      : null;
    const location_lng = body.location_lng !== undefined && body.location_lng !== null && body.location_lng !== ""
      ? Number(body.location_lng)
      : null;

    const insertRow = {
      created_by,
      title,
      category: body.category ? String(body.category).trim() : null,
      description: body.description ? String(body.description) : "",
      wage: body.wage ? String(body.wage).trim() : null,
      whatsapp: body.whatsapp ? String(body.whatsapp).trim() : null,
      is_daily,
      notify_radius_m: Number.isFinite(notify_radius_m) ? notify_radius_m : null,
      location_lat: Number.isFinite(location_lat) ? location_lat : null,
      location_lng: Number.isFinite(location_lng) ? location_lng : null,
      location_address: body.location_address ? String(body.location_address) : null,
      status: body.status ? String(body.status) : "open",
    };

    // Some older DB schemas may not have the `status` column yet.
    // If insert fails specifically due to missing column, retry without status (best-effort).
    let insertRes = await supabaseAdmin.from("jobs").insert(insertRow).select("*").single();
    if (insertRes.error && /\bstatus\b/i.test(insertRes.error.message || "")) {
      const { status, ...withoutStatus } = insertRow;
      insertRes = await supabaseAdmin.from("jobs").insert(withoutStatus).select("*").single();
    }
    const { data, error } = insertRes;
    if (error) return res.status(400).json({ error: error.message });

    // Trigger seeker notifications (best-effort)
    try {
      const jobForNotify = {
        id: data.id,
        title: data.title,
        notifyRadiusM: data.notify_radius_m ?? (Number.isFinite(notify_radius_m) ? notify_radius_m : 500),
        location: {
          lat: data.location_lat,
          lng: data.location_lng,
        },
      };
      await notifyNearbySeekers(jobForNotify);
    } catch {}

    await logEvent("admin_job_created", null, { job_id: data.id, created_by });
    return res.json({ ok: true, job: data });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

app.patch("/admin/jobs/:id", requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const patch = req.body || {};

    const allowed = {
      title: patch.title,
      category: patch.category,
      description: patch.description,
      wage: patch.wage,
      whatsapp: patch.whatsapp,
      is_daily: patch.is_daily,
      notify_radius_m: patch.notify_radius_m,
      location_lat: patch.location_lat,
      location_lng: patch.location_lng,
      location_address: patch.location_address,
    };
    Object.keys(allowed).forEach((k) => allowed[k] === undefined && delete allowed[k]);

    const { data, error } = await supabaseAdmin.from("jobs").update(allowed).eq("id", id).select("*").single();
    if (error) return res.status(400).json({ error: error.message });

    await logEvent("admin_job_updated", null, { job_id: id, patch: allowed });
    return res.json({ ok: true, job: data });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

app.delete("/admin/jobs/:id", requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const { error } = await supabaseAdmin.from("jobs").delete().eq("id", id);
    if (error) return res.status(400).json({ error: error.message });
    await logEvent("admin_job_deleted", null, { job_id: id });
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});


// Categories (with sub-categories via parent_id)
app.get("/admin/categories", requireAdmin, async (req, res) => {
  try {
    const q = (req.query.q || "").toString().trim();
    const limit = Math.min(1000, Math.max(1, Number(req.query.limit || 200)));

    let query = supabaseAdmin
      .from("categories")
      .select("*")
      .order("sort", { ascending: true })
      .order("created_at", { ascending: false })
      .limit(limit);

    if (q) {
      const safe = q.replaceAll(",", " ").trim();
      query = query.or(`name.ilike.%${safe}%,slug.ilike.%${safe}%`);
    }

    const { data, error } = await query;
    if (error) {
      const msg = (error.message || "").toString();
      if (/Could not find the table|schema cache/i.test(msg)) {
        return res.json({
          items: [],
          categoriesSetupRequired: true,
          hint:
            "Supabase SQL Editor-də backend/supabase_migrations.sql faylını run edin (public.categories cədvəli yaradılmalıdır). Sonra 10-30 saniyə gözləyin və yenidən yoxlayın.",
        });
      }
      return res.status(400).json({ error: msg });
    }
    return res.json({ items: data || [] });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

app.post("/admin/categories", requireAdmin, async (req, res) => {
  try {
    const { name, slug, sort, is_active, parent_id } = req.body || {};
    if (!name || !String(name).trim()) return res.status(400).json({ error: "Name is required" });

    const finalSlug = String(slug || "").trim() ? String(slug).trim() : slugify(name);
    if (!finalSlug) return res.status(400).json({ error: "Slug is required" });

    // Optional: validate parent exists
    if (parent_id) {
      const { data: parent, error: pErr } = await supabaseAdmin.from("categories").select("id").eq("id", parent_id).maybeSingle();
      if (pErr) return res.status(400).json({ error: pErr.message });
      if (!parent) return res.status(400).json({ error: "Parent category not found" });
    }

    const payload = {
      name: String(name).trim(),
      slug: finalSlug,
      sort: Number.isFinite(Number(sort)) ? Number(sort) : 0,
      is_active: is_active !== false,
      parent_id: parent_id || null,
    };

    const { data, error } = await supabaseAdmin.from("categories").insert(payload).select("*").single();
    if (error) return res.status(400).json({ error: error.message });

    await logEvent("admin_category_created", null, { category_id: data.id, payload });
    return res.json({ ok: true, category: data });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

app.patch("/admin/categories/:id", requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const patch = req.body || {};

    const allowed = {
      name: patch.name !== undefined ? String(patch.name || "").trim() : undefined,
      slug: patch.slug !== undefined ? String(patch.slug || "").trim() : undefined,
      sort: patch.sort !== undefined ? (Number.isFinite(Number(patch.sort)) ? Number(patch.sort) : 0) : undefined,
      is_active: patch.is_active !== undefined ? patch.is_active !== false : undefined,
      parent_id: patch.parent_id !== undefined ? (patch.parent_id || null) : undefined,
    };
    Object.keys(allowed).forEach((k) => allowed[k] === undefined && delete allowed[k]);

    if (allowed.name === "") return res.status(400).json({ error: "Name is required" });
    if (allowed.slug === "") allowed.slug = allowed.name ? slugify(allowed.name) : undefined;

    if (allowed.parent_id) {
      if (allowed.parent_id === id) return res.status(400).json({ error: "Parent cannot be itself" });
      const { data: parent, error: pErr } = await supabaseAdmin.from("categories").select("id").eq("id", allowed.parent_id).maybeSingle();
      if (pErr) return res.status(400).json({ error: pErr.message });
      if (!parent) return res.status(400).json({ error: "Parent category not found" });
    }

    const { data, error } = await supabaseAdmin.from("categories").update(allowed).eq("id", id).select("*").single();
    if (error) return res.status(400).json({ error: error.message });

    await logEvent("admin_category_updated", null, { category_id: id, patch: allowed });
    return res.json({ ok: true, category: data });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

app.delete("/admin/categories/:id", requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;

    // Prevent deleting a parent that still has children (so admin doesn't accidentally break structure)
    const { count: childrenCount, error: cErr } = await supabaseAdmin
      .from("categories")
      .select("*", { count: "exact", head: true })
      .eq("parent_id", id);

    if (cErr) return res.status(400).json({ error: cErr.message });
    if ((childrenCount || 0) > 0) {
      return res.status(400).json({ error: "Bu kateqoriyanın alt-kateqoriyaları var. Əvvəlcə onları silin və ya parent-i dəyişin." });
    }

    const { error } = await supabaseAdmin.from("categories").delete().eq("id", id);
    if (error) return res.status(400).json({ error: error.message });

    await logEvent("admin_category_deleted", null, { category_id: id });
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

// Public categories (for mobile selects)
app.get("/categories", async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from("categories")
      .select("*")
      .eq("is_active", true)
      .order("sort", { ascending: true })
      .order("created_at", { ascending: false })
      .limit(2000);

    if (error) {
      const msg = (error.message || "").toString();
      if (/Could not find the table|schema cache/i.test(msg)) {
        return res.json({ items: [], categoriesSetupRequired: true });
      }
      return res.status(400).json({ error: msg });
    }

    // Nest them: parents -> children
    const byId = new Map();
    const parents = [];
    for (const c of data || []) byId.set(c.id, { ...c, children: [] });
    for (const c of byId.values()) {
      if (c.parent_id && byId.has(c.parent_id)) byId.get(c.parent_id).children.push(c);
      else parents.push(c);
    }
    return res.json({ items: parents });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

// Events
app.get("/admin/events", requireAdmin, async (req, res) => {
  try {
    const type = (req.query.type || "").toString().trim();
    const actorId = (req.query.actorId || "").toString().trim();
    const limit = Math.min(200, Math.max(1, Number(req.query.limit || 50)));
    const offset = Math.max(0, Number(req.query.offset || 0));

    let query = supabaseAdmin
      .from("events")
      .select("*")
      .order("created_at", { ascending: false })
      .range(offset, offset + limit - 1);

    if (type) query = query.eq("type", type);
    if (actorId) query = query.eq("actor_id", actorId);

    const { data, error } = await query;
    if (error) {
      const msg = (error.message || "").toString();
      // If events table isn't created yet, don't hard-fail.
      if (/Could not find the table|schema cache/i.test(msg)) {
        return res.json({
          items: [],
          limit,
          offset,
          eventsSetupRequired: true,
          hint:
            "Supabase SQL Editor-də backend/supabase_migrations.sql faylını run edin (public.events cədvəli yaradılmalıdır). Sonra 10-30 saniyə gözləyin və yenidən yoxlayın.",
        });
      }
      return res.status(400).json({ error: msg });
    }
    return res.json({ items: data || [], limit, offset });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});
// -------------------- /Admin API --------------------

// Register -> sends EMAIL OTP code via Supabase Auth (password is set after OTP verification)
app.post("/auth/register", async (req, res) => {
  try {
    const {
      role, // seeker | employer
      fullName,
      companyName,
      email,
      password,
      phone,
      location,
    } = req.body || {};

    if (!email || !password || !fullName || !role) {
      return res.status(400).json({ error: "Missing fields" });
    }
    if (!["seeker", "employer"].includes(role)) {
      return res.status(400).json({ error: "Invalid role" });
    }

    // EMAIL OTP (6 rəqəmli kod) göndər.
    // Qeyd: `signInWithOtp` default olaraq Magic Link email template-ni istifadə edir.
    // 6 rəqəmli OTP görmək üçün Supabase Dashboard > Auth > Email Templates > Magic Link
    // template-inə `{{ .Token }}` əlavə edilməlidir.
    const { data, error } = await supabaseAnon.auth.signInWithOtp({
      email,
      options: {
        shouldCreateUser: true,
        data: {
          role,
          fullName,
          companyName: role === "employer" ? (companyName || null) : null,
          phone: phone || null,
          location: location || null,
        },
      },
    });

    if (error) {
      const msg = error.message || "Auth error";
      const lower = msg.toLowerCase();
      if (lower.includes("rate") && lower.includes("limit")) {
        return res.status(429).json({ error: "Email göndərmə limiti dolub. Biraz sonra yenidən yoxla və ya Supabase-də SMTP qoş." });
      }
      return res.status(400).json({ error: msg });
    }

    // Best-effort: persist role/profile early (fixes cases where OTP metadata is not saved)
    const otpUserId = data?.user?.id;
    if (otpUserId) {
      try {
        const existing = data.user.user_metadata || {};
        await supabaseAdmin.auth.admin.updateUserById(otpUserId, {
          user_metadata: {
            ...existing,
            role,
            fullName,
            companyName: role === "employer" ? (companyName || null) : null,
            phone: phone || null,
            location: location || null,
          },
        });
      } catch {}

      try {
        await supabaseAdmin.from("profiles").upsert({
          id: otpUserId,
          role,
          full_name: fullName,
          company_name: role === "employer" ? (companyName || null) : null,
          phone: phone || null,
          location: location || null,
        });
      } catch {}
    }

    await logEvent("auth_register_request", otpUserId || null, { email, role, hasCompanyName: !!companyName });

    // OTP axınında session adətən NULL olur.
    return res.json({
      ok: true,
      needsOtp: true,
      email,
      message: "OTP sorğusu göndərildi. Əgər emaildə 6 rəqəmli kod görünmürsə, Supabase Dashboard > Auth > Email Templates > Magic Link template-inə {{ .Token }} əlavə edin. Email ümumiyyətlə gəlmirsə, Supabase-də Custom SMTP qoşmaq lazımdır (deliverability).",
      token: null,
      refreshToken: null,
      user: data?.user ? profileToUser(null, data.user) : null,
    });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});



// Geocode proxy (Nominatim) — Azerbaijan focused
app.get("/geo/search", async (req, res) => {
  try {
    const q = (req.query.q || "").toString().trim();
    if (!q) return res.status(400).json({ error: "q is required" });

    // Azerbaijan bounding box (approx): left,top,right,bottom
    const viewbox = "44.73,41.95,50.62,38.30";
    const url =
      "https://nominatim.openstreetmap.org/search?format=jsonv2&limit=5" +
      "&addressdetails=1&accept-language=az&countrycodes=az&bounded=1" +
      "&viewbox=" + encodeURIComponent(viewbox) +
      "&q=" + encodeURIComponent(q);

    const r = await fetch(url, {
      headers: {
        "Accept": "application/json",
        // Identify the app as per Nominatim usage guidance (server-side is fine)
        "User-Agent": "Asimos/1.0 (render-backend)",
      },
    });

    if (!r.ok) {
      const t = await r.text();
      return res.status(502).json({ error: "Geocode failed", status: r.status, body: t.slice(0, 300) });
    }

    const data = await r.json();
    // Normalize fields
    const out = (data || []).map((x) => ({
      display_name: x.display_name,
      lat: Number(x.lat),
      lon: Number(x.lon),
    })).filter(x => Number.isFinite(x.lat) && Number.isFinite(x.lon));

    return res.json(out);
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});


// Login
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "Missing fields" });

    const { data: signin, error } = await supabaseAnon.auth.signInWithPassword({ email, password });
    if (error) return res.status(401).json({ error: "Email və ya şifrə yanlışdır" });

    const profile = await getProfile(signin.user.id);
    await logEvent("auth_login", signin.user.id, { email });

    return res.json({
      token: signin.session.access_token,
      refreshToken: signin.session.refresh_token,
      user: profileToUser(profile, signin.user),
    });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});


// Verify Email OTP and return session tokens + create profile
app.post("/auth/verify-otp", async (req, res) => {
  try {
    const { email, code, password, role: roleFromReq, fullName: fullNameFromReq, companyName: companyNameFromReq, phone: phoneFromReq, location: locationFromReq } = req.body || {};
    if (!email || !code) return res.status(400).json({ error: "Missing fields" });
    if (!password) return res.status(400).json({ error: "Password required" });

    const cleanCode = String(code).replace(/\s+/g, "").trim();
    // Supabase Email OTP length can be configured in Dashboard (6 or 8 digits).
    // We accept both so the app keeps working while you switch it to 6 digits.
    if (!/^\d{6,8}$/.test(cleanCode)) {
      return res.status(400).json({ error: "OTP kod 6 (və ya 8) rəqəmli olmalıdır" });
    }

    const { data, error } = await supabaseAnon.auth.verifyOtp({
      email,
      token: cleanCode,
      type: "email",
    });

    if (error) {
      const msg = error.message || "Auth error";
      const lower = msg.toLowerCase();
      if (lower.includes("rate") && lower.includes("limit")) {
        return res.status(429).json({ error: "Email göndərmə limiti dolub. Biraz sonra yenidən yoxla və ya Supabase-də SMTP qoş." });
      }
      return res.status(400).json({ error: msg });
    }
    if (!data?.user || !data?.session) return res.status(400).json({ error: "OTP doğrulanmadı" });

    const userId = data.user.id;

    const md = data.user.user_metadata || {};
    const requestedRole = (roleFromReq ?? md.role);
    const finalRole = ["seeker", "employer"].includes(requestedRole) ? requestedRole : "seeker";

    const finalFullName = String(fullNameFromReq ?? md.fullName ?? "");
    const finalCompanyName = finalRole === "employer" ? (companyNameFromReq ?? md.companyName ?? null) : null;
    const finalPhone = phoneFromReq ?? md.phone ?? null;
    const finalLocation = locationFromReq ?? md.location ?? null;

    // Keep auth user_metadata in sync (best-effort)
    try {
      await supabaseAdmin.auth.admin.updateUserById(userId, {
        user_metadata: {
          ...md,
          role: finalRole,
          fullName: finalFullName,
          companyName: finalCompanyName,
          phone: finalPhone,
          location: finalLocation,
        },
      });
    } catch {}

    const { error: profErr } = await supabaseAdmin.from("profiles").upsert({
      id: userId,
      role: finalRole,
      full_name: finalFullName,
      company_name: finalCompanyName,
      phone: finalPhone,
      location: finalLocation,
    });

    if (profErr) return res.status(400).json({ error: profErr.message });

    // Set password after OTP verification so user can login with email+password
    try {
      const { error: updErr } = await supabaseAdmin.auth.admin.updateUserById(userId, { password });
      if (updErr) return res.status(400).json({ error: updErr.message });
    } catch (e) {
      return res.status(500).json({ error: e.message || "Password set failed" });
    }

    // IMPORTANT:
    // Updating password can invalidate the OTP session tokens.
    // So we create a *fresh* session via email+password and return that token.
    const { data: signin, error: signinErr } = await supabaseAnon.auth.signInWithPassword({ email, password });
    if (signinErr || !signin?.session || !signin?.user) {
      return res.status(400).json({ error: signinErr?.message || "Login after OTP failed" });
    }

    const profile = await getProfile(userId);
    await logEvent("auth_register_verified", userId, { email, role: profile?.role || finalRole });

    return res.json({
      token: signin.session.access_token,
      refreshToken: signin.session.refresh_token,
      user: profileToUser(profile, signin.user),
    });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

// Resend signup confirmation email
app.post("/auth/resend-otp", async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: "email required" });

    // OTP yenidən göndərmək üçün eyni OTP axınını çağırırıq.
    const { error } = await supabaseAnon.auth.signInWithOtp({
      email,
      options: { shouldCreateUser: true },
    });

    if (error) {
      const msg = error.message || "Auth error";
      const lower = msg.toLowerCase();
      if (lower.includes("rate") && lower.includes("limit")) {
        return res.status(429).json({ error: "Email göndərmə limiti dolub. Biraz sonra yenidən yoxla və ya Supabase-də SMTP qoş." });
      }
      return res.status(400).json({ error: msg });
    }
    return res.json({ ok: true, message: "OTP kod yenidən göndərildi" });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});



// Refresh access token using refresh_token (Supabase Auth)
app.post("/auth/refresh", async (req, res) => {
  try {
    const refreshToken = req.body?.refreshToken;
    if (!refreshToken) return res.status(400).json({ error: "refreshToken required" });

    if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
      return res.status(500).json({ error: "Supabase env not configured" });
    }

    const url = `${SUPABASE_URL}/auth/v1/token?grant_type=refresh_token`;

    const r = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "apikey": SUPABASE_ANON_KEY,
        "Authorization": `Bearer ${SUPABASE_ANON_KEY}`,
      },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });

    const data = await r.json().catch(() => null);

    if (!r.ok) {
      const msg = data?.msg || data?.error_description || data?.error || "Refresh failed";
      return res.status(401).json({ error: msg });
    }

    const accessToken = data?.access_token;
    const newRefresh = data?.refresh_token;
    const userId = data?.user?.id;

    if (!accessToken || !userId) {
      return res.status(401).json({ error: "Invalid refresh response" });
    }

    const profile = await getProfile(userId);
    await logEvent("auth_register_verified", userId, { email, role: profile?.role || finalRole });

    return res.json({
      token: accessToken,
      refreshToken: newRefresh || refreshToken,
      user: profileToUser(profile, data.user),
    });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});


// Update my location
app.patch("/me/location", requireAuth, async (req, res) => {
  try {
    const loc = req.body?.location;
    if (!loc || typeof loc.lat !== "number" || typeof loc.lng !== "number") {
      return res.status(400).json({ error: "Invalid location" });
    }

    const { error } = await supabaseAdmin
      .from("profiles")
      .update({ location: loc })
      .eq("id", req.authUser.id);

    if (error) return res.status(400).json({ error: error.message });

    const profile = await getProfile(req.authUser.id);
    await logEvent("location_update", req.authUser.id, { location: loc });
    return res.json({ ok: true, user: profileToUser(profile, req.authUser) });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

// Save Expo Push Token (for notifications)
app.post("/me/push-token", requireAuth, async (req, res) => {
  try {
    const expoPushToken = req.body?.expoPushToken;
    if (!expoPushToken || typeof expoPushToken !== "string") {
      return res.status(400).json({ error: "expoPushToken required" });
    }

    // 1) Upsert into push_tokens (preferred)
    const { error: tokErr } = await supabaseAdmin
      .from("push_tokens")
      .upsert(
        { user_id: req.authUser.id, expo_push_token: expoPushToken, updated_at: new Date().toISOString() },
        { onConflict: "user_id" }
      );
    if (tokErr) {
      return res.status(400).json({ error: tokErr.message || "Update failed" });
    }

    // 2) Best-effort legacy storage on profiles (optional)
    await supabaseAdmin
      .from("profiles")
      .update({ expo_push_token: expoPushToken })
      .eq("id", req.authUser.id)
      .then(() => {})
      .catch(() => {});
    await logEvent("push_token_saved", req.authUser.id, { hasToken: true });
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

// Remove Expo Push Token (disable notifications)
app.delete("/me/push-token", requireAuth, async (req, res) => {
  try {
    // 1) Remove from push_tokens
    await supabaseAdmin
      .from("push_tokens")
      .delete()
      .eq("user_id", req.authUser.id)
      .then(() => {})
      .catch(() => {});

    // 2) Best-effort legacy storage clear
    await supabaseAdmin
      .from("profiles")
      .update({ expo_push_token: null })
      .eq("id", req.authUser.id)
      .then(() => {})
      .catch(() => {});

    await logEvent("push_token_removed", req.authUser.id, { hasToken: false });
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

// -------------------- Notifications (in-app inbox) --------------------
app.get("/me/notifications", requireAuth, async (req, res) => {
  try {
    const limit = Math.min(100, Math.max(1, Number(req.query.limit || 50)));
    const offset = Math.max(0, Number(req.query.offset || 0));

    const { data, error } = await supabaseAdmin
      .from("notifications")
      .select("*")
      .eq("user_id", req.authUser.id)
      .order("created_at", { ascending: false })
      .range(offset, offset + limit - 1);

    if (error) {
      const msg = String(error.message || "");
      if (/Could not find the table|schema cache|does not exist/i.test(msg)) return res.json({ items: [], limit, offset });
      return res.status(400).json({ error: error.message });
    }

    return res.json({ items: data || [], limit, offset });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

app.get("/me/notifications/unread-count", requireAuth, async (req, res) => {
  try {
    const { count, error } = await supabaseAdmin
      .from("notifications")
      .select("id", { count: "exact", head: true })
      .eq("user_id", req.authUser.id)
      .is("read_at", null);
    if (error) {
      const msg = String(error.message || "");
      if (/Could not find the table|schema cache|does not exist/i.test(msg)) return res.json({ unread: 0 });
      return res.status(400).json({ error: error.message });
    }
    return res.json({ unread: count || 0 });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

app.patch("/me/notifications/:id/read", requireAuth, async (req, res) => {
  try {
    const id = String(req.params.id || "");
    if (!id) return res.status(400).json({ error: "id required" });

    const { error } = await supabaseAdmin
      .from("notifications")
      .update({ read_at: new Date().toISOString() })
      .eq("id", id)
      .eq("user_id", req.authUser.id);

    if (error) {
      const msg = String(error.message || "");
      if (/Could not find the table|schema cache|does not exist/i.test(msg)) return res.json({ ok: true });
      return res.status(400).json({ error: error.message });
    }
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

app.post("/me/notifications/read-all", requireAuth, async (req, res) => {
  try {
    const { error } = await supabaseAdmin
      .from("notifications")
      .update({ read_at: new Date().toISOString() })
      .eq("user_id", req.authUser.id)
      .is("read_at", null);

    if (error) {
      const msg = String(error.message || "");
      if (/Could not find the table|schema cache|does not exist/i.test(msg)) return res.json({ ok: true });
      return res.status(400).json({ error: error.message });
    }

    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

// List jobs (search + optional createdBy filter)
app.get("/jobs", requireAuth, async (req, res) => {
  try {
    const createdBy = req.query.createdBy ? String(req.query.createdBy) : null;

    const q = req.query.q ? String(req.query.q) : "";
    const dailyRaw = req.query.daily;
    const daily = (dailyRaw === undefined || dailyRaw === null || dailyRaw === "") ? null : (String(dailyRaw) === "true");

    const profile = await getProfile(req.authUser.id);
    const baseLat = toNum(req.query.lat) ?? toNum(profile?.location?.lat);
    const baseLng = toNum(req.query.lng) ?? toNum(profile?.location?.lng);
    const radiusM = toNum(req.query.radius_m) ?? null;

    // Auto-delete expired jobs (best-effort)
    await cleanupExpiredJobs();

    let query = supabaseAdmin
      .from("jobs")
      .select("*")
      .order("created_at", { ascending: false })
      .limit(200);

    if (createdBy) {
      // Security: only allow "my jobs" filter for the current user
      if (createdBy !== req.authUser.id) return res.status(403).json({ error: "Forbidden" });
      query = query.eq("created_by", req.authUser.id);
    }

    if (daily !== null) query = query.eq("is_daily", daily);

    if (q) {
      const safe = q.replaceAll(",", " ").trim();
      // OR filter for title/category
      query = query.or(`title.ilike.%${safe}%,category.ilike.%${safe}%`);
    }

    if (baseLat !== null && baseLng !== null && radiusM !== null) {
      const b = bbox(baseLat, baseLng, radiusM);
      query = query
        .gte("location_lat", b.minLat)
        .lte("location_lat", b.maxLat)
        .gte("location_lng", b.minLng)
        .lte("location_lng", b.maxLng);
    }

    const { data, error } = await query;
    if (error) return res.status(400).json({ error: error.message });

    const nowMs = Date.now();

    let items = (data || []).map((r) => {
      const expiresMs = r.expires_at ? new Date(r.expires_at).getTime() : null;
      const createdMs = r.created_at ? new Date(r.created_at).getTime() : null;
      if (expiresMs !== null && expiresMs <= nowMs) return null;
      if (expiresMs === null && (r.is_daily === false || r.is_daily === null) && createdMs !== null && createdMs <= (nowMs - 28 * MS_DAY)) return null;

      const loc = {
        lat: r.location_lat,
        lng: r.location_lng,
        address: r.location_address,
      };
      const job = {
        id: r.id,
        title: r.title,
        category: r.category,
        description: r.description,
        wage: r.wage,
        whatsapp: r.whatsapp,
        isDaily: r.is_daily,
        jobType: r.job_type || (r.is_daily ? "temporary" : "permanent"),
        durationDays: (r.duration_days ?? null),
        expiresAt: (r.expires_at ?? null),
        notifyRadiusM: r.notify_radius_m,
        createdAt: r.created_at,
        createdBy: r.created_by,
        status: (r.status || "open"),
        closedAt: (r.closed_at ?? null),
        closedReason: (r.closed_reason ?? null),
        location: loc,
      };

      if (baseLat !== null && baseLng !== null && typeof loc.lat === "number" && typeof loc.lng === "number") {
        job.distanceM = Math.round(haversineDistanceM(baseLat, baseLng, loc.lat, loc.lng));
      }
      return job;
    }).filter(Boolean);

    if (radiusM !== null) {
      items = items.filter((j) => typeof j.distanceM !== "number" || j.distanceM <= radiusM);
    }

    // Sort closest first if distance exists
    if (baseLat !== null && baseLng !== null) {
      items.sort((a, b) => (a.distanceM ?? 1e18) - (b.distanceM ?? 1e18));
    }

    // Hide closed jobs from seekers by default
    if (profile?.role === "seeker") {
      items = items.filter((j) => String(j.status || "open").toLowerCase() !== "closed");
    }

    return res.json(items);
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

// Get a single job by id
app.get("/jobs/:id", requireAuth, async (req, res) => {
  try {
    const id = String(req.params.id || "");
    if (!id) return res.status(400).json({ error: "id required" });

    // Auto-delete expired jobs (best-effort)
    await cleanupExpiredJobs();

    const { data, error } = await supabaseAdmin
      .from("jobs")
      .select("*")
      .eq("id", id)
      .maybeSingle();

    if (error) return res.status(400).json({ error: error.message });
    if (!data) return res.status(404).json({ error: "Not found" });

    const profile = await getProfile(req.authUser.id);
    const baseLat = toNum(profile?.location?.lat);
    const baseLng = toNum(profile?.location?.lng);

    const job = {
      id: data.id,
      title: data.title,
      category: data.category,
      description: data.description,
      wage: data.wage,
      whatsapp: data.whatsapp,
      isDaily: data.is_daily,
      jobType: data.job_type || (data.is_daily ? "temporary" : "permanent"),
      durationDays: (data.duration_days ?? null),
      expiresAt: (data.expires_at ?? null),
      notifyRadiusM: data.notify_radius_m,
      createdAt: data.created_at,
      createdBy: data.created_by,
      status: (data.status || "open"),
      closedAt: (data.closed_at ?? null),
      closedReason: (data.closed_reason ?? null),
      location: { lat: data.location_lat, lng: data.location_lng, address: data.location_address },
    };

    // If seeker tries to open a closed job, hide it (acts like not found)
    if (profile?.role === "seeker" && String(job.status || "open").toLowerCase() === "closed") {
      return res.status(404).json({ error: "Not found" });
    }

    if (baseLat !== null && baseLng !== null && typeof job.location.lat === "number" && typeof job.location.lng === "number") {
      job.distanceM = Math.round(haversineDistanceM(baseLat, baseLng, job.location.lat, job.location.lng));
    }

    return res.json(job);
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

// Create job (employer only)
app.post("/jobs", requireAuth, async (req, res) => {
  try {
    const profile = await getProfile(req.authUser.id);
    if (profile?.role !== "employer") return res.status(403).json({ error: "Only employer can create jobs" });

    const {
      title,
      category,
      description,
      wage,
      whatsapp,
      isDaily,
      jobType,
      durationDays,
      notifyRadiusM,
      location,
    } = req.body || {};

    if (!title) return res.status(400).json({ error: "Title required" });

    const jt = normalizeJobType(jobType, !!isDaily);
    let dDays = null;
    if (jt === "temporary") {
      dDays = toNum(durationDays);
      if (!dDays || dDays < 1 || dDays > 365) {
        return res.status(400).json({ error: "durationDays required (1-365) for temporary job" });
      }
    }

    const expiresAt = computeExpiresAt(jt, dDays || 1);

    const locLat = toNum(location?.lat);
    const locLng = toNum(location?.lng);
    const locAddr = location?.address ? String(location.address) : null;

    const payload = {
      created_by: req.authUser.id,
      status: "open",
      title,
      category: category || null,
      description: description || "",
      wage: wage || null,
      whatsapp: whatsapp || null,
      // Keep old boolean field for mobile compatibility
      is_daily: jt === "temporary",
      // New fields (may not exist yet — fallback below)
      job_type: jt,
      duration_days: dDays,
      expires_at: expiresAt,
      notify_radius_m: toNum(notifyRadiusM),
      location_lat: locLat,
      location_lng: locLng,
      location_address: locAddr,
    };

    let data = null;
    let error = null;

    ({ data, error } = await supabaseAdmin
      .from("jobs")
      .insert(payload)
      .select("*")
      .single());

    if (error) {
      // If the DB schema is not migrated yet, retry without new columns (so the app keeps working).
      const msg = String(error.message || "");
      if (/column .*\b(job_type|duration_days|expires_at|status)\b/i.test(msg)) {
        const fallback = { ...payload };
        fallback.job_type = undefined;
        fallback.duration_days = undefined;
        fallback.expires_at = undefined;
        fallback.status = undefined;
        fallback.status = undefined;

        const r2 = await supabaseAdmin
          .from("jobs")
          .insert(fallback)
          .select("*")
          .single();

        if (r2.error) return res.status(400).json({ error: r2.error.message });
        data = r2.data;
      } else {
        return res.status(400).json({ error: msg });
      }
    }

    const job = {
      id: data.id,
      title: data.title,
      category: data.category,
      description: data.description,
      wage: data.wage,
      whatsapp: data.whatsapp,
      isDaily: data.is_daily,
      jobType: data.job_type || (data.is_daily ? "temporary" : "permanent"),
      durationDays: (data.duration_days ?? null),
      expiresAt: (data.expires_at ?? null),
      notifyRadiusM: data.notify_radius_m,
      createdAt: data.created_at,
      createdBy: data.created_by,
      status: (data.status || "open"),
      closedAt: (data.closed_at ?? null),
      closedReason: (data.closed_reason ?? null),
      location: { lat: data.location_lat, lng: data.location_lng, address: data.location_address },
    };

    await logEvent("job_create", req.authUser.id, { job_id: job.id, title: job.title, job_type: job.jobType, duration_days: job.durationDays });

    // Fire-and-forget: notify nearby seekers (push notifications), if enabled.
    // This will not block the API response.
    notifyNearbySeekers(job).catch((e) => console.warn("notifyNearbySeekers failed", e?.message || e));

    return res.json(job);
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

// Close a job (employer owner only)
app.patch("/jobs/:id/close", requireAuth, async (req, res) => {
  try {
    const id = String(req.params.id || "");
    if (!id) return res.status(400).json({ error: "id required" });

    const profile = await getProfile(req.authUser.id);
    if (profile?.role !== "employer") return res.status(403).json({ error: "Only employer can close jobs" });

    const { data: row, error: gErr } = await supabaseAdmin
      .from("jobs")
      .select("id, created_by, is_daily, job_type, duration_days")
      .eq("id", id)
      .maybeSingle();
    if (gErr) return res.status(400).json({ error: gErr.message });
    if (!row) return res.status(404).json({ error: "Not found" });
    if (row.created_by !== req.authUser.id) return res.status(403).json({ error: "Forbidden" });

    const reason = req.body?.reason ? String(req.body.reason) : "filled";
    const nowIso = new Date().toISOString();

    // Preferred schema: status/closed_at/closed_reason
    const updatePayload = {
      status: "closed",
      closed_at: nowIso,
      closed_reason: reason,
      // Also set expires_at to now so older clients that only rely on expiry will stop seeing it.
      expires_at: nowIso,
    };

    let updated = null;
    let uErr = null;

    ({ data: updated, error: uErr } = await supabaseAdmin
      .from("jobs")
      .update(updatePayload)
      .eq("id", id)
      .select("*")
      .single());

    if (uErr) {
      const msg = String(uErr.message || "");
      // Fallback for old schema (no status/closed columns)
      if (/column .*\b(status|closed_at|closed_reason)\b/i.test(msg)) {
        const r2 = await supabaseAdmin
          .from("jobs")
          .update({ expires_at: nowIso })
          .eq("id", id)
          .select("*")
          .single();
        if (r2.error) return res.status(400).json({ error: r2.error.message });
        updated = r2.data;
      } else {
        return res.status(400).json({ error: msg });
      }
    }

    await logEvent("job_close", req.authUser.id, { job_id: id, reason });

    // Map to app shape
    return res.json({
      id: updated.id,
      title: updated.title,
      category: updated.category,
      description: updated.description,
      wage: updated.wage,
      whatsapp: updated.whatsapp,
      isDaily: updated.is_daily,
      jobType: updated.job_type || (updated.is_daily ? "temporary" : "permanent"),
      durationDays: (updated.duration_days ?? null),
      expiresAt: (updated.expires_at ?? null),
      notifyRadiusM: updated.notify_radius_m,
      createdAt: updated.created_at,
      createdBy: updated.created_by,
      status: (updated.status || "closed"),
      closedAt: (updated.closed_at ?? nowIso),
      closedReason: (updated.closed_reason ?? reason),
      location: { lat: updated.location_lat, lng: updated.location_lng, address: updated.location_address },
    });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

// Backward/alternate path support (some clients may call singular `/job`)
app.patch("/job/:id/close", requireAuth, async (req, res) => {
  try {
    const id = String(req.params.id || "");
    if (!id) return res.status(400).json({ error: "id required" });

    const profile = await getProfile(req.authUser.id);
    if (profile?.role !== "employer") return res.status(403).json({ error: "Only employer can close jobs" });

    const { data: row, error: gErr } = await supabaseAdmin
      .from("jobs")
      .select("id, created_by, is_daily, job_type, duration_days")
      .eq("id", id)
      .maybeSingle();
    if (gErr) return res.status(400).json({ error: gErr.message });
    if (!row) return res.status(404).json({ error: "Not found" });
    if (row.created_by !== req.authUser.id) return res.status(403).json({ error: "Forbidden" });

    const reason = req.body?.reason ? String(req.body.reason) : "filled";
    const nowIso = new Date().toISOString();

    const updatePayload = {
      status: "closed",
      closed_at: nowIso,
      closed_reason: reason,
      expires_at: nowIso,
    };

    let updated = null;
    let uErr = null;
    ({ data: updated, error: uErr } = await supabaseAdmin
      .from("jobs")
      .update(updatePayload)
      .eq("id", id)
      .select("*")
      .single());

    if (uErr) {
      const msg = String(uErr.message || "");
      if (/column .*\b(status|closed_at|closed_reason)\b/i.test(msg)) {
        const r2 = await supabaseAdmin
          .from("jobs")
          .update({ expires_at: nowIso })
          .eq("id", id)
          .select("*")
          .single();
        if (r2.error) return res.status(400).json({ error: r2.error.message });
        updated = r2.data;
      } else {
        return res.status(400).json({ error: msg });
      }
    }

    await logEvent("job_close", req.authUser.id, { job_id: id, reason });

    return res.json({
      id: updated.id,
      title: updated.title,
      category: updated.category,
      description: updated.description,
      wage: updated.wage,
      whatsapp: updated.whatsapp,
      isDaily: updated.is_daily,
      jobType: updated.job_type || (updated.is_daily ? "temporary" : "permanent"),
      durationDays: (updated.duration_days ?? null),
      expiresAt: (updated.expires_at ?? null),
      notifyRadiusM: updated.notify_radius_m,
      createdAt: updated.created_at,
      createdBy: updated.created_by,
      status: (updated.status || "closed"),
      closedAt: (updated.closed_at ?? nowIso),
      closedReason: (updated.closed_reason ?? reason),
      location: { lat: updated.location_lat, lng: updated.location_lng, address: updated.location_address },
    });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

// Re-open a job (employer owner only)
app.patch("/jobs/:id/reopen", requireAuth, async (req, res) => {
  try {
    const id = String(req.params.id || "");
    if (!id) return res.status(400).json({ error: "id required" });

    const profile = await getProfile(req.authUser.id);
    if (profile?.role !== "employer") return res.status(403).json({ error: "Only employer can reopen jobs" });

    const { data: row, error: gErr } = await supabaseAdmin
      .from("jobs")
      .select("id, created_by, job_type, duration_days, is_daily")
      .eq("id", id)
      .maybeSingle();
    if (gErr) return res.status(400).json({ error: gErr.message });
    if (!row) return res.status(404).json({ error: "Not found" });
    if (row.created_by !== req.authUser.id) return res.status(403).json({ error: "Forbidden" });

    const jt = normalizeJobType(row.job_type || null, !!row.is_daily);
    const expiresAt = computeExpiresAt(jt, toNum(row.duration_days) || 1);

    let updated = null;
    let uErr = null;
    ({ data: updated, error: uErr } = await supabaseAdmin
      .from("jobs")
      .update({ status: "open", closed_at: null, closed_reason: null, expires_at: expiresAt })
      .eq("id", id)
      .select("*")
      .single());

    if (uErr) {
      const msg = String(uErr.message || "");
      if (/column .*\b(status|closed_at|closed_reason)\b/i.test(msg)) {
        const r2 = await supabaseAdmin
          .from("jobs")
          .update({ expires_at: expiresAt })
          .eq("id", id)
          .select("*")
          .single();
        if (r2.error) return res.status(400).json({ error: r2.error.message });
        updated = r2.data;
      } else {
        return res.status(400).json({ error: msg });
      }
    }

    await logEvent("job_reopen", req.authUser.id, { job_id: id });

    return res.json({
      id: updated.id,
      title: updated.title,
      category: updated.category,
      description: updated.description,
      wage: updated.wage,
      whatsapp: updated.whatsapp,
      isDaily: updated.is_daily,
      jobType: updated.job_type || (updated.is_daily ? "temporary" : "permanent"),
      durationDays: (updated.duration_days ?? null),
      expiresAt: (updated.expires_at ?? expiresAt),
      notifyRadiusM: updated.notify_radius_m,
      createdAt: updated.created_at,
      createdBy: updated.created_by,
      status: (updated.status || "open"),
      closedAt: (updated.closed_at ?? null),
      closedReason: (updated.closed_reason ?? null),
      location: { lat: updated.location_lat, lng: updated.location_lng, address: updated.location_address },
    });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

// Backward/alternate path support (some clients may call singular `/job`)
app.patch("/job/:id/reopen", requireAuth, async (req, res) => {
  try {
    const id = String(req.params.id || "");
    if (!id) return res.status(400).json({ error: "id required" });

    const profile = await getProfile(req.authUser.id);
    if (profile?.role !== "employer") return res.status(403).json({ error: "Only employer can reopen jobs" });

    const { data: row, error: gErr } = await supabaseAdmin
      .from("jobs")
      .select("id, created_by, job_type, duration_days, is_daily")
      .eq("id", id)
      .maybeSingle();
    if (gErr) return res.status(400).json({ error: gErr.message });
    if (!row) return res.status(404).json({ error: "Not found" });
    if (row.created_by !== req.authUser.id) return res.status(403).json({ error: "Forbidden" });

    const jt = normalizeJobType(row.job_type || null, !!row.is_daily);
    const expiresAt = computeExpiresAt(jt, toNum(row.duration_days) || 1);

    let updated = null;
    let uErr = null;
    ({ data: updated, error: uErr } = await supabaseAdmin
      .from("jobs")
      .update({ status: "open", closed_at: null, closed_reason: null, expires_at: expiresAt })
      .eq("id", id)
      .select("*")
      .single());

    if (uErr) {
      const msg = String(uErr.message || "");
      if (/column .*\b(status|closed_at|closed_reason)\b/i.test(msg)) {
        const r2 = await supabaseAdmin
          .from("jobs")
          .update({ expires_at: expiresAt })
          .eq("id", id)
          .select("*")
          .single();
        if (r2.error) return res.status(400).json({ error: r2.error.message });
        updated = r2.data;
      } else {
        return res.status(400).json({ error: msg });
      }
    }

    await logEvent("job_reopen", req.authUser.id, { job_id: id });

    return res.json({
      id: updated.id,
      title: updated.title,
      category: updated.category,
      description: updated.description,
      wage: updated.wage,
      whatsapp: updated.whatsapp,
      isDaily: updated.is_daily,
      jobType: updated.job_type || (updated.is_daily ? "temporary" : "permanent"),
      durationDays: (updated.duration_days ?? null),
      expiresAt: (updated.expires_at ?? null),
      notifyRadiusM: updated.notify_radius_m,
      createdAt: updated.created_at,
      createdBy: updated.created_by,
      status: (updated.status || "open"),
      closedAt: (updated.closed_at ?? null),
      closedReason: (updated.closed_reason ?? null),
      location: { lat: updated.location_lat, lng: updated.location_lng, address: updated.location_address },
    });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

app.listen(PORT, () => {
  console.log(`Asimos backend running on :${PORT}`);
});
