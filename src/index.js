import "dotenv/config";
import express from "express";
import cors from "cors";
import { createClient } from "@supabase/supabase-js";
import crypto from "crypto";
import nodemailer from "nodemailer";
import path from "path";
import { fileURLToPath } from "url";
import cron from "node-cron";


const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = process.env.SMTP_PORT || 587;
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const SMTP_FROM = process.env.SMTP_FROM || "no-reply@asimos.local";

const mailer = nodemailer.createTransport({
  host: SMTP_HOST,
  port: SMTP_PORT,
  secure: Number(SMTP_PORT) === 465, // true for 465, false for other ports
  auth: {
    user: SMTP_USER,
    pass: SMTP_PASS,
  },
});

async function sendApprovalEmail(toEmail, fullName) {
  if (!SMTP_HOST || !SMTP_USER) {
    return;
  }
  try {
    await mailer.sendMail({
      from: SMTP_FROM,
      to: toEmail,
      subject: "ASIMOS - Hesabınız Təsdiqləndi",
      text: `Salam ${fullName},\n\nHesabınız admin tərəfindən təsdiqləndi. Artıq proqrama daxil olub işçi axtara bilərsiniz.\n\nHörmətlə,\nAsimos Komandası`,
      html: `<p>Salam <b>${fullName}</b>,</p><p>Hesabınız admin tərəfindən təsdiqləndi. Artıq proqrama daxil olub işçi axtara bilərsiniz.</p><p>Hörmətlə,<br>Asimos Komandası</p>`,
    });
  } catch (e) {
  }
}

const app = express();
app.use(cors());
app.use(express.json());

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(path.join(__dirname, "..", "public")));

const PORT = process.env.PORT || 4000;

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SUPABASE_SERVICE_ROLE_KEY) {
}

const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
});
const supabaseAnon = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
});

const EXPO_PUSH_ENDPOINT = "https://exp.host/--/api/v2/push/send";// Static Super Admin (for React Admin Panel)
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

// --- TELEGRAM CONFIG ---
const TELEGRAM_BOT_TOKEN = "8523281077:AAEtiS8wd8a5E8oto4htgPAUdeLQqEpZJl4";
const TELEGRAM_CHAT_ID = "5920740941";

async function sendTelegram(text) {
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) return;
  try {
    const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;
    await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: TELEGRAM_CHAT_ID,
        text: text,
        parse_mode: "HTML"
      })
    });
  } catch (e) {
    console.error("Telegram error:", e.message);
  }
}

async function logEvent(type, actorId, metadata) {
  try {
    await supabaseAdmin.from("events").insert({
      type,
      actor_id: actorId || null,
      metadata: metadata || null,
    });

    // --- TELEGRAM NOTIFICATIONS ---
    let msg = "";
    const meta = metadata || {};

    if (type === "auth_register_verified") {
      msg = `🚀 <b>Yeni İstifadəçi</b>\nEmail: ${meta.email}\nRol: ${meta.role || "seeker"}`;
    } else if (type === "auth_login") {
      // msg = `🟢 <b>Giriş</b>\nEmail: ${meta.email}`; 
    } else if (type === "admin_login_success") {
      msg = `🛡️ <b>Admin Girişi</b>\nEmail: ${meta.email}`;
    } else if (type === "job_create") {
      const mapLink = meta.lat && meta.lng ? `https://maps.google.com/?q=loc:${meta.lat},${meta.lng}` : "Yoxdur";
      const wazeLink = meta.lat && meta.lng ? `https://waze.com/ul?ll=${meta.lat},${meta.lng}&navigate=yes` : "Yoxdur";

      msg = `📢 <b>Yeni Elan</b>\n\n` +
        `🔹 <b>Başlıq:</b> ${meta.title}\n` +
        `💰 <b>Maaş:</b> ${meta.wage ? meta.wage + " AZN" : "Razılaşma ilə"}\n` +
        `📂 <b>Kateqoriya:</b> ${meta.category || "Qeyd olunmayıb"}\n` +
        `📝 <b>Təsvir:</b> ${meta.description || "-"}\n` +
        `🕒 <b>Növ:</b> ${meta.job_type === "temporary" ? "Müvəqqəti" : "Daimi"} (${meta.duration_days || 1} gün)\n` +
        `📍 <b>Ünvan:</b> ${meta.address || "Qeyd olunmayıb"}\n` +
        `📞 <b>Əlaqə:</b> ${meta.phone || meta.whatsapp || "-"}\n` +
        `🔗 <b>Link:</b> ${meta.link || "-"}\n` +
        `🗺 <b>Xəritə:</b> <a href="${mapLink}">Google Maps</a> | <a href="${wazeLink}">Waze</a>`;
    } else if (type === "support_ticket") {
      msg = `📩 <b>Dəstək Bileti</b>\n\n` +
        `👤 <b>İstifadəçi:</b> ${meta.email}\n` +
        `📂 <b>Kateqoriya:</b> ${meta.category || "Ümumi"}\n` +
        `❓ <b>Mövzu:</b> ${meta.subject}\n` +
        `💬 <b>Mesaj:</b>\n${meta.message}`;
    }

    if (msg) await sendTelegram(msg);

  } catch (e) {
    console.error("Log event error:", e.message);
  }
}

function toNum(v) {
  if (v === null || v === undefined || v === "") return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function haversineDistanceM(la1, lo1, la2, lo2) {
  const R = 6371e3; // metres
  const φ1 = la1 * Math.PI / 180;
  const φ2 = la2 * Math.PI / 180;
  const Δφ = (la2 - la1) * Math.PI / 180;
  const Δλ = (lo2 - lo1) * Math.PI / 180;

  const a = Math.sin(Δφ / 2) * Math.sin(Δφ / 2) +
    Math.cos(φ1) * Math.cos(φ2) *
    Math.sin(Δλ / 2) * Math.sin(Δλ / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

  return R * c;
}

function chunk(arr, size) {
  const out = [];
  for (let i = 0; i < (arr?.length || 0); i += size) out.push(arr.slice(i, i + size));
  return out;
}

async function sendExpoPush(messages) {
  if (!messages?.length) return { ok: true, sent: 0 };

  const batches = chunk(messages, 100);
  let sent = 0;
  let paramErrors = [];

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
      await insertNotifications([{
        user_id: batch[0].data?.jobId ? messages[0].data.jobId : null, // Try to find a target if possible, otherwise skip
        title: "Expo Error",
        body: `Status: ${r.status}. Data: ${JSON.stringify(data)}`,
        data: { type: "debug" }
      }]);
      continue;
    }

    if (data?.data) {
      const firstRes = data.data[0];

      const errorDetails = data.data.filter(x => x.status === "error");
      if (errorDetails.length > 0) {
      }
    }

    if (data?.data) {
      const errs = data.data.filter(x => x.status === "error");
      if (errs.length > 0) paramErrors.push(...errs);
    }

    sent += batch.length;
  }
  return { ok: true, sent, errors: paramErrors };
}

async function insertNotifications(rows) {
  if (!rows?.length) return { ok: true, inserted: 0 };
  try {
    const batches = chunk(rows, 500);
    let inserted = 0;
    for (const b of batches) {
      const { error } = await supabaseAdmin.from("notifications").insert(b);
      if (error) {
        const msg = String(error.message || "");
        if (/Could not find the table|schema cache|does not exist/i.test(msg)) {
          return { ok: false, warning: "notifications table missing" };
        }
        continue;
      }
      inserted += b.length;
    }
    return { ok: true, inserted };
  } catch (e) {
    return { ok: false };
  }
}





async function notifyNearbyEmployers(alert, seekerName) {
  try {
    const lat = toNum(alert?.location_lat);
    const lng = toNum(alert?.location_lng);
    const radiusM = toNum(alert?.radius_m) || 10000;
    const category = alert?.category;

    if (lat === null || lng === null) return { ok: false, reason: "no_alert_location" };
    if (!category) return { ok: false, reason: "no_category" };

    // Find employers with matching category
    // Note: We use ilike for flexible matching. Real prod might use exact slug match.
    const { data: employers, error } = await supabaseAdmin
      .from("profiles")
      .select("id, full_name, location, expo_push_token, company_name")
      .eq("role", "employer")
      .ilike("category", `%${category}%`);

    if (error || !employers || employers.length === 0) return { ok: true, matched: 0 };

    const pushMessages = [];
    const historyRows = [];
    let matchCount = 0;

    for (const emp of employers) {
      const plat = toNum(emp.location?.lat);
      const plng = toNum(emp.location?.lng);
      if (plat === null || plng === null) continue;

      const d = haversineDistanceM(lat, lng, plat, plng);
      if (d <= radiusM) {
        matchCount++;
        const title = "Yeni işçi axtarışı";
        const body = `Yaxınlıqda (${Math.round(d)}m) ${seekerName || "bir nəfər"} ${category} sahəsi üzrə iş axtarır.`;
        const dataPayload = { type: "alert_match", alertId: alert.id };

        const userToken = emp.expo_push_token;

        if (userToken && String(userToken).startsWith("ExponentPushToken")) {
          pushMessages.push({
            to: userToken,
            title,
            body,
            data: dataPayload,
            sound: "default",
            priority: "high"
          });
        }
        historyRows.push({
          user_id: emp.id,
          title,
          body,
          data: dataPayload
        });
      }
    }

    if (pushMessages.length > 0) {
      sendExpoPush(pushMessages).catch(console.error);
    }
    if (historyRows.length > 0) {
      await insertNotifications(historyRows);
    }

    return { ok: true, matched: matchCount };
  } catch (e) {
    console.warn("notifyNearbyEmployers error", e);
    return { ok: false };
  }
}

function isValidLatLng(lat, lng) {
  return (
    typeof lat === "number" &&
    typeof lng === "number" &&
    Number.isFinite(lat) &&
    Number.isFinite(lng) &&
    lat >= -90 &&
    lat <= 90 &&
    lng >= -180 &&
    lng <= 180
  );
}



function bbox(lat, lng, radiusM) {
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
  if (raw === "seeker") return "seeker";
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
    await supabaseAdmin.from("jobs").delete().lte("expires_at", nowIso);

    const cutoffIso = new Date(Date.now() - 28 * MS_DAY).toISOString();
    await supabaseAdmin.from("jobs").delete().is("expires_at", null).eq("is_daily", false).lte("created_at", cutoffIso);
    await supabaseAdmin.from("jobs").delete().is("expires_at", null).is("is_daily", null).lte("created_at", cutoffIso);
  } catch {
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

    const { data, error } = await supabaseAnon.auth.getUser(token);
    if (error || !data?.user) return res.status(401).json({ error: "Invalid token" });

    req.authUser = data.user;
    req.accessToken = token;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Unauthorized" });
  }
}

async function optionalAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;
    if (!token) {
      req.authUser = null;
      req.accessToken = null;
      return next();
    }

    // 1. Try Admin Token
    const adminPayload = verifyAdminToken(token);
    if (adminPayload) {
      req.authUser = {
        id: "admin",
        email: adminPayload.email,
        role: "admin",
        is_admin: true
      };
      req.accessToken = token;
      return next();
    }

    // 2. Try Supabase Token
    const { data, error } = await supabaseAnon.auth.getUser(token);
    if (error || !data?.user) {
      req.authUser = null;
      req.accessToken = null;
      return next();
    }
    req.authUser = data.user;
    req.accessToken = token;
    return next();
  } catch {
    req.authUser = null;
    req.accessToken = null;
    return next();
  }
}

app.get("/health", (req, res) => res.json({ ok: true }));
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

app.get("/admin/users", requireAdmin, async (req, res) => {
  try {
    const q = (req.query.q || "").toString().trim();
    const role = (req.query.role || "").toString().trim();
    const limit = Math.min(200, Math.max(1, Number(req.query.limit || 50)));
    const offset = Math.max(0, Number(req.query.offset || 0));

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
      status: patch.status,
    };

    Object.keys(allowed).forEach((k) => allowed[k] === undefined && delete allowed[k]);

    if (allowed.role && !["seeker", "employer"].includes(allowed.role)) {
      return res.status(400).json({ error: "Invalid role" });
    }
    if (allowed.status && !["active", "pending", "suspended"].includes(allowed.status)) {
      return res.status(400).json({ error: "Invalid status" });
    }

    let shouldSendEmail = false;
    if (allowed.status === "active") {
      const { data: oldProfile } = await supabaseAdmin.from("profiles").select("status").eq("id", id).single();
      if (oldProfile && oldProfile.status === "pending") {
        shouldSendEmail = true;
      }
    }

    const { data, error } = await supabaseAdmin.from("profiles").update(allowed).eq("id", id).select("*").single();
    if (error) return res.status(400).json({ error: error.message });

    if (shouldSendEmail) {
      const { data: authUser } = await supabaseAdmin.auth.admin.getUserById(id);
      if (authUser?.user?.email) {
      }
    }

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
    try { await supabaseAdmin.auth.admin.deleteUser(id); } catch { }

    await logEvent("admin_user_deleted", null, { target_user_id: id });
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

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

app.post("/admin/jobs", requireAdmin, async (req, res) => {
  try {
    const body = req.body || {};
    const title = String(body.title || "").trim();
    const created_by = body.created_by ? String(body.created_by).trim() : "";

    if (!title) return res.status(400).json({ error: "Title is required" });
    if (!created_by) return res.status(400).json({ error: "created_by (employer user id) is required" });

    const { data: emp, error: empErr } = await supabaseAdmin
      .from("profiles")
      .select("id, role, average_rating")
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

    if (!Number.isFinite(location_lat) || !Number.isFinite(location_lng)) {
      return res.status(400).json({ error: "Lokasiya seçilməlidir (xəritədən seçin)" });
    }
    if (location_lat < -90 || location_lat > 90 || location_lng < -180 || location_lng > 180) {
      return res.status(400).json({ error: "Lokasiya koordinatları düzgün deyil" });
    }


    const insertRow = {
      created_by,
      title,
      category: body.category ? String(body.category).trim() : null,
      description: body.description ? String(body.description) : "",
      wage: body.wage ? String(body.wage).trim() : null,
      whatsapp: body.whatsapp ? String(body.whatsapp).trim() : null,
      contact_phone: (body.contact_phone || body.phone || body.contactPhone) ? String(body.contact_phone || body.phone || body.contactPhone).trim() : null,
      contact_link: (body.contact_link || body.link || body.contactLink) ? String(body.contact_link || body.link || body.contactLink).trim() : null,
      voen: body.voen ? String(body.voen).trim() : null,
      is_daily,
      notify_radius_m: Number.isFinite(notify_radius_m) ? notify_radius_m : null,
      location_lat: Number.isFinite(location_lat) ? location_lat : null,
      location_lng: Number.isFinite(location_lng) ? location_lng : null,
      location_address: body.location_address ? String(body.location_address) : null,
      location_address: body.location_address ? String(body.location_address) : null,
      status: body.status ? String(body.status) : "open",
    };

    if (emp.average_rating && emp.average_rating >= 4.8) {
      const boostDate = new Date();
      boostDate.setDate(boostDate.getDate() + 7); // +1 week
      insertRow.boosted_until = boostDate.toISOString();
    }

    let insertRes = await supabaseAdmin.from("jobs").insert(insertRow).select("*").single();
    if (insertRes.error && /\bstatus\b/i.test(insertRes.error.message || "")) {
      const { status, ...withoutStatus } = insertRow;
      insertRes = await supabaseAdmin.from("jobs").insert(withoutStatus).select("*").single();
    }
    const { data, error } = insertRes;
    if (error) return res.status(400).json({ error: error.message });

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
    } catch { }

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
      contact_phone: patch.contact_phone ?? patch.phone ?? patch.contactPhone,
      contact_link: patch.contact_link ?? patch.link ?? patch.contactLink,
      voen: patch.voen,
      is_daily: patch.is_daily,
      notify_radius_m: patch.notify_radius_m,
      location_lat: patch.location_lat,
      location_lng: patch.location_lng,
      location_address: patch.location_address,
      status: patch.status,
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
      category,
    } = req.body || {};

    if (!email || !password || !fullName || !role) {
      return res.status(400).json({ error: "Missing fields" });
    }
    if (!["seeker", "employer"].includes(role)) {
      return res.status(400).json({ error: "Invalid role" });
    }

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
            category: role === "employer" ? (category || null) : null,
          },
        });
      } catch { }

      try {
        await supabaseAdmin.from("profiles").upsert({
          id: otpUserId,
          role,
          full_name: fullName,
          company_name: role === "employer" ? (companyName || null) : null,
          phone: phone || null,
          location: location || null,
          category: role === "employer" ? (category || null) : null,
        });
      } catch { }
    }

    await logEvent("auth_register_request", otpUserId || null, { email, role, hasCompanyName: !!companyName });

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



app.get("/geo/search", async (req, res) => {
  try {
    const q = (req.query.q || "").toString().trim();
    if (!q) return res.status(400).json({ error: "q is required" });

    const viewbox = "44.0,42.0,51.0,38.0";
    const url =
      "https://nominatim.openstreetmap.org/search?format=jsonv2&limit=5" +
      "&addressdetails=1&accept-language=az&countrycodes=az" +
      "&viewbox=" + encodeURIComponent(viewbox) +
      "&q=" + encodeURIComponent(q);

    const r = await fetch(url, {
      headers: {
        "Accept": "application/json",
        "User-Agent": "AsimosApp/1.0 (info@asimos.az)",
      },
    });

    if (!r.ok) {
      const t = await r.text();
      return res.status(502).json({ error: "Geocode failed", status: r.status, body: t.slice(0, 300) });
    }

    const data = await r.json();
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


app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "Missing fields" });

    const { data: signin, error } = await supabaseAnon.auth.signInWithPassword({ email, password });
    if (error) return res.status(401).json({ error: "Email və ya şifrə yanlışdır" });

    const profile = await getProfile(signin.user.id);
    await logEvent("auth_login", signin.user.id, { email });

    if (profile?.status === "pending") {
      return res.status(403).json({ error: "Hesabınız təsdiq gözləyir. Admin təsdiqindən sonra daxil ola bilərsiniz." });
    }
    if (profile?.status === "suspended") {
      return res.status(403).json({ error: "Hesabınız bloklanıb." });
    }

    return res.json({
      token: signin.session.access_token,
      refreshToken: signin.session.refresh_token,
      user: profileToUser(profile, signin.user),
    });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});


app.post("/auth/verify-otp", async (req, res) => {
  try {
    const { email, code, password, role: roleFromReq, fullName: fullNameFromReq, companyName: companyNameFromReq, phone: phoneFromReq, location: locationFromReq } = req.body || {};
    if (!email || !code) return res.status(400).json({ error: "Missing fields" });
    if (!password) return res.status(400).json({ error: "Password required" });

    const cleanCode = String(code).replace(/\s+/g, "").trim();
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
    } catch { }

    // Check if profile exists (if not, it's a new or resurrected user -> clean up potential orphans)
    const { data: existingProfile } = await supabaseAdmin.from("profiles").select("id").eq("id", userId).maybeSingle();
    if (!existingProfile) {
      try {
        await supabaseAdmin.from("notifications").delete().eq("user_id", userId);
        await supabaseAdmin.from("job_alerts").delete().eq("user_id", userId);
        await supabaseAdmin.from("push_tokens").delete().eq("user_id", userId);
      } catch { }
    }


    const { error: profErr } = await supabaseAdmin.from("profiles").upsert({
      id: userId,
      role: finalRole,
      full_name: finalFullName,
      company_name: finalCompanyName,
      phone: finalPhone,
      location: finalLocation,
      status: finalRole === "employer" ? "pending" : "active",
    });

    if (profErr) return res.status(400).json({ error: profErr.message });

    try {
      const { error: updErr } = await supabaseAdmin.auth.admin.updateUserById(userId, { password });
      if (updErr) return res.status(400).json({ error: updErr.message });
    } catch (e) {
      return res.status(500).json({ error: e.message || "Password set failed" });
    }

    const { data: signin, error: signinErr } = await supabaseAnon.auth.signInWithPassword({ email, password });
    if (signinErr || !signin?.session || !signin?.user) {
      return res.status(400).json({ error: signinErr?.message || "Login after OTP failed" });
    }

    const profile = await getProfile(userId);
    await logEvent("auth_register_verified", userId, { email, role: profile?.role || finalRole });

    if (profile?.status === "pending") {
      return res.json({
        ok: true,
        pendingApproval: true,
        message: "Qeydiyyat tamamlandı. Hesabınız admin təsdiqindən sonra aktivləşəcək. Təsdiq olunduqda sizə email gələcək.",
        user: profileToUser(profile, signin.user),
        token: null,
        refreshToken: null,
      });
    }

    return res.json({
      token: signin.session.access_token,
      refreshToken: signin.session.refresh_token,
      user: profileToUser(profile, signin.user),
    });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

app.post("/auth/resend-otp", async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: "email required" });

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
    const userEmail = data.user?.email;
    await logEvent("auth_refreshed", userId, { email: userEmail, role: profile?.role });

    return res.json({
      token: accessToken,
      refreshToken: newRefresh || refreshToken,
      user: profileToUser(profile, data.user),
    });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});


app.patch("/me/location", requireAuth, async (req, res) => {
  try {
    const loc = req.body?.location;
    if (!loc || typeof loc.lat !== "number" || typeof loc.lng !== "number") {
      return res.status(400).json({ error: "Invalid location" });
    }
    if (!isValidLatLng(loc.lat, loc.lng)) {
      return res.status(400).json({ error: "Invalid location range" });
    }

    if (!isValidLatLng(loc.lat, loc.lng)) {
      return res.status(400).json({ error: "Lokasiya koordinatları düzgün deyil" });
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

app.post("/me/push-token", requireAuth, async (req, res) => {
  try {
    const expoPushToken = req.body?.expoPushToken;
    if (!expoPushToken || typeof expoPushToken !== "string") {
      return res.status(400).json({ error: "expoPushToken required" });
    }

    const { error: tokErr } = await supabaseAdmin
      .from("push_tokens")
      .upsert(
        { user_id: req.authUser.id, expo_push_token: expoPushToken, updated_at: new Date().toISOString() },
        { onConflict: "user_id" }
      );
    if (tokErr) {
      return res.status(400).json({ error: tokErr.message || "Update failed" });
    }

    await supabaseAdmin
      .from("profiles")
      .update({ expo_push_token: expoPushToken })
      .eq("id", req.authUser.id)
      .then(() => { })
      .catch(() => { });
    await logEvent("push_token_saved", req.authUser.id, { hasToken: true });
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

app.delete("/me/push-token", requireAuth, async (req, res) => {
  try {
    await supabaseAdmin
      .from("push_tokens")
      .delete()
      .eq("user_id", req.authUser.id)
      .then(() => { })
      .catch(() => { });

    await supabaseAdmin
      .from("profiles")
      .update({ expo_push_token: null })
      .eq("id", req.authUser.id)
      .then(() => { })
      .catch(() => { });

    await logEvent("push_token_removed", req.authUser.id, { hasToken: false });
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

app.post("/ratings", requireAuth, async (req, res) => {
  try {
    const { target_id, job_id, score, comment } = req.body || {};
    if (!target_id || !job_id || !score) return res.status(400).json({ error: "Missing fields" });

    const numScore = Number(score);
    if (!Number.isInteger(numScore) || numScore < 1 || numScore > 5) {
      return res.status(400).json({ error: "Score must be 1-5" });
    }

    if (req.authUser.id === target_id) return res.status(400).json({ error: "Cannot rate yourself" });

    const { error: insErr } = await supabaseAdmin.from("ratings").insert({
      reviewer_id: req.authUser.id,
      target_id,
      job_id,
      score: numScore,
      comment: String(comment || "").trim(),
    });

    if (insErr) {
      if (insErr.message.includes("unique")) {
        return res.status(400).json({ error: "Siz bu elan üçün artıq reytinq vermisiniz." });
      }
      return res.status(400).json({ error: insErr.message });
    }

    const { data: allRatings, error: rErr } = await supabaseAdmin
      .from("ratings")
      .select("score")
      .eq("target_id", target_id);

    if (!rErr && allRatings) {
      const count = allRatings.length;
      const sum = allRatings.reduce((acc, r) => acc + r.score, 0);
      const avg = count > 0 ? sum / count : 0;

      await supabaseAdmin
        .from("profiles")
        .update({ average_rating: avg, rating_count: count })
        .eq("id", target_id);

      await logEvent("user_rated", req.authUser.id, { target_id, score: numScore, new_avg: avg });
    }

    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});


app.post("/auth/forgot-password", async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: "Email required" });

    const cleanEmail = String(email).trim().toLowerCase();

    const { error } = await supabaseAnon.auth.signInWithOtp({
      email: cleanEmail,
      options: { shouldCreateUser: false },
    });

    if (error) {
      const msg = error.message || "Auth error";
      const lower = msg.toLowerCase();
      if (lower.includes("rate") && lower.includes("limit")) {
        return res.status(429).json({ error: "Email göndərmə limiti dolub. Biraz sonra yenidən yoxla." });
      }
      return res.status(400).json({ error: msg });
    }

    return res.json({ ok: true, message: "OTP kod emailinizə göndərildi." });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

app.post("/auth/reset-password", async (req, res) => {
  try {
    const { email, code, password } = req.body || {};
    if (!email || !code || !password) return res.status(400).json({ error: "Missing fields" });

    const cleanEmail = String(email).trim().toLowerCase();
    const cleanCode = String(code).replace(/\s+/g, "").trim();


    let verifyData = null;
    let verifyError = null;

    const { data: d1, error: e1 } = await supabaseAnon.auth.verifyOtp({
      email: cleanEmail,
      token: cleanCode,
      type: "email",
    });
    if (!e1 && d1?.session) verifyData = d1;
    else verifyError = e1;

    if (!verifyData) {
      const { data: d2, error: e2 } = await supabaseAnon.auth.verifyOtp({
        email: cleanEmail,
        token: cleanCode,
        type: "recovery",
      });
      if (!e2 && d2?.session) verifyData = d2;
    }

    if (!verifyData) {
      const { data: d3, error: e3 } = await supabaseAnon.auth.verifyOtp({
        email: cleanEmail,
        token: cleanCode,
        type: "signup",
      });
      if (!e3 && d3?.session) verifyData = d3;
    }

    if (!verifyData) {
      return res.status(400).json({ error: verifyError?.message || "Kod yanlışdır və ya müddəti bitib." });
    }

    const data = verifyData;
    const userId = data.user.id;

    const { error: updErr } = await supabaseAdmin.auth.admin.updateUserById(userId, { password });
    if (updErr) return res.status(400).json({ error: updErr.message });

    const { data: signin, error: signinErr } = await supabaseAnon.auth.signInWithPassword({ email: cleanEmail, password });

    if (signinErr) return res.status(400).json({ error: "Şifrə dəyişdi, amma avto-giriş alınmadı. Zəhmət olmasa giriş edin." });

    const profile = await getProfile(userId);
    await logEvent("auth_password_reset", userId, { email: cleanEmail });

    return res.json({
      ok: true,
      token: signin.session.access_token,
      refreshToken: signin.session.refresh_token,
      user: profileToUser(profile, signin.user),
    });

  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});


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

    if (error) return res.status(400).json({ error: error.message });
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

app.post("/me/notifications/read-all", requireAuth, async (req, res) => {
  try {
    await supabaseAdmin
      .from("notifications")
      .update({ read_at: new Date() })
      .eq("user_id", req.authUser.id)
      .is("read_at", null);
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});


app.get("/me/alerts", requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from("job_alerts")
      .select("*")
      .eq("user_id", req.authUser.id)
      .order("created_at", { ascending: false });

    if (error) return res.status(400).json({ error: error.message });
    return res.json(data || []);
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

app.post("/me/alerts", requireAuth, async (req, res) => {
  try {
    const { query, min_wage, max_wage, job_type, location, radius_m, category } = req.body;

    if (!query && !min_wage && !job_type && !location) {
      return res.status(400).json({ error: "Ən azı bir kriteriya seçilməlidir (açar söz, maaş, növ və ya məkan)." });
    }

    const payload = {
      user_id: req.authUser.id,
      query: (query || "").trim() || null,
      min_wage: Number(min_wage) || null,
      max_wage: Number(max_wage) || null,
      job_type: job_type || null,
      location_lat: location?.lat || null,
      location_lng: location?.lng || null,
      radius_m: Number(radius_m) || null,
      category: category ? String(category).trim() : null,
    };

    const { data, error } = await supabaseAdmin
      .from("job_alerts")
      .insert(payload)
      .select()
      .single();

    if (error) return res.status(400).json({ error: error.message });

    await logEvent("alert_create", req.authUser.id, { alert_id: data.id });

    // Notify nearby Employers if this alert has category + location
    if (data.category && data.location_lat && data.location_lng) {
      // Run in background
      notifyNearbyEmployers(data, req.authUser.user_metadata?.fullName || "İş axtaran").catch(console.error);
    }

    return res.json(data);
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

app.delete("/me/alerts/:id", requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = await supabaseAdmin
      .from("job_alerts")
      .delete()
      .eq("id", id)
      .eq("user_id", req.authUser.id);

    if (error) return res.status(400).json({ error: error.message });
    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

app.get("/jobs", optionalAuth, async (req, res) => {
  try {
    const createdBy = req.query.createdBy ? String(req.query.createdBy) : null;

    const q = req.query.q ? String(req.query.q) : "";
    const dailyRaw = req.query.daily;
    const daily = (dailyRaw === undefined || dailyRaw === null || dailyRaw === "") ? null : (String(dailyRaw) === "true");

    const profile = req.authUser ? await getProfile(req.authUser.id) : null;
    let baseLat = toNum(req.query.lat) ?? toNum(profile?.location?.lat);
    let baseLng = toNum(req.query.lng) ?? toNum(profile?.location?.lng);
    if (baseLat !== null && baseLng !== null && !isValidLatLng(baseLat, baseLng)) {
      baseLat = null;
      baseLng = null;
    }
    const radiusM = toNum(req.query.radius_m) ?? null;

    const jobTypeFilter = req.query.jobType ? String(req.query.jobType).trim() : null;

    await cleanupExpiredJobs();

    let query = supabaseAdmin
      .from("jobs")
      .select("*")
      .order("boosted_until", { ascending: false, nullsFirst: false }) // Boosted first
      .order("created_at", { ascending: false })
      .limit(200);

    if (createdBy) {
      if (!req.authUser) return res.status(401).json({ error: "Unauthorized" });
      if (createdBy !== req.authUser.id) return res.status(403).json({ error: "Forbidden" });
      query = query.eq("created_by", req.authUser.id);

    } else {
      query = query.eq("status", "open");

      if (jobTypeFilter === "seeker") {
        query = query.eq("job_type", "seeker");
      } else if (jobTypeFilter === "employer") {
        query = query.neq("job_type", "seeker");
      } else {
        // Default: Show employer jobs only (exclude seeker ads unless requested)
        query = query.neq("job_type", "seeker");
      }
    }

    if (daily !== null) query = query.eq("is_daily", daily);

    if (q) {
      const safe = q.replaceAll(",", " ").trim();
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
        lat: (typeof r.location_lat === "number" ? r.location_lat : toNum(r.location_lat)),
        lng: (typeof r.location_lng === "number" ? r.location_lng : toNum(r.location_lng)),
        address: r.location_address,
      };

      if (!isValidLatLng(loc.lat, loc.lng)) {
        loc.lat = null;
        loc.lng = null;
      }
      const job = {
        id: r.id,
        title: r.title,
        category: r.category,
        description: r.description,
        wage: r.wage,
        whatsapp: req.authUser ? (r.whatsapp ?? null) : null,
        phone: req.authUser ? (r.contact_phone ?? null) : null,
        link: req.authUser ? (r.contact_link ?? null) : null,
        voen: (r.voen ?? null),
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
        closedAt: (r.closed_at ?? null),
        closedReason: (r.closed_reason ?? null),
        boostedUntil: (r.boosted_until ?? null),
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


    if (!profile || profile?.role === "seeker") {
      items = items.filter((j) => String(j.status || "open").toLowerCase() !== "closed");
    }

    if (!req.authUser) {
      items = items.map((j) => ({
        ...j,
        whatsapp: null,
        phone: null,
        link: null,
      }));
    }

    return res.json(items);
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

app.get("/jobs/:id", optionalAuth, async (req, res) => {
  try {
    const id = String(req.params.id || "");
    if (!id) return res.status(400).json({ error: "id required" });

    await cleanupExpiredJobs();

    const { data, error } = await supabaseAdmin
      .from("jobs")
      .select("*")
      .eq("id", id)
      .maybeSingle();

    if (error) return res.status(400).json({ error: error.message });
    if (!data) return res.status(404).json({ error: "Not found" });

    const profile = (req.authUser && !req.authUser.is_admin) ? await getProfile(req.authUser.id) : null;
    const baseLat = toNum(profile?.location?.lat);
    const baseLng = toNum(profile?.location?.lng);

    const job = {
      id: data.id,
      title: data.title,
      category: data.category,
      description: data.description,
      wage: data.wage,
      whatsapp: (req.authUser || data.whatsapp) ? (data.whatsapp ?? null) : null, // Show if auth OR if field exists (logic tweak) - actually keeping original logic but ensuring admin gets it. 
      // Better:
      whatsapp: req.authUser ? (data.whatsapp ?? null) : null,
      phone: req.authUser ? (data.contact_phone ?? null) : null,
      link: req.authUser ? (data.contact_link ?? null) : null,
      voen: (data.voen ?? null),
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

    // Fetch creator profile
    if (data.created_by) {
      const { data: creator } = await supabaseAdmin
        .from("profiles")
        .select("email, full_name, phone, role")
        .eq("id", data.created_by)
        .single();

      if (creator) {
        job.creator = {
          email: creator.email,
          fullName: creator.full_name,
          phone: creator.phone,
          role: creator.role
        };
      }
    }

    if ((!profile || profile?.role === "seeker") && String(job.status || "open").toLowerCase() === "closed") {
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

app.post("/jobs", requireAuth, async (req, res) => {
  try {
    const profile = await getProfile(req.authUser.id);
    // Allow both employer and seeker
    if (!["employer", "seeker"].includes(profile?.role)) return res.status(403).json({ error: "Invalid role" });

    const {
      title,
      category,
      description,
      wage,
      whatsapp,
      phone,
      link,
      contactPhone,
      contactLink,
      voen,
      isDaily,
      jobType,
      durationDays,
      notifyRadiusM,
      location,
    } = req.body || {};

    if (!title) return res.status(400).json({ error: "Title required" });

    // Force jobType='seeker' if user is seeker
    const forcedType = profile.role === "seeker" ? "seeker" : jobType;
    const jt = normalizeJobType(forcedType, !!isDaily);
    let dDays = null;
    if (jt === "temporary") {
      dDays = toNum(durationDays);
      if (!dDays || dDays < 1 || dDays > 365) {
        return res.status(400).json({ error: "durationDays required (1-365) for temporary job" });
      }
    }

    const expiresAt = computeExpiresAt(jt, dDays || 1);

    let locLat = toNum(location?.lat);
    let locLng = toNum(location?.lng);
    let locAddr = location?.address ? String(location.address) : null;

    if ((locLat === null || locLng === null) && profile?.location) {
      const pLat = toNum(profile.location.lat);
      const pLng = toNum(profile.location.lng);
      if (pLat !== null && pLng !== null) {
        locLat = pLat;
        locLng = pLng;
        if (!locAddr && profile.location.address) locAddr = String(profile.location.address);
      }
    }

    if (locLat === null || locLng === null) {
      return res.status(400).json({ error: "Lokasiya seçilməlidir" });
    }
    if (!isValidLatLng(locLat, locLng)) {
      return res.status(400).json({ error: "Lokasiya koordinatları düzgün deyil" });
    }

    const { count: existingJobsCount } = await supabaseAdmin
      .from("jobs")
      .select("id", { count: "exact", head: true })
      .eq("created_by", req.authUser.id)
      .in("status", ["open", "closed"]);

    const initialStatus = (existingJobsCount || 0) > 0 ? "open" : "pending";

    const payload = {
      created_by: req.authUser.id,
      status: initialStatus,
      title,
      category: category || null,
      description: description || "",
      wage: wage || null,
      whatsapp: whatsapp || null,
      contact_phone: (contactPhone || phone) ? String(contactPhone || phone).trim() : null,
      contact_link: (contactLink || link) ? String(contactLink || link).trim() : null,
      voen: voen ? String(voen).trim() : null,
      is_daily: jt === "temporary",
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
      wage: data.wage, whatsapp: data.whatsapp,
      phone: data.contact_phone ?? null,
      link: data.contact_link ?? null,
      voen: data.voen ?? null,
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

    await logEvent("job_create", req.authUser.id, {
      job_id: job.id,
      title: job.title,
      job_type: job.jobType,
      duration_days: job.durationDays,
      wage: job.wage,
      category: job.category,
      description: job.description,
      address: job.location?.address,
      lat: job.location?.lat,
      lng: job.location?.lng,
      phone: job.phone || job.contactPhone,
      whatsapp: job.whatsapp,
      link: job.link
    });

    processJobAlerts(job).catch(console.error);
    notifyNearbySeekers(job).catch(console.error);




    return res.json(job);
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

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
      wage: updated.wage, whatsapp: updated.whatsapp,
      phone: updated.contact_phone ?? null,
      link: updated.contact_link ?? null,
      voen: updated.voen ?? null,
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


function getDistanceM(lat1, lon1, lat2, lon2) {
  if (!lat1 || !lon1 || !lat2 || !lon2) return 99999999;
  const R = 6371e3; // metres
  const φ1 = lat1 * Math.PI / 180;
  const φ2 = lat2 * Math.PI / 180;
  const Δφ = (lat2 - lat1) * Math.PI / 180;
  const Δλ = (lon2 - lon1) * Math.PI / 180;

  const a = Math.sin(Δφ / 2) * Math.sin(Δφ / 2) +
    Math.cos(φ1) * Math.cos(φ2) *
    Math.sin(Δλ / 2) * Math.sin(Δλ / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

  return R * c;
}

async function processJobAlerts(job) {
  try {
    const { data: alerts, error } = await supabaseAdmin.from("job_alerts").select("*");
    if (error || !alerts?.length) return;

    const queueItems = [];
    const jobLat = job.location_lat;
    const jobLng = job.location_lng;
    const jobTxt = (job.title + " " + (job.description || "")).toLowerCase();

    for (const alert of alerts) {
      if (alert.user_id === job.created_by) continue;

      if (alert.job_type && alert.job_type !== job.job_type) continue;

      if (alert.category && alert.category !== job.category) continue;


      if (alert.min_wage && (job.wage || 0) < alert.min_wage) continue;
      if (alert.max_wage && (job.wage || 0) > alert.max_wage) continue;

      if (alert.query) {
        if (!jobTxt.includes(alert.query.toLowerCase())) continue;
      }

      if (alert.location_lat && alert.location_lng && alert.radius_m) {
        const dist = getDistanceM(alert.location_lat, alert.location_lng, jobLat, jobLng);
        if (dist > alert.radius_m) continue;
      }

      queueItems.push({
        user_id: alert.user_id,
        title: "Yeni İş Elanı: " + job.title,
        body: `Axtarışınıza uyğun yeni elan: ${job.wage ? job.wage + " AZN" : "Maaş razılaşma ilə"}`,
        data: { type: "job", id: job.id },
        status: 'pending'
      });
    }

    if (queueItems.length > 0) {
      await supabaseAdmin.from("notification_queue").insert(queueItems);
    }
  } catch (e) {
  }
}

// --- SUPPORT SYSTEM ---

app.post("/support", requireAuth, async (req, res) => {
  try {
    const { subject, message, category } = req.body || {};
    if (!message) return res.status(400).json({ error: "Mesaj yazılmayıb" });

    // 1. Create Ticket
    const { data: ticket, error: tErr } = await supabaseAdmin.from("support_tickets").insert({
      user_id: req.authUser.id,
      subject: subject || category || "Dəstək",
      message: message, // Initial message check
      status: "open",
    }).select().single();

    if (tErr) return res.status(400).json({ error: tErr.message });

    // 2. Insert initial message to history
    await supabaseAdmin.from("support_messages").insert({
      ticket_id: ticket.id,
      sender_id: req.authUser.id,
      is_admin: false,
      message: message,
    });

    // Notify Telegram
    await logEvent("support_ticket", req.authUser.id, {
      subject: ticket.subject,
      email: req.authUser.email,
      category: category || "Dəstək",
      message: message
    });

    return res.json({ ok: true, ticket });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

app.get("/support", requireAuth, async (req, res) => {
  try {
    const { data, error } = await supabaseAdmin
      .from("support_tickets")
      .select("*, support_messages(*)")
      .eq("user_id", req.authUser.id)
      .order("created_at", { ascending: false });

    if (error) return res.status(400).json({ error: error.message });
    return res.json({ items: data });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

app.post("/support/:id/reply", requireAuth, async (req, res) => {
  try {
    const { message } = req.body || {};
    const { id } = req.params;
    if (!message) return res.status(400).json({ error: "Mesaj boşdur" });

    // Verify ownership
    const { data: ticket } = await supabaseAdmin.from("support_tickets").select("user_id").eq("id", id).single();
    if (!ticket || ticket.user_id !== req.authUser.id) {
      return res.status(404).json({ error: "Bilet tapılmadı" });
    }

    const { error } = await supabaseAdmin.from("support_messages").insert({
      ticket_id: id,
      sender_id: req.authUser.id,
      is_admin: false,
      message,
    });

    if (error) return res.status(400).json({ error: error.message });

    // Update status to open if it was closed or replied
    await supabaseAdmin.from("support_tickets").update({ status: "open", is_answered: false }).eq("id", id);

    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// Admin Support Routes

app.get("/admin/support", requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(100, Math.max(1, Number(req.query.limit || 50)));
    const offset = Math.max(0, Number(req.query.offset || 0));

    const { data, error } = await supabaseAdmin
      .from("support_tickets")
      .select("*, profiles(full_name, phone)")
      .order("created_at", { ascending: false })
      .range(offset, offset + limit - 1);

    if (error) return res.status(400).json({ error: error.message });
    return res.json({ items: data, limit, offset });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

app.get("/admin/support/:id", requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { data: ticket, error } = await supabaseAdmin
      .from("support_tickets")
      .select("*, profiles(full_name, phone), support_messages(*)")
      .eq("id", id)
      .single();

    if (error) return res.status(400).json({ error: error.message });

    // sort messages
    if (ticket.support_messages) {
      ticket.support_messages.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
    }

    return res.json(ticket);
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

app.post("/admin/support/:id/reply", requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { message, status } = req.body || {};
    if (!message) return res.status(400).json({ error: "Mesaj yazılmayıb" });

    // 1. Add message
    const { error } = await supabaseAdmin.from("support_messages").insert({
      ticket_id: id,
      sender_id: null, // Admin
      is_admin: true,
      message,
    });
    if (error) return res.status(400).json({ error: error.message });

    // 2. Update ticket
    await supabaseAdmin.from("support_tickets").update({
      status: status || "replied",
      is_answered: true
    }).eq("id", id);

    // 3. Notify User
    const { data: ticket } = await supabaseAdmin.from("support_tickets").select("user_id, subject").eq("id", id).single();
    if (ticket?.user_id) {
      const { data: userTokens } = await supabaseAdmin.from("push_tokens").select("expo_push_token").eq("user_id", ticket.user_id);

      const title = "Dəstək Mərkəzi";
      const body = `Sizin müraciətinizə cavab gəldi: "${message.slice(0, 50)}${message.length > 50 ? '...' : ''}"`;

      const msgs = [];
      const history = [];

      // Send to tokens
      if (userTokens) {
        for (const t of userTokens) {
          if (t.expo_push_token) {
            msgs.push({
              to: t.expo_push_token,
              title,
              body,
              data: { type: "support", ticketId: id },
              sound: "default"
            });
          }
        }
      }

      // Send Notification to inbox
      history.push({
        user_id: ticket.user_id,
        title,
        body,
        data: { type: "support", ticketId: id }
      });

      if (msgs.length) sendExpoPush(msgs).catch(() => { });
      if (history.length) insertNotifications(history).catch(() => { });
    }

    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});


app.listen(PORT, () => {
});


cron.schedule("0 8,19 * * *", () => {
});

app.post("/admin/trigger-notifications", async (req, res) => {
  const { secret } = req.body;
  if (secret !== ADMIN_JWT_SECRET) return res.status(403).json({ error: "Forbidden" });

  processNotificationQueue()
    .then(r => res.json(r))
    .catch(e => res.status(500).json({ error: e.message }));
});

async function notifyNearbySeekers(job) {
  try {
    const lat = toNum(job.location_lat ?? job.location?.lat);
    const lng = toNum(job.location_lng ?? job.location?.lng);

    if (lat === null || lng === null) return;

    // Use job radius if provided, otherwise default to 5000m (5km)
    // User mentioned "2000" (likely meters) so 500m default was too small.
    const radiusM = toNum(job.notifyRadiusM ?? job.notify_radius_m) || 5000;

    // 1. Fetch seekers with location
    // Filter by role='seeker' to avoid spamming employers
    // Optimisation: We fetch minimal fields
    const { data: seekers, error } = await supabaseAdmin
      .from("profiles")
      .select("id, location, expo_push_token")
      .eq("role", "seeker")
      .not("location", "is", null);

    if (error || !seekers) return;

    const validSeekers = seekers.filter(s => {
      const slat = toNum(s.location?.lat);
      const slng = toNum(s.location?.lng);
      if (slat === null || slng === null) return false;

      const dist = haversineDistanceM(lat, lng, slat, slng);
      return dist <= radiusM;
    });

    if (validSeekers.length === 0) return;

    // 2. Prepare notifications
    const title = "Yaxınlıqda yeni iş!";
    const body = `${job.title} (${job.wage ? job.wage + " AZN" : "Razılaşma"})`;

    const notifications = [];
    const pushMessages = [];

    // 3. Get extra tokens from push_tokens table
    const userIds = validSeekers.map(s => s.id);
    const { data: extraTokens } = await supabaseAdmin
      .from("push_tokens")
      .select("user_id, expo_push_token")
      .in("user_id", userIds);

    const tokenMap = new Map();
    // Add tokens from profiles
    validSeekers.forEach(s => {
      if (s.expo_push_token) {
        if (!tokenMap.has(s.id)) tokenMap.set(s.id, new Set());
        tokenMap.get(s.id).add(s.expo_push_token);
      }
    });
    // Add extra tokens
    if (extraTokens) {
      extraTokens.forEach(t => {
        if (t.expo_push_token) {
          if (!tokenMap.has(t.user_id)) tokenMap.set(t.user_id, new Set());
          tokenMap.get(t.user_id).add(t.expo_push_token);
        }
      });
    }

    // 4. Send
    for (const [userId, tokens] of tokenMap) {
      if (userId === job.createdBy) continue; // Don't notify self

      const dataPayload = { type: "job", jobId: job.id };

      // DB Notification
      notifications.push({
        user_id: userId,
        title,
        body,
        data: dataPayload,
        read_at: null
      });

      // Push Notifications
      for (const token of tokens) {
        if (String(token).startsWith("ExponentPushToken")) {
          pushMessages.push({
            to: token,
            title,
            body,
            data: dataPayload,
            sound: "default"
          });
        }
      }
    }

    if (notifications.length > 0) {
      await supabaseAdmin.from("notifications").insert(notifications);
    }

    if (pushMessages.length > 0) {
      await sendExpoPush(pushMessages);
    }

    console.log(`Sent nearby notifications to ${pushMessages.length} devices for job ${job.id}`);

  } catch (e) {
    console.error("notifyNearbySeekers error:", e);
  }
}

async function processNotificationQueue() {
  const BATCH_SIZE = 500; // Process 500 at a time to avoid memory issues

  const { data: queue, error } = await supabaseAdmin
    .from("notification_queue")
    .select("*")
    .eq("status", "pending")
    .limit(BATCH_SIZE);

  if (error) {
    return { error: error.message };
  }
  if (!queue || queue.length === 0) {
    return { processed: 0 };
  }

  const userIds = [...new Set(queue.map(q => q.user_id))];
  const { data: tokens } = await supabaseAdmin
    .from("push_tokens")
    .select("user_id, expo_push_token")
    .in("user_id", userIds);

  const { data: profiles } = await supabaseAdmin
    .from("profiles")
    .select("id, expo_push_token")
    .in("id", userIds);

  const tokenMap = new Map();
  tokens?.forEach(t => tokenMap.set(t.user_id, t.expo_push_token));
  profiles?.forEach(p => {
    if (!tokenMap.has(p.id) && p.expo_push_token) {
      tokenMap.set(p.id, p.expo_push_token);
    }
  });

  const messages = [];
  const historyRows = [];
  const processedIds = [];

  for (const item of queue) {
    const token = tokenMap.get(item.user_id);

    historyRows.push({
      user_id: item.user_id,
      title: item.title,
      body: item.body,
      data: item.data,
      created_at: new Date().toISOString() // Show as "new" now
    });

    if (token) {
      messages.push({
        to: token,
        sound: "default",
        title: item.title,
        body: item.body,
        data: item.data,
        channelId: "default",
        priority: "high",
      });
    }
    processedIds.push(item.id);
  }

  if (historyRows.length > 0) {
    await insertNotifications(historyRows);
  }

  let sentCount = 0;
  if (messages.length > 0) {
    const res = await sendExpoPush(messages);
    sentCount = res.sent || 0;
  }

  if (processedIds.length > 0) {
    await supabaseAdmin
      .from("notification_queue")
      .update({ status: "sent" })
      .in("id", processedIds);
  }

  return { processed: processedIds.length, sent: sentCount };
}


app.get("/content/:slug", async (req, res) => {
  try {
    const { slug } = req.params;
    const { data, error } = await supabaseAdmin
      .from("content_pages")
      .select("*")
      .eq("slug", slug)
      .maybeSingle(); // Don't error if missing, just return null or 404

    if (!data) return res.status(404).json({ error: "Page not found" });
    return res.json(data);
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

app.put("/admin/content/:slug", async (req, res) => {
  try {
    const authHeader = req.headers.authorization || "";



    const token = authHeader.replace("Bearer ", "");
    if (!token) return res.status(401).json({ error: "No token" });

    const [headerB64, payloadB64, sigB64] = token.split(".");
    if (!headerB64 || !payloadB64 || !sigB64) return res.status(401).json({ error: "Invalid token" });

    const data = `${headerB64}.${payloadB64}`;
    const expectedSig = crypto.createHmac("sha256", ADMIN_JWT_SECRET).update(data).digest("base64url");
    if (sigB64 !== expectedSig) return res.status(403).json({ error: "Invalid signature" });

    const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString());
    if (payload.exp < Date.now() / 1000) return res.status(403).json({ error: "Token expired" });

    const { slug } = req.params;
    const { title, body } = req.body;

    const { data: updated, error } = await supabaseAdmin
      .from("content_pages")
      .upsert({ slug, title, body, updated_at: new Date().toISOString() })
      .select()
      .single();

    if (error) return res.status(400).json({ error: error.message });
    return res.json(updated);
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});