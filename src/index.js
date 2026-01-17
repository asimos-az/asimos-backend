import "dotenv/config";
import express from "express";
import cors from "cors";
import { createClient } from "@supabase/supabase-js";

const app = express();
app.use(cors());
app.use(express.json());

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

// Register (uses admin API to create user, auto-confirm)

app.get("/health", (req, res) => res.json({ ok: true }));

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
    const { email, code, password } = req.body || {};
    if (!email || !code) return res.status(400).json({ error: "Missing fields" });
    if (!password) return res.status(400).json({ error: "Password required" });

    const cleanCode = String(code).replace(/\s+/g, "").trim();
    if (!/^\d{6}$/.test(cleanCode)) {
      return res.status(400).json({ error: "OTP kod 6 rəqəmli olmalıdır" });
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
    const role = md.role;
    const fullName = md.fullName || "";
    const companyName = md.companyName || null;
    const phone = md.phone || null;
    const location = md.location || null;

    const { error: profErr } = await supabaseAdmin.from("profiles").upsert({
      id: userId,
      role,
      full_name: fullName,
      company_name: companyName,
      phone,
      location,
    });

    if (profErr) return res.status(400).json({ error: profErr.message });

    // Set password after OTP verification so user can login with email+password
    try {
      const { error: updErr } = await supabaseAdmin.auth.admin.updateUserById(userId, { password });
      if (updErr) return res.status(400).json({ error: updErr.message });
    } catch (e) {
      return res.status(500).json({ error: e.message || "Password set failed" });
    }

    const profile = await getProfile(userId);

    return res.json({
      token: data.session.access_token,
      refreshToken: data.session.refresh_token,
      user: profileToUser(profile, data.user),
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
    return res.json({ ok: true, user: profileToUser(profile, req.authUser) });
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

    let items = (data || []).map((r) => {
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
        notifyRadiusM: r.notify_radius_m,
        createdAt: r.created_at,
        createdBy: r.created_by,
        location: loc,
      };

      if (baseLat !== null && baseLng !== null && typeof loc.lat === "number" && typeof loc.lng === "number") {
        job.distanceM = Math.round(haversineDistanceM(baseLat, baseLng, loc.lat, loc.lng));
      }
      return job;
    });

    if (radiusM !== null) {
      items = items.filter((j) => typeof j.distanceM !== "number" || j.distanceM <= radiusM);
    }

    // Sort closest first if distance exists
    if (baseLat !== null && baseLng !== null) {
      items.sort((a, b) => (a.distanceM ?? 1e18) - (b.distanceM ?? 1e18));
    }

    return res.json(items);
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
      notifyRadiusM,
      location,
    } = req.body || {};

    if (!title) return res.status(400).json({ error: "Title required" });

    const locLat = toNum(location?.lat);
    const locLng = toNum(location?.lng);
    const locAddr = location?.address ? String(location.address) : null;

    const { data, error } = await supabaseAdmin
      .from("jobs")
      .insert({
        created_by: req.authUser.id,
        title,
        category: category || null,
        description: description || "",
        wage: wage || null,
        whatsapp: whatsapp || null,
        is_daily: !!isDaily,
        notify_radius_m: toNum(notifyRadiusM),
        location_lat: locLat,
        location_lng: locLng,
        location_address: locAddr,
      })
      .select("*")
      .single();

    if (error) return res.status(400).json({ error: error.message });

    const job = {
      id: data.id,
      title: data.title,
      category: data.category,
      description: data.description,
      wage: data.wage,
      whatsapp: data.whatsapp,
      isDaily: data.is_daily,
      notifyRadiusM: data.notify_radius_m,
      createdAt: data.created_at,
      createdBy: data.created_by,
      location: { lat: data.location_lat, lng: data.location_lng, address: data.location_address },
    };

    return res.json(job);
  } catch (e) {
    return res.status(500).json({ error: e.message || "Server error" });
  }
});

app.listen(PORT, () => {
  console.log(`Asimos backend running on :${PORT}`);
});
