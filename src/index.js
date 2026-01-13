import express from "express";
import cors from "cors";

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 4000;

/**
 * role:
 *  - seeker: İş axtaran (Alıcı)
 *  - employer: İşçi axtaran (Satıcı)
 */
const users = [
  {
    id: "u_emp_1",
    role: "employer",
    fullName: "Demo Employer",
    companyName: "Asimos LLC",
    email: "employer@test.com",
    password: "Password123!",
    phone: "+994501234567",
    location: { lat: 40.4093, lng: 49.8671, address: "Bakı, Azərbaycan" }
  },
  {
    id: "u_seek_1",
    role: "seeker",
    fullName: "Demo Seeker",
    email: "seeker@test.com",
    password: "Password123!",
    phone: "+994551112233"
  }
];

let jobs = [
  {
    id: "job_1",
    title: "Ofisiant",
    category: "Restoran",
    description: "Restorana ofisiant axtarılır. Təcrübə arzuolunandır.",
    wage: "800 AZN",
    whatsapp: "+994551234567",
    isDaily: false,
    notifyRadiusM: 1200,
    createdAt: new Date().toISOString(),
    createdBy: "u_emp_1",
    location: { lat: 40.4093, lng: 49.8671, address: "Bakı, Azərbaycan" }
  },
  {
    id: "job_2",
    title: "Gündəlik yükdaşıma",
    category: "Gündəlik iş",
    description: "Gündəlik yükdaşıma işinə adam lazımdır. Səhər 10:00-da başlayır.",
    wage: "50 AZN / gün",
    whatsapp: "+994501234567",
    isDaily: true,
    notifyRadiusM: 2000,
    createdAt: new Date().toISOString(),
    createdBy: "u_emp_1",
    location: { lat: 40.4040, lng: 49.8570, address: "Nizami rayonu, Bakı" }
  }
];

function makeToken(userId) {
  return `mock-${userId}-${Date.now()}`;
}

function sanitizeUser(u) {
  const { password, ...rest } = u;
  return rest;
}

function toNum(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function haversineDistanceM(lat1, lon1, lat2, lon2) {
  const R = 6371000; // meters
  const toRad = (d) => (d * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

app.get("/", (_, res) => res.json({ ok: true, name: "Asimos API", version: "0.2.0" }));

// --- Auth ---
app.post("/auth/register", (req, res) => {
  const { role, fullName, companyName, email, password, phone, location } = req.body || {};
  if (!role || !fullName || !email || !password || !phone) {
    return res.status(400).json({ message: "Missing required fields." });
  }
  if (role === "employer" && (!companyName || !location)) {
    return res.status(400).json({ message: "Employer requires companyName and location." });
  }
  const exists = users.find(u => u.email.toLowerCase() === String(email).toLowerCase());
  if (exists) return res.status(409).json({ message: "Email already registered." });

  const newUser = {
    id: `u_${Math.random().toString(16).slice(2)}`,
    role,
    fullName,
    companyName: role === "employer" ? companyName : undefined,
    email,
    password,
    phone,
    location: role === "employer" ? location : undefined
  };
  users.push(newUser);
  res.json({ token: makeToken(newUser.id), user: sanitizeUser(newUser) });
});

app.post("/auth/login", (req, res) => {
  const { email, password } = req.body || {};
  const user = users.find(u => u.email.toLowerCase() === String(email).toLowerCase());
  if (!user || user.password !== password) {
    return res.status(401).json({ message: "Email və ya şifrə yanlışdır." });
  }
  res.json({ token: makeToken(user.id), user: sanitizeUser(user) });
});

// --- Jobs ---
// Query params:
//  - createdBy: employer id
//  - q: search keyword (title/description/category)
//  - lat,lng: seeker location
//  - radius_m: distance filter in meters
//  - daily: "true" / "false"
//  - category: exact match (case-insensitive)
app.get("/jobs", (req, res) => {
  const { createdBy, q, lat, lng, radius_m, daily, category } = req.query || {};

  const latN = toNum(lat);
  const lngN = toNum(lng);
  const radiusN = toNum(radius_m);

  const hasGeo = latN !== null && lngN !== null && radiusN !== null;

  let list = jobs.slice();

  if (createdBy) list = list.filter(j => j.createdBy === createdBy);

  if (typeof daily !== "undefined") {
    if (String(daily).toLowerCase() === "true") list = list.filter(j => !!j.isDaily);
    if (String(daily).toLowerCase() === "false") list = list.filter(j => !j.isDaily);
  }

  if (category) {
    const c = String(category).toLowerCase().trim();
    list = list.filter(j => String(j.category || "").toLowerCase().trim() === c);
  }

  if (q) {
    const needle = String(q).toLowerCase().trim();
    list = list.filter(j => {
      const t = String(j.title || "").toLowerCase();
      const d = String(j.description || "").toLowerCase();
      const c = String(j.category || "").toLowerCase();
      return t.includes(needle) || d.includes(needle) || c.includes(needle);
    });
  }

  if (hasGeo) {
    list = list
      .map(j => {
        if (!j.location?.lat || !j.location?.lng) return { ...j, distanceM: null };
        const dist = haversineDistanceM(latN, lngN, Number(j.location.lat), Number(j.location.lng));
        return { ...j, distanceM: Math.round(dist) };
      })
      .filter(j => j.distanceM !== null && j.distanceM <= radiusN);
  } else if (latN !== null && lngN !== null) {
    list = list.map(j => {
      if (!j.location?.lat || !j.location?.lng) return { ...j, distanceM: null };
      const dist = haversineDistanceM(latN, lngN, Number(j.location.lat), Number(j.location.lng));
      return { ...j, distanceM: Math.round(dist) };
    });
  }

  list.sort((a,b)=> (b.createdAt||"").localeCompare(a.createdAt||""));
  res.json(list);
});

app.post("/jobs", (req, res) => {
  const {
    title,
    description,
    wage,
    category,
    whatsapp,
    isDaily,
    notifyRadiusM,
    createdBy,
    location
  } = req.body || {};

  if (!title || !description || !createdBy) {
    return res.status(400).json({ message: "Missing required fields." });
  }

  const creator = users.find(u => u.id === createdBy);
  if (!creator || creator.role !== "employer") {
    return res.status(403).json({ message: "Only employer can create jobs." });
  }

  const job = {
    id: `job_${Math.random().toString(16).slice(2)}`,
    title,
    category: category || "",
    description,
    wage: wage || "",
    whatsapp: whatsapp || "",
    isDaily: !!isDaily,
    notifyRadiusM: Number.isFinite(Number(notifyRadiusM)) ? Number(notifyRadiusM) : null,
    createdAt: new Date().toISOString(),
    createdBy,
    location: location || creator.location || null
  };
  jobs.unshift(job);
  res.json(job);
});

app.listen(PORT, () => {
  console.log(`Asimos API running on http://localhost:${PORT}`);
  console.log("Seed users:");
  console.log("  Employer (Satıcı): employer@test.com / Password123!");
  console.log("  Seeker (Alıcı):   seeker@test.com / Password123!");
});
