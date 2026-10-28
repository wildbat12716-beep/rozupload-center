require("dotenv").config();

const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const helmet = require("helmet");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, "data");
const STORAGE_DIR = path.join(ROOT, "storage");
const DB_FILE = path.join(DATA_DIR, "database.json");
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(STORAGE_DIR, { recursive: true });

const QUOTA_BYTES = Number(process.env.QUOTA_BYTES || 10 * 1024 ** 3);
const MAX_FILE_BYTES = Number(process.env.MAX_FILE_BYTES || 1024 ** 3);
const SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.error("Set SESSION_SECRET in .env to a random string of at least 32 characters.");
  process.exit(1);
}

function loadDb() {
  try {
    const parsed = JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
    return { nextUserId: parsed.nextUserId || 1, users: parsed.users || [], files: parsed.files || [] };
  } catch (err) {
    if (err.code !== "ENOENT") console.error("Could not read database.json; starting with an empty database.", err);
    return { nextUserId: 1, users: [], files: [] };
  }
}
let db = loadDb();
function saveDb() {
  const temp = DB_FILE + ".tmp";
  fs.writeFileSync(temp, JSON.stringify(db, null, 2), "utf8");
  fs.renameSync(temp, DB_FILE);
}

app.disable("x-powered-by");
app.use(helmet({
  contentSecurityPolicy: { directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "https://cdn.tailwindcss.com"],
    styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdn.tailwindcss.com"],
    fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
    imgSrc: ["'self'", "data:", "blob:"], connectSrc: ["'self'"], objectSrc: ["'none'"], frameAncestors: ["'none'"]
  }}
}));
app.use(express.json({ limit: "20kb" }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: "rozu.sid",
  cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 1000 * 60 * 60 * 24 * 7 }
}));
app.use(express.static(path.join(ROOT, "public")));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false });
const uploadLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 100, standardHeaders: true, legacyHeaders: false });
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "ابتدا وارد حساب کاربری شو." });
  next();
}
function safeName(name) {
  const cleaned = path.basename(String(name || "file")).replace(/[^\p{L}\p{N}._() -]/gu, "_").slice(0, 180);
  return cleaned || "file";
}
function userById(id) { return db.users.find(u => u.id === Number(id)); }
function fileById(id) { return db.files.find(f => f.id === id); }
function usedBytes(userId) { return db.files.filter(f => f.user_id === Number(userId)).reduce((sum, f) => sum + f.size_bytes, 0); }
function publicFile(row) {
  const base = process.env.BASE_URL || `http://localhost:${PORT}`;
  return { id: row.id, name: row.original_name, type: row.mime_type, size: row.size_bytes, createdAt: row.created_at,
    directUrl: `${base}/d/${row.id}`, shareUrl: `${base}/share/${row.id}` };
}

const diskStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, STORAGE_DIR),
  filename: (_req, _file, cb) => cb(null, crypto.randomUUID())
});
const upload = multer({ storage: diskStorage, limits: { fileSize: MAX_FILE_BYTES, files: 10 },
  fileFilter: (_req, file, cb) => {
    if (!file.originalname || file.originalname.length > 240) return cb(new Error("نام فایل معتبر نیست."));
    cb(null, true);
  }
});

app.get("/api/me", (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  const user = userById(req.session.userId);
  if (!user) return req.session.destroy(() => res.json({ user: null }));
  res.json({ user: { id: user.id, email: user.email, createdAt: user.created_at }, used: usedBytes(user.id), quota: QUOTA_BYTES });
});

app.post("/api/register", authLimiter, async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) return res.status(400).json({ error: "ایمیل معتبر وارد کن." });
  if (password.length < 10 || password.length > 200) return res.status(400).json({ error: "رمز عبور باید حداقل ۱۰ کاراکتر باشد." });
  if (db.users.some(u => u.email === email)) return res.status(409).json({ error: "این ایمیل قبلاً ثبت شده است." });
  const user = { id: db.nextUserId++, email, password_hash: await bcrypt.hash(password, 12), created_at: new Date().toISOString() };
  db.users.push(user);
  try { saveDb(); } catch (err) { db.users = db.users.filter(u => u.id !== user.id); db.nextUserId--; return res.status(500).json({ error: "ذخیره حساب ناموفق بود." }); }
  req.session.userId = user.id;
  res.json({ ok: true });
});

app.post("/api/login", authLimiter, async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const user = db.users.find(u => u.email === email);
  if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: "ایمیل یا رمز عبور اشتباه است." });
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "خطای ورود." });
    req.session.userId = user.id;
    res.json({ ok: true });
  });
});
app.post("/api/logout", (req, res) => req.session.destroy(() => { res.clearCookie("rozu.sid"); res.json({ ok: true }); }));

app.get("/api/files", requireAuth, (req, res) => {
  const rows = db.files.filter(f => f.user_id === Number(req.session.userId)).sort((a, b) => b.created_at.localeCompare(a.created_at));
  res.json({ files: rows.map(publicFile), used: usedBytes(req.session.userId), quota: QUOTA_BYTES });
});
app.post("/api/upload", requireAuth, uploadLimiter, (req, res, next) => {
  upload.array("files", 10)(req, res, err => {
    if (err) return res.status(400).json({ error: err.code === "LIMIT_FILE_SIZE" ? "حجم یکی از فایل‌ها بیش از حد مجاز است." : (err.message || "آپلود ناموفق بود.") });
    next();
  });
}, (req, res, next) => {
  const files = req.files || [];
  if (!files.length) return res.status(400).json({ error: "فایلی انتخاب نشده است." });
  const current = usedBytes(req.session.userId);
  const incoming = files.reduce((n, f) => n + f.size, 0);
  if (current + incoming > QUOTA_BYTES) {
    for (const f of files) fs.promises.unlink(f.path).catch(() => {});
    return res.status(413).json({ error: "فضای حساب کافی نیست. فایل‌های قبلی را حذف کن یا سهمیه را افزایش بده." });
  }
  const created = new Date().toISOString();
  const rows = files.map(f => ({ id: crypto.randomBytes(18).toString("hex"), user_id: Number(req.session.userId), original_name: safeName(f.originalname), stored_name: path.basename(f.filename), mime_type: f.mimetype || "application/octet-stream", size_bytes: f.size, created_at: created }));
  db.files.push(...rows);
  try { saveDb(); res.json({ files: rows.map(publicFile), used: usedBytes(req.session.userId), quota: QUOTA_BYTES }); }
  catch (err) { db.files = db.files.filter(f => !rows.some(r => r.id === f.id)); for (const f of files) fs.promises.unlink(f.path).catch(() => {}); next(err); }
});
app.delete("/api/files/:id", requireAuth, (req, res) => {
  const row = db.files.find(f => f.id === req.params.id && f.user_id === Number(req.session.userId));
  if (!row) return res.status(404).json({ error: "فایل پیدا نشد." });
  db.files = db.files.filter(f => f.id !== row.id);
  try { saveDb(); } catch (err) { db.files.push(row); return res.status(500).json({ error: "حذف فایل ناموفق بود." }); }
  fs.promises.unlink(path.join(STORAGE_DIR, path.basename(row.stored_name))).catch(() => {});
  res.json({ ok: true, used: usedBytes(req.session.userId) });
});
app.get("/d/:id", (req, res) => {
  const row = fileById(req.params.id);
  if (!row) return res.status(404).send("فایل پیدا نشد.");
  const diskPath = path.join(STORAGE_DIR, path.basename(row.stored_name));
  if (!fs.existsSync(diskPath)) return res.status(404).send("فایل در فضای ذخیره‌سازی موجود نیست.");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Content-Type", "application/octet-stream");
  res.download(diskPath, row.original_name);
});
app.get("/share/:id", (req, res) => {
  const row = fileById(req.params.id);
  if (!row) return res.status(404).send("فایل پیدا نشد.");
  const base = process.env.BASE_URL || `http://localhost:${PORT}`;
  res.type("html").send(`<!doctype html><html lang="fa" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>دانلود فایل</title><body style="font-family:Tahoma,Arial;max-width:680px;margin:60px auto;padding:20px;background:#f8fafc;color:#0f172a"><h1>فایل آماده دانلود است</h1><p>${escapeHtml(row.original_name)}</p><p>${formatBytes(row.size_bytes)}</p><a style="display:inline-block;padding:12px 20px;background:#2563eb;color:white;border-radius:10px;text-decoration:none" href="${base}/d/${row.id}">دانلود فایل</a></body></html>`);
});
function escapeHtml(s) { return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function formatBytes(n) { if (!n) return "0 بایت"; const units=["بایت","کیلوبایت","مگابایت","گیگابایت"]; const i=Math.min(Math.floor(Math.log(n)/Math.log(1024)),3); return `${(n/1024**i).toFixed(i?1:0)} ${units[i]}`; }
app.post("/api/url-upload", requireAuth, (_req, res) => res.status(403).json({ error: "آپلود از لینک فعلاً غیرفعال است." }));
app.use((err, _req, res, _next) => { console.error(err); res.status(500).json({ error: "خطای داخلی سرور." }); });
app.listen(PORT, () => console.log(`RozUpload Center: http://localhost:${PORT}`));
