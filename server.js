// server.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const { z } = require("zod");

const app = express();
const PORT = process.env.PORT || 8080;
const ORIGIN = process.env.ORIGIN || "*";
const ADMIN_PHONE = process.env.ADMIN_PHONE || "22234605765";
const SESSION_TTL_MS = Number(process.env.SESSION_TTL_MS || 1000 * 60 * 60 * 24 * 7);
const DB_PATH = process.env.DB_PATH || "./echtiraki.db";

// أمان أساسي
app.use(helmet());
app.use(cors({ origin: ORIGIN, credentials: true }));
app.use(express.json({ limit: "200kb" }));
app.use(rateLimit({ windowMs: 60_000, max: 120 })); // 120 طلب/دقيقة

// قاعدة بيانات SQLite (ملف على القرص)
const db = new Database(DB_PATH);
db.pragma("foreign_keys = ON");
// إنشاء الجداول عند أول تشغيل
db.exec(`
  PRAGMA journal_mode = WAL;

  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    full_name TEXT NOT NULL,
    phone TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS products (
    id TEXT PRIMARY KEY,
    name_ar TEXT NOT NULL,
    cat TEXT NOT NULL,
    duration TEXT,
    price INTEGER NOT NULL,
    img TEXT,
    keywords TEXT
  );

  CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY,
    product_id TEXT NOT NULL,
    product_name TEXT NOT NULL,
    duration TEXT,
    price INTEGER NOT NULL,
    full_name TEXT NOT NULL,
    phone TEXT NOT NULL,
    email TEXT,
    notes TEXT,
    status TEXT NOT NULL DEFAULT 'pending', -- pending | paid | delivered | canceled
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    user_id TEXT,
    FOREIGN KEY (product_id) REFERENCES products(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

const orderColumns = db.prepare("PRAGMA table_info(orders)").all();
if (!orderColumns.some((col) => col.name === "user_id")) {
  db.exec("ALTER TABLE orders ADD COLUMN user_id TEXT");
}

// إدخال منتجات (مرة واحدة) لو الجدول فاضي
const count = db.prepare("SELECT COUNT(*) as c FROM products").get().c;
if (count === 0) {
  const seed = db.prepare(`
    INSERT INTO products (id, name_ar, cat, duration, price, img, keywords)
    VALUES (@id, @name_ar, @cat, @duration, @price, @img, @keywords)
  `);

  const products = [
    { id:"_uhd", name_ar:"Netflix 4K (حساب مشترك )", cat:"الترفيه", duration:"1 mois", price:270, img:"/ntflx.jpg", keywords:"نتفلكس Netflix UHD 4K" },
    { id:"netflix_uhd", name_ar:"Netflix 4K (حساب مشترك )", cat:"الترفيه", duration:"3 mois", price:500, img:"/ntflx.jpg", keywords:"نتفلكس Netflix UHD 4K" },

    { id:"chatgpt_plus_1", name_ar:"chat-gpt plus(حساب مشترك )", cat:"الذكاء الاصطناعي", duration:"1 mois", price:280, img:"/gpt.jpg", keywords:"شات جي بي تي chat-gpt gpt" },
    { id:"chatgpt_plus_3", name_ar:"chat-gpt plus (حساب مشترك )", cat:"الذكاء الاصطناعي", duration:"3 mois", price:800, img:"/gpt.jpg", keywords:"شات جي بي تي chat-gpt gpt" },
    { id:"chatgpt_plus_private", name_ar:"chat-gpt plus (حساب خاص )", cat:"الذكاء الاصطناعي", duration:"1 mois", price:880, img:"/gpt.jpg", keywords:"شات جي بي تي chat-gpt gpt" },

    { id:"snap_plus_3", name_ar:"snap chat- plus", cat:"الترفيه", duration:"3 mois", price:270, img:"/snapchat.jpg", keywords:"سناب شات snap plus" },
    { id:"snap_plus_6", name_ar:"snap chat- plus", cat:"الترفيه", duration:"6 mois", price:500, img:"/snapchat.jpg", keywords:"سناب شات snap plus" },

    { id:"canva_pro", name_ar:"canva pro (حساب خاص )", cat:"الترويج", duration:"infinie-مدى الحياة", price:200, img:"/canva.jpg", keywords:"كانفا canva pro" },
    { id:"capcut_pro", name_ar:" capcut pro (حساب خاص )", cat:"الترويج", duration:"1 mois", price:800, img:"/capcut.jpg", keywords:"كابكات capcut pro" },
    { id:"meta_verified", name_ar:"meta verified-توثيق صفحة فيسبوك ", cat:"الترويج", duration:"1 mois", price:800, img:"/meta.jpg", keywords:"فيسبوك توثيق meta" },
    { id:"adobe_suite", name_ar:"adobe برامج فوتوشوب ", cat:"الترويج", duration:"infinie-مدى الحياة", price:1000, img:"/adobe.jpg", keywords:"adobe photoshop illustrator" },
  ];

  const insert = db.transaction((items) => {
    for (const p of items) seed.run(p);
  });
  insert(products);
  console.log("Seeded products ✅");
}

// مخططات التحقق
const CreateOrderSchema = z.object({
  productId: z.string().min(1),
  fullName: z.string().min(2).or(z.literal("")).optional(),
  phone: z.string().min(6).or(z.literal("")).optional(),
  email: z.string().email().optional().or(z.literal("")),
  notes: z.string().max(1000).optional().or(z.literal("")),
});

// مساعد: مُعرّف طلب عشوائي قصير
const RegisterSchema = z.object({
  fullName: z.string().min(2).max(120),
  phone: z.string().min(6).max(30),
  password: z.string().min(6).max(128),
});

const LoginSchema = z.object({
  phone: z.string().min(6).max(30),
  password: z.string().min(6).max(128),
});

function normalizePhone(value = "") {
  if (!value) return "";
  const trimmed = String(value).trim();
  if (!trimmed) return "";

  const withoutSpaces = trimmed.replace(/\s+/g, "");
  const hasPlus = withoutSpaces.startsWith("+");
  const digits = withoutSpaces.replace(/[^\d]/g, "");
  if (!digits) return "";
  return hasPlus ? `+${digits}` : digits;
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return { salt, hash };
}

function verifyPassword(password, salt, storedHash) {
  try {
    const hashBuffer = crypto.scryptSync(password, salt, 64);
    const storedBuffer = Buffer.from(storedHash, "hex");
    if (hashBuffer.length !== storedBuffer.length) return false;
    return crypto.timingSafeEqual(hashBuffer, storedBuffer);
  } catch (err) {
    return false;
  }
}

function createSession(userId) {
  const token = crypto.randomBytes(48).toString("hex");
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();

  db.prepare(`
    INSERT INTO sessions (id, user_id, expires_at)
    VALUES (@id, @user_id, @expires_at)
  `).run({ id: token, user_id: userId, expires_at: expiresAt });

  return { token, expiresAt };
}

function deleteSession(token) {
  db.prepare("DELETE FROM sessions WHERE id = ?").run(token);
}

function getSession(token) {
  if (!token) return null;
  const session = db.prepare("SELECT * FROM sessions WHERE id = ?").get(token);
  if (!session) return null;

  if (Date.parse(session.expires_at) <= Date.now()) {
    deleteSession(token);
    return null;
  }

  return session;
}

function loadUser(userId) {
  return db.prepare("SELECT id, full_name, phone, created_at FROM users WHERE id = ?").get(userId);
}

function loadUserByPhone(phone) {
  return db.prepare("SELECT id, full_name, phone, password_hash, password_salt, created_at FROM users WHERE phone = ?").get(phone);
}

function toPublicUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    fullName: row.full_name,
    phone: row.phone,
    createdAt: row.created_at,
  };
}

function extractToken(req) {
  const authHeader = req.get("authorization");
  if (authHeader && authHeader.toLowerCase().startsWith("bearer ")) {
    return authHeader.slice(7).trim();
  }

  const headerToken = req.get("x-session-token");
  return headerToken ? headerToken.trim() : null;
}

function authenticateRequest(req) {
  const token = extractToken(req);
  if (!token) return null;

  const session = getSession(token);
  if (!session) return null;

  const userRow = loadUser(session.user_id);
  if (!userRow) {
    deleteSession(token);
    return null;
  }

  return { token, session, user: toPublicUser(userRow) };
}

function requireAuth(req, res, next) {
  const auth = authenticateRequest(req);
  if (!auth) return res.status(401).json({ error: "UNAUTHORIZED" });
  req.auth = auth;
  next();
}

app.post("/api/auth/register", (req, res) => {
  const parsed = RegisterSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "INVALID_INPUT", details: parsed.error.errors });
  }

  const fullName = parsed.data.fullName.trim();
  const phone = normalizePhone(parsed.data.phone);
  const password = parsed.data.password;

  if (!phone) {
    return res.status(400).json({ error: "INVALID_PHONE" });
  }

  const existing = db.prepare("SELECT id FROM users WHERE phone = ?").get(phone);
  if (existing) {
    return res.status(409).json({ error: "USER_EXISTS" });
  }

  const { hash, salt } = hashPassword(password);
  const userId = newId("usr");

  db.prepare(`
    INSERT INTO users (id, full_name, phone, password_hash, password_salt)
    VALUES (@id, @full_name, @phone, @password_hash, @password_salt)
  `).run({
    id: userId,
    full_name: fullName,
    phone,
    password_hash: hash,
    password_salt: salt,
  });

  const session = createSession(userId);
  const userRow = loadUser(userId);

  res.status(201).json({
    token: session.token,
    expiresAt: session.expiresAt,
    user: toPublicUser(userRow),
  });
});

app.post("/api/auth/login", (req, res) => {
  const parsed = LoginSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: "INVALID_INPUT", details: parsed.error.errors });
  }

  const phone = normalizePhone(parsed.data.phone);
  const password = parsed.data.password;

  if (!phone) {
    return res.status(400).json({ error: "INVALID_PHONE" });
  }

  const userRow = loadUserByPhone(phone);
  if (!userRow || !verifyPassword(password, userRow.password_salt, userRow.password_hash)) {
    return res.status(401).json({ error: "INVALID_CREDENTIALS" });
  }

  const session = createSession(userRow.id);

  res.json({
    token: session.token,
    expiresAt: session.expiresAt,
    user: toPublicUser(userRow),
  });
});

app.post("/api/auth/logout", requireAuth, (req, res) => {
  deleteSession(req.auth.token);
  res.status(204).send();
});

app.get("/api/auth/me", requireAuth, (req, res) => {
  res.json({
    user: req.auth.user,
    expiresAt: req.auth.session.expires_at,
  });
});

function newId(prefix="ord") {
  return `${prefix}_${Math.random().toString(36).slice(2,8)}${Date.now().toString(36).slice(-4)}`;
}

/* ========== APIs ========== */

// التصنيفات
app.get("/api/categories", (req, res) => {
  const rows = db.prepare("SELECT DISTINCT cat FROM products ORDER BY cat").all();
  res.json(rows.map(r => r.cat));
});

// كل المنتجات أو حسب تصنيف
app.get("/api/products", (req, res) => {
  const { cat, q } = req.query;

  let sql = "SELECT * FROM products";
  const where = [];
  const params = {};

  if (cat && cat !== "الكل") { where.push("cat = @cat"); params.cat = cat; }
  if (q) { where.push("(LOWER(name_ar) LIKE @q OR LOWER(keywords) LIKE @q)"); params.q = `%${String(q).toLowerCase()}%`; }

  if (where.length) sql += " WHERE " + where.join(" AND ");
  sql += " ORDER BY name_ar";

  const rows = db.prepare(sql).all(params);
  res.json(rows);
});

app.get("/api/orders", requireAuth, (req, res) => {
  const orders = db.prepare(`
    SELECT *
    FROM orders
    WHERE user_id = ?
    ORDER BY datetime(created_at) DESC
  `).all(req.auth.user.id);

  res.json(orders);
});

// إنشاء طلب
app.post("/api/orders", requireAuth, (req, res) => {
  const parse = CreateOrderSchema.safeParse(req.body);
  if (!parse.success) {
    return res.status(400).json({ error: "INVALID_INPUT", details: parse.error.errors });
  }

  const { productId, fullName, phone, email, notes } = parse.data;

  const user = req.auth.user;
  const buyerName = typeof fullName === "string" && fullName.trim().length >= 2 ? fullName.trim() : user.fullName;
  const normalizedUserPhone = normalizePhone(user.phone);
  const submittedPhone = typeof phone === "string" ? phone : "";
  const contactPhone = normalizePhone(submittedPhone) || normalizedUserPhone;

  if (!contactPhone) {
    return res.status(400).json({ error: "INVALID_PHONE" });
  }

  const contactEmail = email && email.trim() ? email.trim() : null;
  const orderNotes = notes && notes.trim() ? notes.trim() : null;

  const product = db.prepare("SELECT * FROM products WHERE id = ?").get(productId);
  if (!product) return res.status(404).json({ error: "PRODUCT_NOT_FOUND" });

  const id = newId();
  db.prepare(`
    INSERT INTO orders (id, user_id, product_id, product_name, duration, price, full_name, phone, email, notes, status)
    VALUES (@id, @user_id, @product_id, @product_name, @duration, @price, @full_name, @phone, @email, @notes, 'pending')
  `).run({
    id,
    user_id: user.id,
    product_id: product.id,
    product_name: product.name_ar,
    duration: product.duration,
    price: product.price,
    full_name: buyerName,
    phone: contactPhone,
    email: contactEmail,
    notes: orderNotes,
  });

  // رابط واتساب جاهز (اختياري ترسله للفرونت)
  const text = [
    "🛒 *فاتورة طلب اشتراك*",
    `• المنتج: ${product.name_ar}`,
    `• المدة: ${product.duration}`,
    `• السعر: ${product.price} MRU`,
    "— — —",
    `• الاسم: ${buyerName}`,
    `• الواتساب: ${contactPhone}`,
    email ? `• البريد: ${email}` : null,
    notes ? `• ملاحظات: ${notes}` : null,
    `• رقم الطلب: ${id}`,
    `• وقت الإرسال: ${new Date().toLocaleString()}`,
  ].filter(Boolean).join("\n");

  const wa = `https://wa.me/${ADMIN_PHONE}?text=${encodeURIComponent(text)}`;

  res.status(201).json({ id, status: "pending", whatsappLink: wa });
});

// الحصول على طلب برقم التتبّع
app.get("/api/orders/:id", (req, res) => {
  const adminKey = req.get("x-admin-key");
  if (adminKey && adminKey === process.env.ADMIN_KEY) {
    const row = db.prepare("SELECT * FROM orders WHERE id = ?").get(req.params.id);
    if (!row) return res.status(404).json({ error: "ORDER_NOT_FOUND" });
    return res.json(row);
  }

  const auth = authenticateRequest(req);
  if (!auth) return res.status(401).json({ error: "UNAUTHORIZED" });

  const row = db.prepare("SELECT * FROM orders WHERE id = ? AND user_id = ?").get(req.params.id, auth.user.id);
  if (!row) return res.status(404).json({ error: "ORDER_NOT_FOUND" });

  res.json(row);
});

// (اختياري) تحديث حالة الطلب — اجعلها محمية بمفتاح سري بسيط
app.put("/api/orders/:id/status", (req, res) => {
  const key = req.header("x-admin-key");
  if (key !== process.env.ADMIN_KEY) return res.status(401).json({ error: "UNAUTHORIZED" });

  const allowed = new Set(["pending", "paid", "delivered", "canceled"]);
  const { status } = req.body || {};
  if (!allowed.has(status)) return res.status(400).json({ error: "INVALID_STATUS" });

  const info = db.prepare("UPDATE orders SET status = ? WHERE id = ?").run(status, req.params.id);
  if (info.changes === 0) return res.status(404).json({ error: "ORDER_NOT_FOUND" });

  res.json({ id: req.params.id, status });
});

app.get("/health", (_, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`API listening on http://localhost:${PORT}`);
});



