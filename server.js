require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const { Redis } = require("@upstash/redis");
const { z } = require("zod");

const app = express();

const PORT = process.env.PORT || 8080;
const ORIGIN = process.env.ORIGIN || "*";
const ADMIN_PHONE = process.env.ADMIN_PHONE || "22234605765";
const ADMIN_KEY = process.env.ADMIN_KEY || "";
const SESSION_TTL_MS = Number(process.env.SESSION_TTL_MS || 1000 * 60 * 60 * 24 * 7);
const SESSION_TTL_SECONDS = Math.max(60, Math.ceil(SESSION_TTL_MS / 1000));

const redis = process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN
  ? Redis.fromEnv()
  : process.env.KV_REST_API_URL && process.env.KV_REST_API_TOKEN
    ? new Redis({ url: process.env.KV_REST_API_URL, token: process.env.KV_REST_API_TOKEN })
    : null;

const DEFAULT_PRODUCTS = [
  { id: "netflix_1", name_ar: "نتفلكس 4K (بروفايل خاص)", cat: "منصات ترفيه", duration: "شهر واحد", price: 270, img: "/ntflx.jpg", keywords: "netflix uhd 4k" },
  { id: "netflix_3", name_ar: "نتفلكس 4K (بروفايل خاص)", cat: "منصات ترفيه", duration: "3 أشهر", price: 500, img: "/ntflx.jpg", keywords: "netflix uhd 4k" },
  { id: "chatgpt_plus_1", name_ar: "شات جي بي تي بلس (حساب مشترك)", cat: "أدوات إنتاجية", duration: "شهر واحد", price: 280, img: "/gpt.jpg", keywords: "chatgpt gpt plus" },
  { id: "chatgpt_plus_3", name_ar: "شات جي بي تي بلس (حساب مشترك)", cat: "أدوات إنتاجية", duration: "3 أشهر", price: 800, img: "/gpt.jpg", keywords: "chatgpt gpt plus" },
  { id: "chatgpt_plus_private", name_ar: "شات جي بي تي بلس (حساب خاص)", cat: "أدوات إنتاجية", duration: "شهر واحد", price: 880, img: "/gpt.jpg", keywords: "chatgpt gpt plus private" },
  { id: "snap_plus_3", name_ar: "سناب شات بلس", cat: "منصات تواصل", duration: "3 أشهر", price: 270, img: "/snapchat.jpg", keywords: "snapchat plus" },
  { id: "snap_plus_6", name_ar: "سناب شات بلس", cat: "منصات تواصل", duration: "6 أشهر", price: 500, img: "/snapchat.jpg", keywords: "snapchat plus" },
  { id: "canva_pro", name_ar: "كانفا برو (حساب مشترك)", cat: "تصميم وإبداع", duration: "غير محدود", price: 200, img: "/canva.jpg", keywords: "canva pro design" },
  { id: "capcut_pro", name_ar: "كاب كت برو (حساب خاص)", cat: "تصميم وإبداع", duration: "شهر واحد", price: 800, img: "/capcut.jpg", keywords: "capcut pro" },
  { id: "meta_verified", name_ar: "ميتا فيريفيد", cat: "تصميم وإبداع", duration: "شهر واحد", price: 800, img: "/meta.jpg", keywords: "meta verified" },
  { id: "adobe_suite", name_ar: "أدوبي كرياتيف كلاود", cat: "تصميم وإبداع", duration: "غير محدود", price: 1000, img: "/adobe.jpg", keywords: "adobe photoshop illustrator" },
];

app.use(helmet());
app.use(cors({ origin: ORIGIN, credentials: true }));
app.use(express.json({ limit: "200kb" }));
app.use(rateLimit({ windowMs: 60_000, max: 120 }));

const CreateOrderSchema = z.object({
  productId: z.string().min(1),
  fullName: z.string().min(2).optional().or(z.literal("")),
  phone: z.string().min(6).optional().or(z.literal("")),
  email: z.string().email().optional().or(z.literal("")),
  notes: z.string().max(1000).optional().or(z.literal("")),
});

const RegisterSchema = z.object({
  fullName: z.string().min(2).max(120),
  phone: z.string().min(6).max(30),
  password: z.string().min(6).max(128),
});

const LoginSchema = z.object({
  phone: z.string().min(6).max(30),
  password: z.string().min(6).max(128),
});

const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

function assertRedis() {
  if (!redis) {
    throw new Error("KV storage is not configured. Set KV_REST_API_URL and KV_REST_API_TOKEN.");
  }
  return redis;
}

let seedPromise = null;
async function ensureSeeded() {
  assertRedis();
  if (seedPromise) return seedPromise;
  seedPromise = (async () => {
    const exists = await redis.exists("products");
    if (!exists) {
      await redis.set("products", DEFAULT_PRODUCTS);
    }
  })();
  return seedPromise;
}

async function getProducts() {
  await ensureSeeded();
  return (await redis.get("products")) || [];
}

async function getProductById(id) {
  const products = await getProducts();
  return products.find((product) => product.id === id) || null;
}

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
  } catch {
    return false;
  }
}

function toPublicUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    fullName: user.full_name,
    phone: user.phone,
    createdAt: user.created_at,
  };
}

function newId(prefix = "ord") {
  return `${prefix}_${Math.random().toString(36).slice(2, 8)}${Date.now().toString(36).slice(-4)}`;
}

async function getUserById(id) {
  if (!id) return null;
  await ensureSeeded();
  return (await redis.get(`user:${id}`)) || null;
}

async function getUserByPhone(phone) {
  if (!phone) return null;
  await ensureSeeded();
  const userId = await redis.get(`user:phone:${phone}`);
  if (!userId) return null;
  return getUserById(userId);
}

async function saveUser(user) {
  await ensureSeeded();
  await redis.set(`user:${user.id}`, user);
  await redis.set(`user:phone:${user.phone}`, user.id);
}

async function createSession(userId) {
  await ensureSeeded();
  const token = crypto.randomBytes(48).toString("hex");
  const createdAt = new Date();
  const expiresAt = new Date(createdAt.getTime() + SESSION_TTL_MS);
  const session = {
    id: token,
    user_id: userId,
    created_at: createdAt.toISOString(),
    expires_at: expiresAt.toISOString(),
  };
  await redis.set(`session:${token}`, session, { ex: SESSION_TTL_SECONDS });
  return { token, expiresAt: session.expires_at };
}

async function getSession(token) {
  if (!token) return null;
  await ensureSeeded();
  return (await redis.get(`session:${token}`)) || null;
}

async function deleteSession(token) {
  if (!token) return;
  await ensureSeeded();
  await redis.del(`session:${token}`);
}

async function authenticateRequest(req) {
  const authHeader = req.get("authorization");
  let token = null;
  if (authHeader && typeof authHeader === "string" && authHeader.toLowerCase().startsWith("bearer ")) {
    token = authHeader.slice(7).trim();
  } else {
    const headerToken = req.get("x-session-token");
    token = headerToken ? headerToken.trim() : null;
  }

  if (!token) return null;
  const session = await getSession(token);
  if (!session) return null;
  const user = await getUserById(session.user_id);
  if (!user) {
    await deleteSession(token);
    return null;
  }

  return {
    token,
    session,
    user: toPublicUser(user),
  };
}

function requireAuth(req, res, next) {
  authenticateRequest(req)
    .then((auth) => {
      if (!auth) return res.status(401).json({ error: "UNAUTHORIZED" });
      req.auth = auth;
      next();
    })
    .catch(next);
}

async function saveOrder(order) {
  await ensureSeeded();
  await redis.set(`order:${order.id}`, order);
  await redis.lpush(`orders:user:${order.user_id}`, order.id);
}

async function getOrdersForUser(userId) {
  await ensureSeeded();
  const ids = await redis.lrange(`orders:user:${userId}`, 0, -1);
  if (!ids || ids.length === 0) return [];
  const seen = new Set();
  const result = [];
  for (const id of ids) {
    if (seen.has(id)) continue;
    seen.add(id);
    const order = await redis.get(`order:${id}`);
    if (order) result.push(order);
  }
  return result.sort((a, b) => Date.parse(b.created_at || 0) - Date.parse(a.created_at || 0));
}

async function getOrderById(id) {
  await ensureSeeded();
  return (await redis.get(`order:${id}`)) || null;
}

app.post(
  "/api/auth/register",
  asyncHandler(async (req, res) => {
    const parsed = RegisterSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "INVALID_INPUT", details: parsed.error.errors });
    }

    assertRedis();
    const fullName = parsed.data.fullName.trim();
    const phone = normalizePhone(parsed.data.phone);
    if (!phone) {
      return res.status(400).json({ error: "INVALID_PHONE" });
    }

    const existing = await getUserByPhone(phone);
    if (existing) {
      return res.status(409).json({ error: "USER_EXISTS" });
    }

    const { hash, salt } = hashPassword(parsed.data.password);
    const userId = newId("usr");
    const createdAt = new Date().toISOString();
    const user = {
      id: userId,
      full_name: fullName,
      phone,
      password_hash: hash,
      password_salt: salt,
      created_at: createdAt,
    };

    await saveUser(user);
    const session = await createSession(userId);

    res.status(201).json({
      token: session.token,
      expiresAt: session.expiresAt,
      user: toPublicUser(user),
    });
  })
);

app.post(
  "/api/auth/login",
  asyncHandler(async (req, res) => {
    const parsed = LoginSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "INVALID_INPUT", details: parsed.error.errors });
    }

    assertRedis();
    const phone = normalizePhone(parsed.data.phone);
    if (!phone) {
      return res.status(400).json({ error: "INVALID_PHONE" });
    }

    const user = await getUserByPhone(phone);
    if (!user || !verifyPassword(parsed.data.password, user.password_salt, user.password_hash)) {
      return res.status(401).json({ error: "INVALID_CREDENTIALS" });
    }

    const session = await createSession(user.id);

    res.json({
      token: session.token,
      expiresAt: session.expiresAt,
      user: toPublicUser(user),
    });
  })
);

app.post(
  "/api/auth/logout",
  requireAuth,
  asyncHandler(async (req, res) => {
    await deleteSession(req.auth.token);
    res.status(204).send();
  })
);

app.get(
  "/api/auth/me",
  requireAuth,
  asyncHandler(async (req, res) => {
    res.json({
      user: req.auth.user,
      expiresAt: req.auth.session.expires_at,
    });
  })
);

app.get(
  "/api/categories",
  asyncHandler(async (req, res) => {
    assertRedis();
    const products = await getProducts();
    const categories = Array.from(
      new Set(
        products
          .map((product) => product.cat)
          .filter((cat) => typeof cat === "string" && cat.trim().length > 0)
      )
    ).sort((a, b) => a.localeCompare(b, "ar"));

    res.json(categories);
  })
);

app.get(
  "/api/products",
  asyncHandler(async (req, res) => {
    assertRedis();
    let products = await getProducts();

    const cat = req.query.cat ? String(req.query.cat) : null;
    const q = req.query.q ? String(req.query.q).toLowerCase() : null;

    if (cat && cat !== "الكل") {
      products = products.filter((product) => product.cat === cat);
    }

    if (q) {
      products = products.filter((product) => {
        const haystack = `${product.name_ar} ${product.keywords}`.toLowerCase();
        return haystack.includes(q);
      });
    }

    res.json(products);
  })
);

app.get(
  "/api/orders",
  requireAuth,
  asyncHandler(async (req, res) => {
    assertRedis();
    const orders = await getOrdersForUser(req.auth.user.id);
    res.json(orders);
  })
);

app.post(
  "/api/orders",
  requireAuth,
  asyncHandler(async (req, res) => {
    assertRedis();
    const parse = CreateOrderSchema.safeParse(req.body);
    if (!parse.success) {
      return res.status(400).json({ error: "INVALID_INPUT", details: parse.error.errors });
    }

    const { productId, fullName, phone, email, notes } = parse.data;
    const product = await getProductById(productId);
    if (!product) {
      return res.status(404).json({ error: "PRODUCT_NOT_FOUND" });
    }

    const user = req.auth.user;
    const buyerName = typeof fullName === "string" && fullName.trim().length >= 2 ? fullName.trim() : user.fullName;
    const submittedPhone = typeof phone === "string" ? phone : "";
    const contactPhone = normalizePhone(submittedPhone) || normalizePhone(user.phone);
    if (!contactPhone) {
      return res.status(400).json({ error: "INVALID_PHONE" });
    }

    const contactEmail = email && email.trim() ? email.trim() : null;
    const orderNotes = notes && notes.trim() ? notes.trim() : null;

    const id = newId();
    const createdAt = new Date().toISOString();
    const order = {
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
      status: "pending",
      created_at: createdAt,
    };

    await saveOrder(order);

    const text = [
      "طلب جديد عبر موقع إشتراكي",
      `المنتج: ${product.name_ar}`,
      `مدة الاشتراك: ${product.duration}`,
      `السعر: ${product.price} MRU`,
      "----",
      `العميل: ${buyerName}`,
      `الهاتف: ${contactPhone}`,
      contactEmail ? `البريد: ${contactEmail}` : null,
      orderNotes ? `ملاحظات: ${orderNotes}` : null,
      `رقم الطلب: ${id}`,
      `تاريخ الطلب: ${new Date(createdAt).toLocaleString()}`,
    ]
      .filter(Boolean)
      .join("\n");

    const wa = `https://wa.me/${ADMIN_PHONE}?text=${encodeURIComponent(text)}`;
    res.status(201).json({ id, status: "pending", whatsappLink: wa });
  })
);

app.get(
  "/api/orders/:id",
  asyncHandler(async (req, res) => {
    assertRedis();
    const order = await getOrderById(req.params.id);
    if (!order) return res.status(404).json({ error: "ORDER_NOT_FOUND" });

    const adminKey = req.get("x-admin-key");
    if (adminKey && adminKey === ADMIN_KEY) {
      return res.json(order);
    }

    const auth = await authenticateRequest(req);
    if (!auth) return res.status(401).json({ error: "UNAUTHORIZED" });
    if (order.user_id !== auth.user.id) {
      return res.status(404).json({ error: "ORDER_NOT_FOUND" });
    }

    res.json(order);
  })
);

app.put(
  "/api/orders/:id/status",
  asyncHandler(async (req, res) => {
    assertRedis();
    const key = req.header("x-admin-key");
    if (key !== ADMIN_KEY) {
      return res.status(401).json({ error: "UNAUTHORIZED" });
    }

    const allowed = new Set(["pending", "paid", "delivered", "canceled"]);
    const { status } = req.body || {};
    if (!allowed.has(status)) {
      return res.status(400).json({ error: "INVALID_STATUS" });
    }

    const order = await getOrderById(req.params.id);
    if (!order) return res.status(404).json({ error: "ORDER_NOT_FOUND" });

    order.status = status;
    await redis.set(`order:${order.id}`, order);

    res.json({ id: order.id, status });
  })
);

app.get(
  "/health",
  asyncHandler(async (req, res) => {
    assertRedis();
    await ensureSeeded();
    res.json({ ok: true });
  })
);

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "INTERNAL_ERROR" });
});

if (require.main === module) {
  ensureSeeded()
    .then(() => {
      app.listen(PORT, () => {
        console.log(`API listening on http://localhost:${PORT}`);
      });
    })
    .catch((err) => {
      console.error("Failed to initialize KV storage:", err);
      process.exit(1);
    });
}

module.exports = app;
