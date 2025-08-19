import express from "express";
import dotenv from "dotenv";
import path from "path";
import sqlite3 from "sqlite3";
import { open } from "sqlite";
import { fileURLToPath } from "url";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import csurf from "csurf";
import session from "express-session";
import rateLimit from "express-rate-limit";
import morgan from "morgan";
import crypto from "crypto";
import axios from "axios";
import bcrypt from "bcryptjs";
import { nanoid } from "nanoid";
import Joi from "joi";
import nodemailer from "nodemailer";
import { v4 as uuidv4 } from "uuid";
import fs from "fs";
import winston from "winston";

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();

const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const STORE_NAME = process.env.STORE_NAME || "TopUp PRO PLUS SECURE";

const TRIPAY_API_BASE = process.env.TRIPAY_API_BASE || "https://tripay.co.id/api-sandbox";
const TRIPAY_API_KEY = process.env.TRIPAY_API_KEY || "";
const TRIPAY_PRIVATE_KEY = process.env.TRIPAY_PRIVATE_KEY || "";
const TRIPAY_MERCHANT_CODE = process.env.TRIPAY_MERCHANT_CODE || "";

// ensure logs directory
if(!fs.existsSync(path.join(__dirname,'logs'))) fs.mkdirSync(path.join(__dirname,'logs'));

// logger (winston)
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [
    new winston.transports.File({ filename: path.join(__dirname,'logs','attempts.log') }),
    new winston.transports.Console()
  ]
});

// security & middleware
app.use(helmet());
app.use(morgan("dev"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(session({ secret: process.env.SESSION_SECRET || 'change-me', resave: false, saveUninitialized: false, cookie: { httpOnly: true } }));
app.use(express.static(path.join(__dirname, "public")));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

const limiter = rateLimit({ windowMs: 60*1000, limit: 120 });
app.use(limiter);

const csrfProtection = csurf({ cookie: false });
app.use(csrfProtection);

// DB
const db = await open({ filename: path.join(__dirname, "data.sqlite"), driver: sqlite3.Database });
await db.exec(`
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, password TEXT, role TEXT);
CREATE TABLE IF NOT EXISTS admin_otps(id TEXT PRIMARY KEY, user_id INTEGER, code_hash TEXT, expires_at INTEGER, used INTEGER DEFAULT 0, attempts INTEGER DEFAULT 0, blocked_until INTEGER DEFAULT 0, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS login_attempts(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, ip TEXT, success INTEGER, created_at INTEGER, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS games(id INTEGER PRIMARY KEY AUTOINCREMENT, slug TEXT UNIQUE NOT NULL, name TEXT NOT NULL, publisher TEXT, cover_url TEXT, require_server_region INTEGER DEFAULT 0, require_player_zone INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS denominations(id INTEGER PRIMARY KEY AUTOINCREMENT, game_id INTEGER NOT NULL, label TEXT NOT NULL, value INTEGER NOT NULL, price INTEGER NOT NULL, popular INTEGER DEFAULT 0, FOREIGN KEY (game_id) REFERENCES games(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS orders(id TEXT PRIMARY KEY, game_slug TEXT NOT NULL, game_name TEXT NOT NULL, player_id TEXT NOT NULL, server_region TEXT, player_zone TEXT, denom_label TEXT NOT NULL, denom_value INTEGER NOT NULL, price INTEGER NOT NULL, currency TEXT NOT NULL, status TEXT NOT NULL, pay_method TEXT, payment_provider TEXT, payment_reference TEXT, checkout_url TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS markups(id INTEGER PRIMARY KEY AUTOINCREMENT, method TEXT UNIQUE, amount INTEGER DEFAULT 0);
`);

// bootstrap admin and markups
const userCount = await db.get("SELECT COUNT(*) as c FROM users");
if (userCount.c === 0) {
  const pass = process.env.ADMIN_PASSWORD || "admin123";
  const hash = await bcrypt.hash(pass, 10);
  await db.run("INSERT INTO users(email,password,role) VALUES(?,?,?)", process.env.ADMIN_EMAIL || "admin@example.com", hash, "admin");
}
const markups = ["QRIS","BRIVA","DANA","OVO","MANDIRIVA"];
for(const m of markups){
  const existing = await db.get("SELECT * FROM markups WHERE method=?", m);
  if(!existing){
    const envKey = "MARKUP_" + m.replace(/VA$/,"");
    const envVal = parseInt(process.env["MARKUP_" + m.split(/VA|_/)[0]] || process.env["MARKUP_" + m] || 0);
    await db.run("INSERT INTO markups(method,amount) VALUES(?,?)", m, envVal || 0);
  }
}

// seed games
const gcount = await db.get("SELECT COUNT(*) as c FROM games");
if (gcount.c === 0) {
  const games = [
    {slug:"mobile-legends", name:"Mobile Legends", publisher:"Moonton", cover_url:"/img/mlbb.jpg", require_server_region:1, require_player_zone:1},
    {slug:"free-fire", name:"Free Fire", publisher:"Garena", cover_url:"/img/freefire.jpg", require_server_region:1, require_player_zone:0},
    {slug:"genshin-impact", name:"Genshin Impact", publisher:"HoYoverse", cover_url:"/img/genshin.jpg", require_server_region:0, require_player_zone:0}
  ];
  for(const g of games){
    const r = await db.run("INSERT INTO games(slug,name,publisher,cover_url,require_server_region,require_player_zone) VALUES(?,?,?,?,?,?)", g.slug,g.name,g.publisher,g.cover_url,g.require_server_region,g.require_player_zone);
    const gameId = r.lastID;
    const denoms = [{label:"86 Diamonds",value:86,price:25000},{label:"172 Diamonds",value:172,price:48000,popular:1},{label:"258 Diamonds",value:258,price:71000}];
    for(const d of denoms) await db.run("INSERT INTO denominations(game_id,label,value,price,popular) VALUES(?,?,?,?,?)", gameId,d.label,d.value,d.price,d.popular||0);
  }
}

const rupiah = n => new Intl.NumberFormat("id-ID",{style:"currency",currency:"IDR",maximumFractionDigits:0}).format(n);
const nowISO = () => new Date().toISOString();

// email transporter
let transporter = null;
if(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS){
  transporter = nodemailer.createTransport({ host: process.env.SMTP_HOST, port: parseInt(process.env.SMTP_PORT||587), secure:false, auth:{user:process.env.SMTP_USER, pass:process.env.SMTP_PASS} });
}

// middleware locals and IP whitelist check helper
app.use((req,res,next)=>{
  res.locals.csrfToken = req.csrfToken();
  res.locals.user = req.session.user || null;
  res.locals.STORE_NAME = STORE_NAME;
  next();
});

function ipAllowed(req){
  const list = (process.env.ADMIN_IP_WHITELIST||"").split(",").map(s=>s.trim()).filter(Boolean);
  if(list.length===0) return true;
  const ip = req.ip || req.connection.remoteAddress || "";
  return list.includes(ip);
}

// storefront
app.get("/", async (req,res)=>{
  const games = await db.all("SELECT * FROM games ORDER BY name ASC");
  res.render("index",{games});
});
app.get("/game/:slug", async (req,res)=>{
  const game = await db.get("SELECT * FROM games WHERE slug=?", req.params.slug);
  if(!game) return res.status(404).render("404");
  const denoms = await db.all("SELECT * FROM denominations WHERE game_id=? ORDER BY price ASC", game.id);
  const channels = await db.all("SELECT method,amount FROM markups");
  res.render("game",{game,denoms,rupiah,channels});
});

// checkout (Joi validation + markups)
const checkoutSchema = Joi.object({
  game_slug: Joi.string().required(),
  game_name: Joi.string().required(),
  player_id: Joi.string().pattern(/^[0-9A-Za-z_-]{3,30}$/).required(),
  server_region: Joi.string().allow('', null),
  player_zone: Joi.string().pattern(/^[0-9]{1,10}$/).allow('', null),
  denom_label: Joi.string().required(),
  denom_value: Joi.number().required(),
  price: Joi.number().required(),
  pay_method: Joi.string().required()
});

app.post("/checkout", async (req,res)=>{
  try {
    const { error, value } = checkoutSchema.validate(req.body);
    if(error) return res.status(400).send("Invalid input: " + error.message);

    const id = `ORD-${nanoid(10)}`;
    const amountBase = parseInt(value.price);
    const markupRow = await db.get("SELECT amount FROM markups WHERE method=?", value.pay_method) || {amount:0};
    const finalAmount = amountBase + (markupRow.amount || 0);

    await db.run("INSERT INTO orders(id,game_slug,game_name,player_id,server_region,player_zone,denom_label,denom_value,price,currency,status,pay_method,payment_provider,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
      id, value.game_slug, value.game_name, value.player_id, value.server_region||null, value.player_zone||null, value.denom_label, value.denom_value, finalAmount, process.env.CURRENCY||'IDR', "pending", value.pay_method, "tripay", nowISO(), nowISO());

    const signature = crypto.createHmac("sha256", TRIPAY_PRIVATE_KEY).update(TRIPAY_MERCHANT_CODE + id + finalAmount).digest("hex");
    const endpoint = `${TRIPAY_API_BASE}/transaction/create`;
    const r = await axios.post(endpoint, {
      method: value.pay_method,
      merchant_ref: id,
      amount: finalAmount,
      customer_name: value.player_id,
      customer_email: `customer-${id}@sandbox.local`,
      order_items: [{ sku: value.game_slug, name: `${value.game_name} - ${value.denom_label}`, price: finalAmount, quantity: 1 }],
      return_url: `${BASE_URL}/orders/${id}`,
      expired_time: Math.floor(Date.now()/1000) + (24*60*60),
      signature
    }, { headers: { Authorization: `Bearer ${TRIPAY_API_KEY}` } });

    const data = r.data?.data || {};
    await db.run("UPDATE orders SET payment_reference=?, checkout_url=?, updated_at=? WHERE id=?", data.reference || null, data.checkout_url || null, nowISO(), id);
    res.redirect(`/orders/${id}`);
  } catch(e) {
    console.error(e.response?.data || e.message);
    res.status(500).send("Checkout error");
  }
});

app.get("/orders/:id", async (req,res)=>{
  const order = await db.get("SELECT * FROM orders WHERE id=?", req.params.id);
  if(!order) return res.status(404).render("404");
  res.render("order",{order,rupiah});
});

// webhook with WA template send and email, logs
app.post("/webhook/tripay", async (req,res)=>{
  try {
    const { reference, merchant_ref, status, amount, signature } = req.body || {};
    const expected = crypto.createHmac("sha256", TRIPAY_PRIVATE_KEY).update(merchant_ref + reference + status + amount).digest("hex");
    if(signature !== expected) return res.status(400).json({ message: "Invalid signature" });
    let newStatus = "pending";
    if(status === "PAID" || status === "SUCCESS") newStatus = "paid";
    if(status === "FAILED" || status === "EXPIRED" || status === "REFUND") newStatus = "failed";
    await db.run("UPDATE orders SET status=?, updated_at=? WHERE id=?", newStatus, nowISO(), merchant_ref);

    // log
    logger.info({ event: 'webhook_tripay', order: merchant_ref, status: newStatus, amount });

    // notify email
    if(newStatus === "paid" && transporter && process.env.NOTIFY_EMAIL_TO){
      try { await transporter.sendMail({ from: `"${STORE_NAME}" <${process.env.SMTP_USER}>`, to: process.env.NOTIFY_EMAIL_TO, subject:`Order ${merchant_ref} PAID`, text:`Order ${merchant_ref} telah dibayar. Amount: ${amount}` }); } catch(e){ logger.warn("Email send failed", { message: e.message }); }
    }

    // WhatsApp template (recommended: pre-approved template). Fallback to text message.
    if(newStatus === "paid" && process.env.WA_API_URL && process.env.WA_ACCESS_TOKEN && process.env.WA_TO){
      try {
        // example template payload (modify to your approved template name)
        const templateName = process.env.WA_TEMPLATE_NAME || "order_status";
        const payload = {
          messaging_product: "whatsapp",
          to: process.env.WA_TO,
          type: "template",
          template: {
            name: templateName,
            language: { code: "en_US" },
            components: [
              { type: "body", parameters: [
                { type: "text", text: merchant_ref },
                { type: "text", text: `${amount}` },
                { type: "text", text: new Date().toLocaleString() }
              ] }
            ]
          }
        };
        await axios.post(process.env.WA_API_URL, payload, { headers: { Authorization: `Bearer ${process.env.WA_ACCESS_TOKEN}`, "Content-Type": "application/json" } });
      } catch(e) { logger.warn("WA send failed", { message: e.message }); }
    }

    res.json({ ok: true });
  } catch(e) { logger.error(e); res.status(500).json({ message: "Webhook error" }); }
});

// Admin login -> create hashed OTP -> rate limit & block logic
app.get("/admin/login", (req,res)=> res.render("admin_login"));
app.post("/admin/login", async (req,res)=>{
  const { email, password } = req.body;
  const user = await db.get("SELECT * FROM users WHERE email=?", email);
  const ip = req.ip || req.connection.remoteAddress || '';
  if(!user){
    // log attempt
    await db.run("INSERT INTO login_attempts(user_id,ip,success,created_at) VALUES(?,?,?,?)", null, ip, 0, Math.floor(Date.now()/1000));
    logger.info({ event: 'login_attempt', email, ip, success: false });
    return res.render("admin_login", { error: "Invalid credentials" });
  }
  const ok = await bcrypt.compare(password, user.password);
  await db.run("INSERT INTO login_attempts(user_id,ip,success,created_at) VALUES(?,?,?,?)", user.id, ip, ok?1:0, Math.floor(Date.now()/1000));
  if(!ok) { logger.info({ event: 'login_failed', user: user.email, ip }); return res.render("admin_login", { error: "Invalid credentials" }); }

  // create OTP hashed and save
  const otp = Math.floor(100000 + Math.random()*900000).toString();
  const otpId = uuidv4();
  const expires = Math.floor(Date.now()/1000) + (5*60); // 5 minutes
  const otpHash = await bcrypt.hash(otp, 10);
  await db.run("INSERT INTO admin_otps(id,user_id,code_hash,expires_at,used,attempts,blocked_until) VALUES(?,?,?,?,?,?,?)", otpId, user.id, otpHash, expires, 0, 0, 0);
  // send OTP via email
  if(transporter){
    try { await transporter.sendMail({ from: `"${STORE_NAME}" <${process.env.SMTP_USER}>`, to: user.email, subject: "Your admin OTP", text: `Kode OTP: ${otp}. Berlaku 5 menit.` }); } catch(e){ logger.warn("OTP email failed", { message: e.message }); }
  }
  // store pending in session
  req.session.pendingLogin = { userId: user.id, otpId };
  res.render("admin_otp");
});

// verify OTP with attempt limits & blocking
app.post("/admin/verify-otp", async (req,res)=>{
  const { otp } = req.body;
  const pending = req.session.pendingLogin;
  if(!pending) return res.redirect("/admin/login");
  const row = await db.get("SELECT * FROM admin_otps WHERE id=? AND used=0", pending.otpId);
  if(!row) return res.render("admin_otp", { error: "OTP not found or used" });
  const now = Math.floor(Date.now()/1000);
  if(row.blocked_until && row.blocked_until > now) {
    return res.render("admin_otp", { error: "Too many failed attempts. Try later." });
  }
  if(row.expires_at < now) return res.render("admin_otp", { error: "OTP expired" });
  const match = await bcrypt.compare(otp, row.code_hash);
  if(!match){
    // increment attempts, block if >=3
    const attempts = (row.attempts||0) + 1;
    let blocked_until = row.blocked_until || 0;
    if(attempts >= 3) blocked_until = now + (10*60); // block 10 minutes
    await db.run("UPDATE admin_otps SET attempts=?, blocked_until=? WHERE id=?", attempts, blocked_until, row.id);
    logger.info({ event: 'otp_failed', user_id: row.user_id, attempts, ip: req.ip });
    return res.render("admin_otp", { error: "Incorrect OTP" });
  }
  // success -> mark used and create session
  await db.run("UPDATE admin_otps SET used=1 WHERE id=?", row.id);
  const user = await db.get("SELECT * FROM users WHERE id=?", row.user_id);
  req.session.user = { id: user.id, email: user.email, role: user.role };
  delete req.session.pendingLogin;
  logger.info({ event: 'otp_success', user: user.email, ip: req.ip });
  res.redirect("/admin");
});

// admin routes with IP whitelist
function ensureAdmin(req,res,next){ if(!req.session.user) return res.redirect("/admin/login"); if(!ipAllowed(req)) return res.status(403).send("Access denied from this IP"); next(); }
app.get("/admin", ensureAdmin, async (req,res)=>{
  const stats = await db.get("SELECT COUNT(*) as orders FROM orders");
  const ordersRecent = await db.all("SELECT * FROM orders ORDER BY created_at DESC LIMIT 10");
  res.render("admin_dashboard",{stats,ordersRecent});
});
app.get("/admin/markups", ensureAdmin, async (req,res)=>{ const markups = await db.all("SELECT * FROM markups ORDER BY method ASC"); res.render("admin_markups",{markups}); });
app.post("/admin/markups/:id", ensureAdmin, async (req,res)=>{ const amt = parseInt(req.body.amount||0); await db.run("UPDATE markups SET amount=? WHERE id=?", amt, req.params.id); res.redirect("/admin/markups"); });
app.get("/admin/orders", ensureAdmin, async (req,res)=>{ const orders = await db.all("SELECT * FROM orders ORDER BY created_at DESC LIMIT 200"); res.render("admin_orders",{orders,rupiah}); });
app.get("/admin/login", (req,res)=> res.redirect("/admin/login"));
app.get("/admin/logout", (req,res)=>{ req.session.destroy(()=>res.redirect("/admin/login")); });

// 404
app.use((req,res)=> res.status(404).render("404"));

app.listen(PORT, ()=> console.log(`TopUp PRO PLUS SECURE running at ${BASE_URL}`));
