'use strict';
/*
 * Prime Baking web shop server.
 *
 * Security model in one paragraph: the browser never decides a price and never sees a card or wallet PIN.
 * It sends product ids and quantities; this server prices the order from catalog.js, opens a Paynow
 * transaction with secret keys that live only in environment variables, and marks an order paid only
 * after it has itself asked Paynow (using the poll URL Paynow gave us, never one from a request),
 * checked Paynow's SHA-512 signature, and confirmed the amount and reference match the order exactly.
 */

require('./env').load();
const crypto = require('crypto');
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const axios = require('axios');
const { Paynow } = require('paynow');
const C = require('./catalog');
const store = require('./store');

// ---------- configuration ----------
const PROD = process.env.NODE_ENV === 'production';
const PORT = Number(process.env.PORT) || 3000;
const PUBLIC_URL = (process.env.PUBLIC_URL || '').replace(/\/+$/, '');
const INTEGRATION_ID = process.env.PAYNOW_INTEGRATION_ID;
const INTEGRATION_KEY = process.env.PAYNOW_INTEGRATION_KEY;
const TEST_MODE = process.env.PAYNOW_TEST_MODE === 'true';
const MERCHANT_EMAIL = process.env.PAYNOW_MERCHANT_EMAIL || '';

function fatal(msg) { console.error('Startup refused: ' + msg); process.exit(1); }
if (!INTEGRATION_ID || !INTEGRATION_KEY) fatal('PAYNOW_INTEGRATION_ID and PAYNOW_INTEGRATION_KEY must be set (see .env.example).');
if (!/^https?:\/\/[^/]+$/.test(PUBLIC_URL)) fatal('PUBLIC_URL must be the site origin, e.g. https://primebaking.co.zw');
if (PROD && !PUBLIC_URL.startsWith('https://')) fatal('PUBLIC_URL must use https:// in production.');
if (TEST_MODE && !MERCHANT_EMAIL) fatal('PAYNOW_MERCHANT_EMAIL is required in test mode.');
if (PROD && TEST_MODE) fatal('PAYNOW_TEST_MODE=true is not allowed when NODE_ENV=production. Test payments would mark real orders as paid.');
const TRUST_HOPS = Number(process.env.TRUST_PROXY);
if (!Number.isInteger(TRUST_HOPS) || TRUST_HOPS < 0 || TRUST_HOPS > 5) fatal('TRUST_PROXY must be set to the exact number of proxies in front of the app (0 if none, usually 1 on hosting platforms).');

const paynow = new Paynow(INTEGRATION_ID, INTEGRATION_KEY);
paynow.resultUrl = PUBLIC_URL + '/api/paynow/result';

// ---------- helpers ----------
const PAID = new Set(['paid', 'awaiting delivery', 'delivered']);
const FAILED = new Set(['cancelled', 'failed']);
const REVERSED = new Set(['refunded', 'disputed']);

const clean = (s, max) => String(s).normalize('NFC').replace(/[\u0000-\u001f\u007f<>]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
const isPlainObject = v => v !== null && typeof v === 'object' && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
const onlyKeys = (obj, allowed) => Object.keys(obj).every(k => allowed.includes(k));
// Linear-time email pattern (no nested quantifiers). The Paynow SDK's own pattern can hang on crafted input.
const EMAIL_RE = /^[A-Za-z0-9_]+(?:[.+-][A-Za-z0-9_]+)*@[A-Za-z0-9_]+(?:[.-][A-Za-z0-9_]+)*\.[A-Za-z]{2,24}$/;
const TEST_NUMBERS = /^077(1{7}|2{7}|3{7}|4{7})$/;
const ZW_MOBILE_RE = /^07[1378]\d{7}$/; // Econet 077/078, NetOne 071, Telecel 073

function safeEqual(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

// Parse a Paynow urlencoded message preserving field order (the signature depends on order),
// then verify its SHA-512 hash with a constant-time comparison.
function parseSigned(body) {
  if (typeof body !== 'string' || body.length === 0 || body.length > 8000) return null;
  const fields = paynow.parseQuery(body);
  if (typeof fields.hash !== 'string') return null;
  const expected = paynow.generateHash(fields, INTEGRATION_KEY);
  return safeEqual(fields.hash.toUpperCase(), expected) ? fields : null;
}

function isPaynowUrl(u) {
  try { const x = new URL(u); return x.protocol === 'https:' && x.hostname === 'www.paynow.co.zw'; } catch { return false; }
}

class BadRequest extends Error {}

function validateCheckout(body) {
  if (!isPlainObject(body) || !onlyKeys(body, ['items', 'customer', 'method', 'fulfilment'])) throw new BadRequest('Unexpected fields in request.');
  const { items, customer, method, fulfilment } = body;

  if (!Array.isArray(items) || items.length === 0) throw new BadRequest('Your cart is empty.');
  if (items.length > C.MAX_LINES) throw new BadRequest('Too many different items in one order.');
  const lines = new Map();
  for (const it of items) {
    if (!isPlainObject(it) || !onlyKeys(it, ['id', 'qty'])) throw new BadRequest('Invalid cart item.');
    if (typeof it.id !== 'string' || !Object.prototype.hasOwnProperty.call(C.PRODUCTS, it.id)) throw new BadRequest('A product in your cart is no longer available.');
    if (!Number.isInteger(it.qty) || it.qty < 1 || it.qty > C.MAX_QTY_PER_LINE) throw new BadRequest('Invalid quantity.');
    lines.set(it.id, (lines.get(it.id) || 0) + it.qty);
  }
  for (const q of lines.values()) if (q > C.MAX_QTY_PER_LINE) throw new BadRequest('Invalid quantity.');

  if (!['web', 'ecocash', 'onemoney'].includes(method)) throw new BadRequest('Choose a payment method.');
  if (!['delivery', 'collect'].includes(fulfilment)) throw new BadRequest('Choose delivery or collection.');

  if (!isPlainObject(customer) || !onlyKeys(customer, ['name', 'email', 'phone', 'address'])) throw new BadRequest('Invalid customer details.');
  const name = clean(customer.name || '', 80);
  const email = clean(customer.email || '', 254).toLowerCase();
  const phone = String(customer.phone || '').replace(/[\s-]/g, '').replace(/^\+?263/, '0');
  const address = clean(customer.address || '', 200);
  if (name.length < 2) throw new BadRequest('Enter your name.');
  if (email.length > 254 || !EMAIL_RE.test(email)) throw new BadRequest('Enter a valid email address.');
  if (!ZW_MOBILE_RE.test(phone) || (!TEST_MODE && TEST_NUMBERS.test(phone))) throw new BadRequest('Enter a valid Zimbabwe mobile number, like 0771234567.');
  if (fulfilment === 'delivery' && address.length < 6) throw new BadRequest('Enter a delivery address.');

  // Price everything server-side.
  const priced = [...lines].map(([id, qty]) => ({ id, qty, name: C.PRODUCTS[id].name, cents: C.PRODUCTS[id].cents * qty }));
  const subtotal = priced.reduce((s, l) => s + l.cents, 0);
  const delivery = fulfilment === 'delivery' && subtotal < C.FREE_DELIVERY_FROM_CENTS ? C.DELIVERY_CENTS : 0;
  const total = subtotal + delivery;
  if (total <= 0 || total > C.MAX_ORDER_CENTS) throw new BadRequest('Orders over $1,000 need to be placed with the shop directly.');

  return { lines: priced, subtotal, delivery, total, method, fulfilment, customer: { name, email, phone, address: fulfilment === 'delivery' ? address : '' } };
}

async function pollPaynow(order) {
  if (!isPaynowUrl(order.pollUrl)) return order;
  order.lastPolledAt = Date.now();
  let text;
  try {
    const res = await fetch(order.pollUrl, { method: 'POST', signal: AbortSignal.timeout(10000) });
    text = await res.text();
  } catch (e) {
    console.warn(`Poll failed for ${order.reference}: ${e.message}`);
    return order;
  }
  const f = parseSigned(text);
  if (!f) { console.warn(`Rejected unsigned or tampered poll response for ${order.reference}`); return order; }
  return applyStatus(order, f);
}

async function applyStatus(order, f) {
  const before = JSON.stringify([order.status, order.paynowStatus, order.paynowReference]);
  const status = String(f.status || '').toLowerCase();
  const amountCents = Math.round(parseFloat(f.amount) * 100);
  if (f.reference !== order.reference) { console.warn(`Reference mismatch on ${order.reference}`); return order; }
  order.paynowStatus = f.status;
  if (f.paynowreference) order.paynowReference = clean(f.paynowreference, 40);

  if (PAID.has(status)) {
    if (amountCents !== order.total) {
      if (order.status === 'pending') order.status = 'review';
      console.error(`AMOUNT MISMATCH on ${order.reference}: expected ${order.total} cents, Paynow reports ${amountCents}. Held for review.`);
    } else if (order.status === 'pending') {
      order.status = 'paid';
      order.paidAt = new Date().toISOString();
      console.log(`PAID ${order.reference} $${(order.total / 100).toFixed(2)} (run "npm run orders -- paid" for details)`);
    }
  } else if (FAILED.has(status) && order.status === 'pending') {
    order.status = 'failed';
  } else if (REVERSED.has(status) && order.status !== status) {
    order.status = status;
    console.warn(`${status.toUpperCase()} ${order.reference}`);
  }
  if (JSON.stringify([order.status, order.paynowStatus, order.paynowReference]) !== before) await store.save(order);
  return order;
}

function publicView(o) {
  return { reference: o.reference, status: o.status, total: o.total, method: o.method, fulfilment: o.fulfilment,
    lines: o.lines.map(l => ({ name: l.name, qty: l.qty })) };
}

// Same request the SDK makes, but errors are logged without the request body (which holds customer details).
async function initiate(pn, payment, method, phone) {
  if (payment.items.length() <= 0 || payment.total() <= 0) throw new Error('empty payment');
  const mobile = method !== 'web';
  const data = mobile ? pn.buildMobile(payment, phone, method) : pn.build(payment);
  const url = mobile ? 'https://www.paynow.co.zw/interface/remotetransaction' : 'https://www.paynow.co.zw/interface/initiatetransaction';
  const res = await axios({ method: 'POST', url, data, timeout: 20000, maxRedirects: 0, maxContentLength: 20000,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
  return pn.parse(res.data);
}

// ---------- app ----------
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', TRUST_HOPS);

if (PROD) {
  app.use((req, res, next) => (req.secure ? next() : res.redirect(301, PUBLIC_URL + req.originalUrl)));
}

app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", 'https://fonts.googleapis.com'],
      fontSrc: ['https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
      objectSrc: ["'none'"],
      ...(PROD ? { upgradeInsecureRequests: [] } : {}),
    },
  },
  strictTransportSecurity: PROD ? { maxAge: 63072000, includeSubDomains: true, preload: true } : false,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  crossOriginEmbedderPolicy: false,
}));
app.use((req, res, next) => { res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()'); next(); });

const apiLimiter = rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: 'draft-7', legacyHeaders: false });
const checkoutLimiter = rateLimit({ windowMs: 10 * 60_000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false,
  message: { error: 'Too many checkout attempts. Please wait a few minutes and try again.' } });
app.use('/api/', apiLimiter);

// Only accept JSON from our own pages: blocks cross-site form posts and other origins.
function sameOrigin(req, res, next) {
  const origin = req.get('origin');
  if (origin && origin !== PUBLIC_URL) return res.status(403).json({ error: 'Forbidden.' });
  if (!req.is('application/json')) return res.status(415).json({ error: 'Unsupported request.' });
  next();
}

app.get('/api/products', (req, res) => {
  res.set('Cache-Control', 'public, max-age=300');
  res.json({
    deliveryCents: C.DELIVERY_CENTS, freeDeliveryFromCents: C.FREE_DELIVERY_FROM_CENTS,
    products: Object.entries(C.PRODUCTS).map(([id, p]) => ({ id, name: p.name, unit: p.unit, cents: p.cents })),
    testMode: TEST_MODE,
  });
});

const phoneLimiter = rateLimit({ windowMs: 60 * 60_000, limit: 4, standardHeaders: 'draft-7', legacyHeaders: false,
  keyGenerator: req => 'phone:' + String(req.body?.customer?.phone || '').replace(/\D/g, '').slice(-9),
  message: { error: 'Too many payment requests for this number. Please wait and try again later.' } });
const MAX_OPEN_ORDERS = 300;

app.post('/api/checkout', checkoutLimiter, sameOrigin, express.json({ limit: '8kb', strict: true }), phoneLimiter, async (req, res) => {
  let o;
  try { o = validateCheckout(req.body); }
  catch (e) { return res.status(400).json({ error: e instanceof BadRequest ? e.message : 'Invalid request.' }); }
  if (store.countOpen() >= MAX_OPEN_ORDERS) return res.status(503).json({ error: 'The shop is very busy right now. Please try again in a few minutes.' });

  const id = crypto.randomUUID();
  const token = crypto.randomBytes(32).toString('base64url');
  let reference;
  do { reference = 'PB-' + Date.now().toString(36).toUpperCase() + '-' + crypto.randomBytes(6).toString('hex').toUpperCase(); }
  while (store.findByReference(reference));
  const order = {
    id, reference, tokenHash: crypto.createHash('sha256').update(token).digest('hex'),
    status: 'pending', createdAt: new Date().toISOString(), ...o,
  };

  // A fresh Paynow client per request so the per-order return URL can't leak between concurrent requests.
  const pn = new Paynow(INTEGRATION_ID, INTEGRATION_KEY);
  pn.resultUrl = paynow.resultUrl;
  pn.returnUrl = `${PUBLIC_URL}/?order=${id}`;
  const authEmail = TEST_MODE ? MERCHANT_EMAIL : o.customer.email;
  const payment = pn.createPayment(reference, authEmail);
  const summary = o.lines.map(l => `${l.qty}x ${l.name}`).join(', ') + (o.delivery ? ', delivery' : '');
  payment.add(clean('Prime Baking: ' + summary, 240), o.total / 100);

  await store.save(order); // saved first so an early Paynow callback can find it

  const giveUp = async (msg, log) => {
    console.warn(`Payment not started for ${reference}: ${log}`);
    order.status = 'failed'; await store.save(order);
    return res.status(502).json({ error: msg });
  };
  let resp;
  try { resp = await initiate(pn, payment, o.method, o.customer.phone); }
  catch (e) { return giveUp('The payment service did not respond. Please try again in a moment.', e.code || e.message); }
  if (!resp || !resp.success || !isPaynowUrl(resp.pollUrl)) return giveUp('The payment could not be started. Check your details and try again.', clean((resp && resp.error) || 'no response', 200));
  if (o.method === 'web' && !isPaynowUrl(resp.redirectUrl)) return giveUp('The payment could not be started. Please try again.', 'bad redirect url');

  order.pollUrl = resp.pollUrl;
  await store.save(order);
  res.status(201).json({
    orderId: id, token, reference,
    redirectUrl: o.method === 'web' ? resp.redirectUrl : undefined,
    instructions: o.method !== 'web' ? clean(resp.instructions || 'Check your phone and enter your PIN to approve the payment.', 300) : undefined,
    total: o.total,
  });
});

// Paynow calls this when a transaction changes. We verify the signature, then confirm by polling
// Paynow ourselves; the callback alone never marks anything paid.
app.post('/api/paynow/result', express.text({ type: '*/*', limit: '8kb' }), async (req, res) => {
  res.status(200).end();
  const f = parseSigned(req.body);
  if (!f) { console.warn('Rejected status update with bad signature from', req.ip); return; }
  const order = store.findByReference(f.reference);
  if (!order) return;
  if (!order.pollUrl && isPaynowUrl(f.pollurl)) order.pollUrl = f.pollurl; // signed by Paynow, arrived before our save
  await pollPaynow(order);
});

app.get('/api/orders/:id', async (req, res) => {
  res.set('Cache-Control', 'no-store');
  const order = /^[0-9a-f-]{36}$/.test(req.params.id) ? store.get(req.params.id) : undefined;
  const token = req.get('x-order-token') || '';
  const ok = order && safeEqual(crypto.createHash('sha256').update(token).digest('hex'), order.tokenHash);
  if (!ok) return res.status(404).json({ error: 'Order not found.' });
  const fresh = Date.now() - (order.lastPolledAt || 0) > 4000;
  const young = Date.now() - Date.parse(order.createdAt) < 24 * 3600_000;
  if (order.status === 'pending' && fresh && young) await pollPaynow(order);
  res.json(publicView(order));
});

app.use('/api', (req, res) => res.status(404).json({ error: 'Not found.' }));

app.use(express.static(path.join(__dirname, 'public'), {
  dotfiles: 'deny', index: 'index.html',
  setHeaders: (res, file) => res.setHeader('Cache-Control', file.endsWith('.html') ? 'no-cache' : 'public, max-age=604800'),
}));

app.use((err, req, res, next) => {
  if (res.headersSent) return;
  const status = err.status && err.status < 500 ? err.status : 500;
  if (status === 500) console.error(err);
  res.status(status).json({ error: status === 500 ? 'Something went wrong.' : 'Invalid request.' });
});

// Housekeeping: drop unpaid orders after 48 hours.
setInterval(() => store.prune(48 * 3600_000), 3600_000).unref();
store.prune(48 * 3600_000);

app.listen(PORT, () => console.log(`Prime Baking running on port ${PORT}${TEST_MODE ? ' (Paynow TEST MODE)' : ''}`));
