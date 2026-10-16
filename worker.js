/**
 * ZAVO Cloudflare Worker — hardened baseline
 * Required bindings/secrets:
 *   DB                  D1 database
 *   PAYSTACK_SECRET_KEY Cloudflare secret
 *   ALLOWED_ORIGINS     comma-separated exact HTTPS storefront origins
 *   PUBLIC_SITE_URL     canonical storefront origin, e.g. https://zavo.example
 *
 * Apply worker_schema.sql before deploying. Never put secrets in frontend code.
 * For best cookie compatibility, serve the API and storefront on the same site
 * (e.g. api.example.com and www.example.com), and use HTTPS.
 */

const PAYSTACK_API = "https://api.paystack.co";
const PUBLIC_CONTACT_EMAIL = "zavo.org@proton.me";
const SESSION_COOKIE = "__Host-zavo_session";
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7;

// FIX: The reported Cloudflare runtime rejects PBKDF2 iterations above 100000.
const PBKDF2_ITERATIONS = 100000;

const MAX_JSON_BYTES = 256 * 1024;
const ALLOWED_PAYMENT_METHODS = new Set([
  "card", "mpesa", "airtel_money", "apple_pay", "bank_transfer"
]);

function jsonResponse(data, status = 200, headers = {}) {
  const responseHeaders = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
  });

  for (const [key, value] of Object.entries(headers || {})) {
    if (key.toLowerCase() === "set-cookie" && Array.isArray(value)) {
      for (const cookie of value) {
        responseHeaders.append("Set-Cookie", cookie);
      }
    } else if (value !== undefined && value !== null) {
      responseHeaders.set(key, String(value));
    }
  }

  return new Response(JSON.stringify(data), {
    status,
    headers: responseHeaders,
  });
}

function getAllowedOrigins(env) {
  return String(env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((value) => value.trim().replace(/\/$/, ""))
    .filter(Boolean);
}

function corsHeaders(request, env) {
  const origin = request.headers.get("Origin");
  const allowed = getAllowedOrigins(env);

  const headers = {
    "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-CSRF-Token",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };

  if (origin && allowed.includes(origin.replace(/\/$/, ""))) {
    headers["Access-Control-Allow-Origin"] = origin;
  }

  return headers;
}

function respond(request, env, data, status = 200, extraHeaders = {}) {
  return jsonResponse(data, status, {
    ...corsHeaders(request, env),
    ...extraHeaders,
  });
}

function cookieHeader(value, maxAge = SESSION_TTL_SECONDS) {
  return `${SESSION_COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=${maxAge}`;
}

function clearSessionCookie() {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=0`;
}

function randomHex(byteLength = 32) {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));

  return Array.from(
    bytes,
    (byte) => byte.toString(16).padStart(2, "0")
  ).join("");
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );

  return Array.from(
    new Uint8Array(digest),
    (byte) => byte.toString(16).padStart(2, "0")
  ).join("");
}

/**
 * Password hash format:
 * pbkdf2_sha256$iterations$saltHex$hashHex
 *
 * Cloudflare compatibility fix:
 * use PBKDF2_ITERATIONS, which is set to 100000 above.
 */
async function hashPassword(password, saltHex = randomHex(16)) {
  if (typeof password !== "string") {
    throw new Error("Password must be a string.");
  }

  if (!/^[a-f0-9]{32}$/i.test(saltHex)) {
    throw new Error("Invalid password salt.");
  }

  const salt = Uint8Array.from(
    saltHex.match(/.{2}/g),
    (byte) => parseInt(byte, 16)
  );

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    key,
    256
  );

  const hashHex = Array.from(
    new Uint8Array(bits),
    (byte) => byte.toString(16).padStart(2, "0")
  ).join("");

  return `pbkdf2_sha256$${PBKDF2_ITERATIONS}$${saltHex}$${hashHex}`;
}

/**
 * Verifies passwords using the iteration count stored in the hash.
 *
 * This runtime supports at most 100000 iterations, according to the
 * reported error. Hashes with unsupported iteration counts return false
 * instead of causing an unhandled Worker exception.
 */
async function verifyPassword(password, encoded) {
  if (typeof password !== "string" || typeof encoded !== "string") {
    return false;
  }

  const parts = encoded.split("$");

  if (parts.length !== 4 || parts[0] !== "pbkdf2_sha256") {
    return false;
  }

  const iterations = Number(parts[1]);

  // FIX: reject unsupported counts before calling deriveBits.
  if (
    !Number.isSafeInteger(iterations) ||
    iterations < 100000 ||
    iterations > PBKDF2_ITERATIONS
  ) {
    return false;
  }

  const saltHex = parts[2];
  const expectedHex = parts[3];

  if (
    !/^[a-f0-9]{32}$/i.test(saltHex) ||
    !/^[a-f0-9]{64}$/i.test(expectedHex)
  ) {
    return false;
  }

  const salt = Uint8Array.from(
    saltHex.match(/.{2}/g),
    (byte) => parseInt(byte, 16)
  );

  try {
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations,
        hash: "SHA-256",
      },
      key,
      256
    );

    const actual = Array.from(
      new Uint8Array(bits),
      (byte) => byte.toString(16).padStart(2, "0")
    ).join("");

    return constantTimeEqual(
      actual.toLowerCase(),
      expectedHex.toLowerCase()
    );
  } catch (error) {
    console.error("Password verification failed:", String(error));
    return false;
  }
}

function constantTimeEqual(a, b) {
  if (
    typeof a !== "string" ||
    typeof b !== "string" ||
    a.length !== b.length
  ) {
    return false;
  }

  let result = 0;

  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}

function readCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";

  for (const part of cookie.split(";")) {
    const index = part.indexOf("=");

    if (index < 0) continue;

    if (part.slice(0, index).trim() === name) {
      return part.slice(index + 1).trim();
    }
  }

  return null;
}

async function readJson(request) {
  const contentType = request.headers.get("Content-Type") || "";

  if (!contentType.toLowerCase().includes("application/json")) {
    throw new HttpError(
      415,
      "Send data using Content-Type: application/json."
    );
  }

  const length = Number(request.headers.get("Content-Length") || 0);

  if (length > MAX_JSON_BYTES) {
    throw new HttpError(413, "Request body is too large.");
  }

  const raw = await request.text();

  if (new TextEncoder().encode(raw).byteLength > MAX_JSON_BYTES) {
    throw new HttpError(413, "Request body is too large.");
  }

  try {
    const data = JSON.parse(raw);

    if (!data || typeof data !== "object" || Array.isArray(data)) {
      throw new Error("Invalid object");
    }

    return data;
  } catch {
    throw new HttpError(400, "Invalid JSON request body.");
  }
}

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function cleanString(value, maxLength = 500) {
  if (typeof value !== "string") return "";
  return value.trim().slice(0, maxLength);
}

function validEmail(value) {
  return (
    typeof value === "string" &&
    value.length <= 254 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)
  );
}

function normalizeKenyanPhone(value) {
  const digits = String(value || "").replace(/\D/g, "");

  if (digits.startsWith("254") && digits.length === 12) {
    return `+${digits}`;
  }

  if (digits.startsWith("0") && digits.length === 10) {
    return `+254${digits.slice(1)}`;
  }

  if (digits.length === 9 && /^[17]/.test(digits)) {
    return `+254${digits}`;
  }

  return null;
}

async function paystackRequest(env, endpoint, options = {}) {
  if (!env.PAYSTACK_SECRET_KEY) {
    throw new HttpError(503, "Payment processing is not configured.");
  }

  const response = await fetch(`${PAYSTACK_API}${endpoint}`, {
    ...options,
    headers: {
      Authorization: `Bearer ${env.PAYSTACK_SECRET_KEY}`,
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok || data.status !== true) {
    console.error(
      "Paystack API error",
      response.status,
      data.message || "Unknown error"
    );

    throw new HttpError(
      502,
      "The payment provider could not complete the request."
    );
  }

  return data.data;
}

async function verifyPaystackTransaction(env, reference) {
  return paystackRequest(
    env,
    `/transaction/verify/${encodeURIComponent(reference)}`
  );
}

async function verifyWebhookSignature(rawBody, signature, secret) {
  if (!signature || !secret) return false;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-512" },
    false,
    ["sign"]
  );

  const digest = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(rawBody)
  );

  const expected = Array.from(
    new Uint8Array(digest),
    (byte) => byte.toString(16).padStart(2, "0")
  ).join("");

  return constantTimeEqual(signature.toLowerCase(), expected);
}

async function createSession(env, userId) {
  const token = randomHex(32);
  const tokenHash = await sha256Hex(token);

  await env.DB.prepare(
    "INSERT INTO sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, datetime('now', '+7 days'), CURRENT_TIMESTAMP)"
  ).bind(tokenHash, userId).run();

  return token;
}

async function getSessionUser(request, env) {
  const token = readCookie(request, SESSION_COOKIE);

  if (!token) return null;

  const tokenHash = await sha256Hex(token);

  const row = await env.DB.prepare(`
    SELECT u.id, u.email, u.name, u.role,
           v.id AS vendor_id, v.status AS vendor_status, s.expires_at
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    LEFT JOIN vendors v ON v.user_id = u.id
    WHERE s.token_hash = ?
      AND s.expires_at > CURRENT_TIMESTAMP
      AND u.is_active = 1
    LIMIT 1
  `).bind(tokenHash).first();

  return row || null;
}

function requireRole(user, roles) {
  if (!user) {
    throw new HttpError(401, "Please sign in to continue.");
  }

  if (!roles.includes(user.role)) {
    throw new HttpError(
      403,
      "You are not authorized to perform this action."
    );
  }
}

function requireSameOrigin(request, env) {
  const origin = request.headers.get("Origin");

  if (!origin) return;

  const normalized = origin.replace(/\/$/, "");

  if (!getAllowedOrigins(env).includes(normalized)) {
    throw new HttpError(403, "This origin is not allowed.");
  }
}

async function requireCsrf(request, env) {
  requireSameOrigin(request, env);

  const supplied = request.headers.get("X-CSRF-Token") || "";
  const expected = readCookie(request, "zavo_csrf");

  if (
    !expected ||
    !supplied ||
    !constantTimeEqual(supplied, expected)
  ) {
    throw new HttpError(
      403,
      "Security token missing or invalid. Refresh the page and try again."
    );
  }
}

async function markOrderPaid(env, reference, transaction) {
  const order = await env.DB.prepare(
    "SELECT id, total_amount, payment_status, fulfilment_status FROM orders WHERE id = ? LIMIT 1"
  ).bind(reference).first();

  if (!order) {
    return { success: false, error: "Order not found." };
  }

  const expectedAmount = Math.round(Number(order.total_amount) * 100);
  const actualAmount = Number(transaction.amount);
  const metadataOrderId =
    transaction.metadata && transaction.metadata.order_id;

  if (
    transaction.status !== "success" ||
    transaction.reference !== reference ||
    String(transaction.currency || "").toUpperCase() !== "KES" ||
    !Number.isSafeInteger(actualAmount) ||
    actualAmount !== expectedAmount ||
    (metadataOrderId && metadataOrderId !== reference)
  ) {
    return {
      success: false,
      error: "Payment does not match this order.",
    };
  }

  if (order.payment_status !== "success") {
    await env.DB.prepare(
      "UPDATE orders SET payment_status = 'success' WHERE id = ? AND payment_status != 'success'"
    ).bind(reference).run();
  }

  if (String(order.fulfilment_status || "").toLowerCase() === "delivered") {
    await awardCommissionIfEligible(env, reference);
  }

  return { success: true, order_id: reference };
}

async function awardCommissionIfEligible(env, orderId) {
  const attribution = await env.DB.prepare(`
    SELECT orf.reseller_user_id, o.subtotal, o.total_amount,
           o.payment_status, o.fulfilment_status, ra.commission_rate
    FROM order_referrals orf
    JOIN orders o ON o.id = orf.order_id
    JOIN reseller_accounts ra ON ra.user_id = orf.reseller_user_id
    WHERE orf.order_id = ? AND ra.status = 'approved'
    LIMIT 1
  `).bind(orderId).first();

  if (
    !attribution ||
    attribution.payment_status !== "success" ||
    String(attribution.fulfilment_status).toLowerCase() !== "delivered"
  ) {
    return;
  }

  const amount = Math.round(
    Number(attribution.subtotal || 0) *
    Number(attribution.commission_rate) /
    100 *
    100
  ) / 100;

  if (!Number.isFinite(amount) || amount <= 0) return;

  const existingCommission = await env.DB.prepare(
    "SELECT id FROM reseller_commissions WHERE order_id = ? LIMIT 1"
  ).bind(orderId).first();

  if (existingCommission) return;

  await env.DB.prepare(`
    INSERT INTO reseller_commissions
      (id, order_id, reseller_user_id, amount, currency, status, created_at)
    SELECT ?, ?, ?, ?, 'KES', 'pending', CURRENT_TIMESTAMP
    WHERE NOT EXISTS (
      SELECT 1 FROM reseller_commissions WHERE order_id = ?
    )
  `).bind(
    `com_${crypto.randomUUID().replace(/-/g, "")}`,
    orderId,
    attribution.reseller_user_id,
    amount,
    orderId
  ).run();
}

async function verifyAndMarkOrder(env, reference) {
  const transaction = await verifyPaystackTransaction(env, reference);
  return markOrderPaid(env, reference, transaction);
}

function validateProductText(value, label, maxLength) {
  const text = cleanString(value, maxLength);

  if (!text) {
    throw new HttpError(400, `${label} is required.`);
  }

  if (
    /(https?:\/\/|www\.|[\w.-]+\.[a-z]{2,})/i.test(text) ||
    /(\+?\d[\d\s()-]{8,}\d)/.test(text)
  ) {
    throw new HttpError(
      400,
      `URLs and phone numbers are not allowed in ${label.toLowerCase()}.`
    );
  }

  return text;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();
    const cors = corsHeaders(request, env);

    if (method === "OPTIONS") {
      const origin = request.headers.get("Origin");

      if (
        origin &&
        !getAllowedOrigins(env).includes(origin.replace(/\/$/, ""))
      ) {
        return new Response(null, { status: 403 });
      }

      return new Response(null, {
        status: 204,
        headers: cors,
      });
    }

    try {
      if (!env.DB) {
        throw new HttpError(503, "Database is not configured.");
      }

      if (path === "/api/health" && method === "GET") {
        return respond(request, env, {
          success: true,
          service: "zavo-api",
        });
      }

      if (path === "/api/auth/csrf" && method === "GET") {
        requireSameOrigin(request, env);

        const token = randomHex(24);

        return respond(
          request,
          env,
          { success: true, csrfToken: token },
          200,
          {
            "Set-Cookie": `zavo_csrf=${token}; Path=/; Secure; SameSite=None; Max-Age=3600`,
          }
        );
      }

      // Customer registration.
      if (path === "/api/auth/register" && method === "POST") {
        requireSameOrigin(request, env);

        const body = await readJson(request);
        const name = cleanString(body.name, 100);
        const email = cleanString(body.email, 254).toLowerCase();
        const password =
          typeof body.password === "string" ? body.password : "";

        if (
          name.length < 2 ||
          !validEmail(email) ||
          password.length < 12 ||
          password.length > 128
        ) {
          throw new HttpError(
            400,
            "Provide a valid name and email, and a password of 12–128 characters."
          );
        }

        const existing = await env.DB.prepare(
          "SELECT id FROM users WHERE email = ? LIMIT 1"
        ).bind(email).first();

        if (existing) {
          throw new HttpError(
            409,
            "An account with this email already exists."
          );
        }

        const userId = `usr_${crypto.randomUUID().replace(/-/g, "")}`;
        const passwordHash = await hashPassword(password);

        await env.DB.prepare(`
          INSERT INTO users
            (id, name, email, password_hash, role, is_active, created_at)
          VALUES (?, ?, ?, ?, 'customer', 1, CURRENT_TIMESTAMP)
        `).bind(userId, name, email, passwordHash).run();

        const session = await createSession(env, userId);
        const csrf = randomHex(24);

        return respond(
          request,
          env,
          {
            success: true,
            user: {
              id: userId,
              name,
              email,
              role: "customer",
            },
            redirectTo: "/",
          },
          201,
          {
            "Set-Cookie": [
              cookieHeader(session),
              `zavo_csrf=${csrf}; Path=/; Secure; SameSite=None; Max-Age=3600`,
            ],
          }
        );
      }

      if (path === "/api/auth/login" && method === "POST") {
        requireSameOrigin(request, env);

        const body = await readJson(request);
        const email = cleanString(body.email, 254).toLowerCase();
        const password =
          typeof body.password === "string" ? body.password : "";

        if (!validEmail(email) || !password || password.length > 128) {
          throw new HttpError(
            400,
            "Enter a valid email address and password."
          );
        }

        const user = await env.DB.prepare(`
          SELECT id, name, email, password_hash, role, is_active
          FROM users
          WHERE email = ?
          LIMIT 1
        `).bind(email).first();

        if (
          !user ||
          Number(user.is_active) !== 1 ||
          !(await verifyPassword(password, user.password_hash))
        ) {
          throw new HttpError(401, "Email or password is incorrect.");
        }

        const session = await createSession(env, user.id);
        const csrf = randomHex(24);

        const vendor = await env.DB.prepare(
          "SELECT id, status FROM vendors WHERE user_id = ? LIMIT 1"
        ).bind(user.id).first();

        const redirectTo =
          user.role === "admin"
            ? "/admin.html"
            : user.role === "vendor"
              ? "/vendor.html"
              : "/";

        return respond(
          request,
          env,
          {
            success: true,
            user: {
              id: user.id,
              name: user.name,
              email: user.email,
              role: user.role,
              vendor_id: vendor?.id || null,
              vendor_status: vendor?.status || null,
            },
            redirectTo,
          },
          200,
          {
            "Set-Cookie": [
              cookieHeader(session),
              `zavo_csrf=${csrf}; Path=/; Secure; SameSite=None; Max-Age=3600`,
            ],
          }
        );
      }

      if (path === "/api/auth/me" && method === "GET") {
        const user = await getSessionUser(request, env);

        if (!user) {
          throw new HttpError(401, "You are not signed in.");
        }

        let effectiveRole = user.role;

        if (user.role === "customer") {
          const reseller = await env.DB.prepare(
            "SELECT status FROM reseller_accounts WHERE user_id = ? LIMIT 1"
          ).bind(user.id).first();

          if (reseller && reseller.status === "approved") {
            effectiveRole = "reseller";
          }
        }

        return respond(request, env, {
          success: true,
          user: {
            id: user.id,
            name: user.name,
            email: user.email,
            role: effectiveRole,
            vendor_id: user.vendor_id || null,
          },
        });
      }

      if (path === "/api/auth/logout" && method === "POST") {
        await requireCsrf(request, env);

        const token = readCookie(request, SESSION_COOKIE);

        if (token) {
          await env.DB.prepare(
            "DELETE FROM sessions WHERE token_hash = ?"
          ).bind(await sha256Hex(token)).run();
        }

        return respond(
          request,
          env,
          { success: true },
          200,
          {
            "Set-Cookie": [
              clearSessionCookie(),
              "zavo_csrf=; Path=/; Secure; SameSite=None; Max-Age=0",
            ],
          }
        );
      }

      // Paystack webhook.
      if (path === "/api/paystack/webhook" && method === "POST") {
        if (!env.PAYSTACK_SECRET_KEY) {
          throw new HttpError(
            503,
            "Payment processing is not configured."
          );
        }

        const rawBody = await request.text();

        if (
          new TextEncoder().encode(rawBody).byteLength > MAX_JSON_BYTES
        ) {
          throw new HttpError(413, "Webhook body too large.");
        }

        const valid = await verifyWebhookSignature(
          rawBody,
          request.headers.get("x-paystack-signature"),
          env.PAYSTACK_SECRET_KEY
        );

        if (!valid) {
          throw new HttpError(401, "Invalid webhook signature.");
        }

        let event;

        try {
          event = JSON.parse(rawBody);
        } catch {
          throw new HttpError(400, "Invalid webhook JSON.");
        }

        if (
          event.event === "charge.success" &&
          event.data &&
          event.data.reference
        ) {
          const result = await verifyAndMarkOrder(
            env,
            String(event.data.reference)
          );

          if (!result.success) {
            console.error(
              "Paystack webhook transaction did not match order",
              result.error
            );

            return jsonResponse(
              { received: true, payment_updated: false },
              200
            );
          }
        }

        return jsonResponse({ received: true }, 200);
      }

      if (path === "/api/products" && method === "GET") {
        const { results } = await env.DB.prepare(`
          SELECT id, title, description, price, stock, category, images, created_at
          FROM products
          WHERE status = 'active' AND stock > 0
          ORDER BY created_at DESC
          LIMIT 200
        `).all();

        return respond(request, env, {
          success: true,
          products: results || [],
        });
      }

      if (path === "/api/checkout" && method === "POST") {
        requireSameOrigin(request, env);

        const body = await readJson(request);
        const customerName = cleanString(body.customer_name, 100);
        const customerPhone = normalizeKenyanPhone(body.customer_phone);
        const customerEmail = cleanString(body.customer_email, 254).toLowerCase();
        const county = cleanString(body.county, 80);
        const town = cleanString(body.town, 100);
        const deliveryAddress = cleanString(body.delivery_address, 500);
        const items = body.items;
        const paymentMethod = body.payment_method;

        if (
          !customerName ||
          !customerPhone ||
          !validEmail(customerEmail) ||
          !county ||
          !town ||
          !deliveryAddress ||
          !Array.isArray(items) ||
          items.length < 1 ||
          items.length > 50
        ) {
          throw new HttpError(
            400,
            "Provide valid customer, delivery, and cart details."
          );
        }

        if (!ALLOWED_PAYMENT_METHODS.has(paymentMethod)) {
          throw new HttpError(400, "Select a supported payment method.");
        }

        if (!env.PAYSTACK_SECRET_KEY) {
          throw new HttpError(503, "Online payments are not configured.");
        }

        const referralCode = cleanString(
          body.referral_code || body.ref || "",
          80
        );

        let attributedReseller = null;

        if (referralCode) {
          if (!/^[A-Za-z0-9_-]{3,80}$/.test(referralCode)) {
            throw new HttpError(400, "Invalid referral code.");
          }

          attributedReseller = await env.DB.prepare(`
            SELECT rc.user_id, rc.code
            FROM referral_codes rc
            JOIN reseller_accounts ra ON ra.user_id = rc.user_id
            WHERE rc.code = ? AND ra.status = 'approved'
            LIMIT 1
          `).bind(referralCode).first();

          if (!attributedReseller) {
            throw new HttpError(
              400,
              "This referral code is not active."
            );
          }
        }

        const quantities = new Map();

        for (const item of items) {
          const id = cleanString(item && item.id, 100);
          const quantity = Number(item && item.quantity);

          if (
            !id ||
            !Number.isSafeInteger(quantity) ||
            quantity < 1 ||
            quantity > 100
          ) {
            throw new HttpError(
              400,
              "The cart contains an invalid product or quantity."
            );
          }

          quantities.set(id, (quantities.get(id) || 0) + quantity);

          if (quantities.get(id) > 100) {
            throw new HttpError(
              400,
              "Maximum quantity per product is 100."
            );
          }
        }

        let subtotal = 0;
        const verifiedItems = [];

        for (const [id, quantity] of quantities.entries()) {
          const product = await env.DB.prepare(`
            SELECT id, title, price, stock, vendor_id
            FROM products
            WHERE id = ? AND status = 'active'
            LIMIT 1
          `).bind(id).first();

          if (!product) {
            throw new HttpError(
              400,
              "A product in your cart is no longer available."
            );
          }

          if (
            !Number.isSafeInteger(Number(product.stock)) ||
            Number(product.stock) < quantity
          ) {
            throw new HttpError(
              409,
              `Insufficient stock for ${cleanString(product.title, 100)}.`
            );
          }

          const price = Number(product.price);

          if (
            !Number.isFinite(price) ||
            price <= 0 ||
            price > 100000000
          ) {
            throw new HttpError(400, "A product has an invalid price.");
          }

          subtotal += price * quantity;

          verifiedItems.push({
            id: product.id,
            title: product.title,
            price,
            quantity,
            vendor_id: product.vendor_id,
          });
        }

        if (
          !Number.isFinite(subtotal) ||
          subtotal <= 0 ||
          subtotal > 100000000
        ) {
          throw new HttpError(400, "Invalid order total.");
        }

        const shippingCost =
          county.toLowerCase() === "nairobi" ? 250 : 450;

        const totalAmount =
          Math.round((subtotal + shippingCost) * 100) / 100;

        const reference =
          `ord_${crypto.randomUUID().replace(/-/g, "")}`;

        await env.DB.prepare(`
          INSERT INTO orders (
            id, customer_name, customer_phone, customer_email, county, town,
            delivery_address, items_json, subtotal, shipping_cost, total_amount,
            payment_method, payment_status, fulfilment_status, shipping_address
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_payment', 'pending', ?)
        `).bind(
          reference,
          customerName,
          customerPhone,
          customerEmail,
          county,
          town,
          deliveryAddress,
          JSON.stringify(verifiedItems),
          subtotal,
          shippingCost,
          totalAmount,
          paymentMethod,
          deliveryAddress
        ).run();

        if (attributedReseller) {
          await env.DB.prepare(`
            INSERT INTO order_referrals
              (order_id, reseller_user_id, referral_code, created_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
          `).bind(
            reference,
            attributedReseller.user_id,
            attributedReseller.code
          ).run();
        }

        const amount = String(Math.round(totalAmount * 100));

        if (
          paymentMethod === "mpesa" ||
          paymentMethod === "airtel_money"
        ) {
          const provider =
            paymentMethod === "mpesa" ? "mpesa" : "atl";

          const charge = await paystackRequest(env, "/charge", {
            method: "POST",
            body: JSON.stringify({
              email: customerEmail,
              amount,
              currency: "KES",
              reference,
              mobile_money: {
                phone: customerPhone,
                provider,
              },
              metadata: {
                order_id: reference,
                payment_method: paymentMethod,
              },
            }),
          });

          return respond(
            request,
            env,
            {
              success: true,
              payment_mode: "mobile_money",
              order_id: reference,
              total_amount: totalAmount,
              payment_status: charge.status || "pending",
              display_text:
                charge.display_text ||
                "Follow the payment instructions sent to your phone.",
            },
            201
          );
        }

        const channels = {
          card: ["card"],
          apple_pay: ["card", "apple_pay"],
          bank_transfer: ["bank_transfer"],
        }[paymentMethod];

        let siteUrl;

        try {
          const parsedSiteUrl = new URL(
            String(env.PUBLIC_SITE_URL || "")
          );

          if (
            parsedSiteUrl.protocol !== "https:" ||
            parsedSiteUrl.username ||
            parsedSiteUrl.password ||
            parsedSiteUrl.pathname !== "/" ||
            parsedSiteUrl.search ||
            parsedSiteUrl.hash
          ) {
            throw new Error("Invalid site origin");
          }

          siteUrl = parsedSiteUrl.origin;

          if (!getAllowedOrigins(env).includes(siteUrl)) {
            throw new Error("Site origin not allowlisted");
          }
        } catch {
          throw new HttpError(
            503,
            "PUBLIC_SITE_URL must be an HTTPS origin included in ALLOWED_ORIGINS."
          );
        }

        const transaction = await paystackRequest(
          env,
          "/transaction/initialize",
          {
            method: "POST",
            body: JSON.stringify({
              email: customerEmail,
              amount,
              currency: "KES",
              reference,
              channels,
              callback_url:
                `${siteUrl}/checkout.html?payment_return=1&reference=${encodeURIComponent(reference)}`,
              metadata: {
                order_id: reference,
                payment_method: paymentMethod,
                customer_name: customerName,
              },
            }),
          }
        );

        return respond(
          request,
          env,
          {
            success: true,
            payment_mode: "popup",
            order_id: reference,
            total_amount: totalAmount,
            access_code: transaction.access_code,
            authorization_url: transaction.authorization_url,
          },
          201
        );
      }

      if (path === "/api/payment/verify" && method === "GET") {
        const reference = cleanString(
          url.searchParams.get("reference"),
          100
        );

        if (!/^ord_[a-f0-9]{32}$/i.test(reference)) {
          throw new HttpError(400, "Invalid payment reference.");
        }

        const order = await env.DB.prepare(
          "SELECT id, total_amount, payment_status FROM orders WHERE id = ? LIMIT 1"
        ).bind(reference).first();

        if (!order) {
          throw new HttpError(404, "Order not found.");
        }

        if (order.payment_status === "success") {
          return respond(request, env, {
            success: true,
            paid: true,
            order_id: reference,
            payment_status: "success",
          });
        }

        try {
          const result = await verifyAndMarkOrder(env, reference);

          if (result.success) {
            return respond(request, env, {
              success: true,
              paid: true,
              order_id: reference,
              payment_status: "success",
            });
          }

          const transaction = await verifyPaystackTransaction(
            env,
            reference
          );

          return respond(request, env, {
            success: true,
            paid: false,
            order_id: reference,
            payment_status: transaction.status || "pending",
          });
        } catch (error) {
          if (error instanceof HttpError && error.status < 500) {
            throw error;
          }

          return respond(request, env, {
            success: true,
            paid: false,
            order_id: reference,
            payment_status: "pending",
          });
        }
      }

      // Public referral click tracking.
      if (path === "/api/referral/click" && method === "GET") {
        const code = cleanString(url.searchParams.get("ref"), 80);

        if (!/^[A-Za-z0-9_-]{3,80}$/.test(code)) {
          throw new HttpError(400, "Invalid referral code.");
        }

        const referral = await env.DB.prepare(`
          SELECT rc.user_id, rc.code
          FROM referral_codes rc
          JOIN reseller_accounts ra ON ra.user_id = rc.user_id
          WHERE rc.code = ? AND ra.status = 'approved'
          LIMIT 1
        `).bind(code).first();

        if (!referral) {
          return respond(request, env, {
            success: true,
            tracked: false,
          });
        }

        const ip =
          request.headers.get("CF-Connecting-IP") || "unknown";

        const userAgent = cleanString(
          request.headers.get("User-Agent") || "",
          300
        );

        const day = new Date().toISOString().slice(0, 10);

        if (
          !env.REFERRAL_IP_SALT ||
          String(env.REFERRAL_IP_SALT).length < 32
        ) {
          throw new HttpError(
            503,
            "Referral click tracking is not configured."
          );
        }

        const ipHash = await sha256Hex(
          `${env.REFERRAL_IP_SALT}:${ip}`
        );

        const existing = await env.DB.prepare(`
          SELECT id FROM referral_clicks
          WHERE referral_code = ? AND ip_hash = ? AND click_day = ?
          LIMIT 1
        `).bind(code, ipHash, day).first();

        if (!existing) {
          await env.DB.prepare(`
            INSERT INTO referral_clicks (
              id, reseller_user_id, referral_code, ip_hash,
              user_agent, click_day, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
          `).bind(
            `clk_${crypto.randomUUID().replace(/-/g, "")}`,
            referral.user_id,
            code,
            ipHash,
            userAgent,
            day
          ).run();
        }

        return respond(request, env, {
          success: true,
          tracked: true,
        });
      }

      if (path === "/api/reseller/apply" && method === "POST") {
        await requireCsrf(request, env);

        const user = await getSessionUser(request, env);

        requireRole(user, ["customer", "reseller", "admin"]);

        const existing = await env.DB.prepare(
          "SELECT status FROM reseller_accounts WHERE user_id = ? LIMIT 1"
        ).bind(user.id).first();

        if (existing && existing.status === "approved") {
          return respond(request, env, {
            success: true,
            status: "approved",
          });
        }

        if (existing) {
          throw new HttpError(
            409,
            `Your reseller application is ${existing.status}.`
          );
        }

        await env.DB.prepare(`
          INSERT INTO reseller_accounts
            (user_id, status, commission_rate, created_at, updated_at)
          VALUES (?, 'pending', 5.0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        `).bind(user.id).run();

        return respond(
          request,
          env,
          { success: true, status: "pending" },
          201
        );
      }

      if (path === "/api/reseller/dashboard" && method === "GET") {
        const user = await getSessionUser(request, env);

        requireRole(user, ["customer", "reseller", "admin"]);

        const account = await env.DB.prepare(`
          SELECT ra.status, rc.code
          FROM reseller_accounts ra
          LEFT JOIN referral_codes rc ON rc.user_id = ra.user_id
          WHERE ra.user_id = ?
          LIMIT 1
        `).bind(user.id).first();

        if (
          !account ||
          account.status !== "approved" ||
          !account.code
        ) {
          throw new HttpError(
            403,
            "Your reseller account is not approved yet. Apply for the reseller programme or contact ZAVO support."
          );
        }

        const clicks = await env.DB.prepare(
          "SELECT COUNT(*) AS total FROM referral_clicks WHERE reseller_user_id = ?"
        ).bind(user.id).first();

        const commissions = await env.DB.prepare(`
          SELECT
            COALESCE(SUM(CASE WHEN status IN ('pending', 'approved') THEN amount ELSE 0 END), 0) AS pending_total,
            COALESCE(SUM(CASE WHEN status = 'paid' THEN amount ELSE 0 END), 0) AS paid_total
          FROM reseller_commissions
          WHERE reseller_user_id = ?
        `).bind(user.id).first();

        return respond(request, env, {
          success: true,
          referral_code: account.code,
          clicks: Number(clicks?.total || 0),
          pending_commission: Number(commissions?.pending_total || 0),
          paid_commission: Number(commissions?.paid_total || 0),
          currency: "KES",
          status: account.status,
        });
      }

      if (path === "/api/admin/resellers" && method === "GET") {
        const user = await getSessionUser(request, env);

        requireRole(user, ["admin"]);

        const { results } = await env.DB.prepare(`
          SELECT
            ra.user_id, u.name, u.email, ra.status,
            ra.commission_rate, ra.created_at,
            rc.code AS referral_code
          FROM reseller_accounts ra
          JOIN users u ON u.id = ra.user_id
          LEFT JOIN referral_codes rc ON rc.user_id = ra.user_id
          ORDER BY ra.created_at DESC
          LIMIT 500
        `).all();

        return respond(request, env, {
          success: true,
          resellers: results || [],
        });
      }

      if (path === "/api/admin/resellers/approve" && method === "POST") {
        await requireCsrf(request, env);

        const user = await getSessionUser(request, env);

        requireRole(user, ["admin"]);

        const body = await readJson(request);
        const targetUserId = cleanString(body.user_id, 100);
        const rate =
          body.commission_rate === undefined
            ? 5
            : Number(body.commission_rate);

        if (
          !targetUserId ||
          !Number.isFinite(rate) ||
          rate < 0 ||
          rate > 50
        ) {
          throw new HttpError(
            400,
            "Provide a valid user ID and commission rate between 0 and 50 percent."
          );
        }

        const application = await env.DB.prepare(
          "SELECT user_id, status FROM reseller_accounts WHERE user_id = ? LIMIT 1"
        ).bind(targetUserId).first();

        if (!application) {
          throw new HttpError(404, "Reseller application not found.");
        }

        if (application.status === "rejected") {
          throw new HttpError(
            409,
            "Rejected applications cannot be approved through this endpoint."
          );
        }

        const codeRow = await env.DB.prepare(
          "SELECT code FROM referral_codes WHERE user_id = ? LIMIT 1"
        ).bind(targetUserId).first();

        let code = codeRow?.code;

        if (!code) {
          code = `ZV${randomHex(6).toUpperCase()}`;

          await env.DB.prepare(
            "INSERT INTO referral_codes (user_id, code, created_at) VALUES (?, ?, CURRENT_TIMESTAMP)"
          ).bind(targetUserId, code).run();
        }

        await env.DB.prepare(`
          UPDATE reseller_accounts
          SET status = 'approved',
              commission_rate = ?,
              approved_by = ?,
              approved_at = CURRENT_TIMESTAMP,
              updated_at = CURRENT_TIMESTAMP
          WHERE user_id = ?
        `).bind(rate, user.id, targetUserId).run();

        return respond(request, env, {
          success: true,
          user_id: targetUserId,
          status: "approved",
          referral_code: code,
          commission_rate: rate,
        });
      }

      if (path === "/api/admin/resellers/reject" && method === "POST") {
        await requireCsrf(request, env);

        const user = await getSessionUser(request, env);

        requireRole(user, ["admin"]);

        const body = await readJson(request);
        const targetUserId = cleanString(body.user_id, 100);

        if (!targetUserId) {
          throw new HttpError(400, "User ID is required.");
        }

        const result = await env.DB.prepare(`
          UPDATE reseller_accounts
          SET status = 'rejected', updated_at = CURRENT_TIMESTAMP
          WHERE user_id = ? AND status = 'pending'
        `).bind(targetUserId).run();

        if (!result.meta?.changes) {
          throw new HttpError(
            404,
            "Pending reseller application not found."
          );
        }

        return respond(request, env, {
          success: true,
          status: "rejected",
        });
      }

      if (path === "/api/admin/orders/status" && method === "POST") {
        await requireCsrf(request, env);

        const user = await getSessionUser(request, env);

        requireRole(user, ["admin"]);

        const body = await readJson(request);
        const orderId = cleanString(body.order_id, 100);
        const status = cleanString(
          body.order_status,
          40
        ).toLowerCase();

        const allowedStatuses = new Set([
          "pending",
          "processing",
          "shipped",
          "delivered",
          "cancelled",
        ]);

        if (!orderId || !allowedStatuses.has(status)) {
          throw new HttpError(
            400,
            "Provide a valid order ID and status."
          );
        }

        const order = await env.DB.prepare(
          "SELECT id, payment_status FROM orders WHERE id = ? LIMIT 1"
        ).bind(orderId).first();

        if (!order) {
          throw new HttpError(404, "Order not found.");
        }

        await env.DB.prepare(
          "UPDATE orders SET fulfilment_status = ? WHERE id = ?"
        ).bind(status, orderId).run();

        if (
          status === "delivered" &&
          order.payment_status === "success"
        ) {
          await awardCommissionIfEligible(env, orderId);
        }

        return respond(request, env, {
          success: true,
          order_id: orderId,
          fulfilment_status: status,
          order_status: status,
        });
      }

      if (path === "/api/admin/reseller-commissions" && method === "GET") {
        const user = await getSessionUser(request, env);

        requireRole(user, ["admin"]);

        const { results } = await env.DB.prepare(`
          SELECT
            c.id, c.order_id, c.reseller_user_id,
            u.name, u.email, c.amount, c.currency,
            c.status, c.created_at
          FROM reseller_commissions c
          JOIN users u ON u.id = c.reseller_user_id
          ORDER BY c.created_at DESC
          LIMIT 500
        `).all();

        return respond(request, env, {
          success: true,
          commissions: results || [],
        });
      }

      if (path === "/api/admin/reseller-commissions/pay" && method === "POST") {
        await requireCsrf(request, env);

        const user = await getSessionUser(request, env);

        requireRole(user, ["admin"]);

        const body = await readJson(request);
        const commissionId = cleanString(body.commission_id, 100);
        const payoutReference = cleanString(
          body.payout_reference || "",
          160
        );

        if (!commissionId || !payoutReference) {
          throw new HttpError(
            400,
            "Commission ID and payout reference are required."
          );
        }

        const result = await env.DB.prepare(`
          UPDATE reseller_commissions
          SET status = 'paid',
              paid_at = CURRENT_TIMESTAMP,
              payout_reference = ?
          WHERE id = ? AND status IN ('pending', 'approved')
        `).bind(payoutReference, commissionId).run();

        if (!result.meta?.changes) {
          throw new HttpError(404, "Unpaid commission not found.");
        }

        return respond(request, env, {
          success: true,
          commission_id: commissionId,
          status: "paid",
        });
      }

      // Vendor product submission.
      if (path === "/api/vendor/products" && method === "POST") {
        await requireCsrf(request, env);

        const user = await getSessionUser(request, env);

        requireRole(user, ["vendor", "admin"]);

        const body = await readJson(request);
        const title = validateProductText(body.title, "Title", 120);
        const description = validateProductText(
          body.desc || body.description,
          "Description",
          3000
        );

        const category = cleanString(body.category, 80);
        const price = Number(body.price);
        const stock = Number(body.stock);

        if (
          !category ||
          !Number.isFinite(price) ||
          price <= 0 ||
          price > 100000000 ||
          !Number.isSafeInteger(stock) ||
          stock < 0 ||
          stock > 1000000
        ) {
          throw new HttpError(
            400,
            "Enter a valid category, price, and stock quantity."
          );
        }

        const images = Array.isArray(body.images)
          ? body.images.slice(0, 8)
          : [];

        if (
          images.some(
            (image) =>
              typeof image !== "string" ||
              image.length > 2000 ||
              !/^https:\/\//i.test(image)
          )
        ) {
          throw new HttpError(
            400,
            "Product images must be HTTPS URLs."
          );
        }

        if (
          user.role === "vendor" &&
          (!user.vendor_id || user.vendor_status !== "approved")
        ) {
          throw new HttpError(
            403,
            "Your vendor profile must be approved before you can list products."
          );
        }

        const vendorId =
          user.role === "admin"
            ? cleanString(body.vendor_id, 100)
            : user.vendor_id;

        if (!vendorId) {
          throw new HttpError(400, "A vendor profile is required.");
        }

        const vendorExists = await env.DB.prepare(
          "SELECT id FROM vendors WHERE id = ? LIMIT 1"
        ).bind(vendorId).first();

        if (!vendorExists) {
          throw new HttpError(404, "Vendor profile not found.");
        }

        const productId =
          `prod_${crypto.randomUUID().replace(/-/g, "")}`;

        await env.DB.prepare(`
          INSERT INTO products (
            id, vendor_id, title, description, price, stock,
            category, images, status, created_at
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', CURRENT_TIMESTAMP)
        `).bind(
          productId,
          vendorId,
          title,
          description,
          price,
          stock,
          category,
          JSON.stringify(images)
        ).run();

        return respond(
          request,
          env,
          { success: true, product_id: productId },
          201
        );
      }

      if (path === "/api/vendor/products" && method === "GET") {
        const user = await getSessionUser(request, env);

        requireRole(user, ["vendor", "admin"]);

        const requestedVendorId = cleanString(
          url.searchParams.get("vendor_id"),
          100
        );

        const vendorId =
          user.role === "admin"
            ? requestedVendorId
            : user.vendor_id;

        if (!vendorId) {
          throw new HttpError(400, "Vendor ID is required.");
        }

        if (
          user.role === "vendor" &&
          user.vendor_status !== "approved"
        ) {
          throw new HttpError(
            403,
            "Your vendor profile is not approved."
          );
        }

        const { results } = await env.DB.prepare(
          "SELECT id, vendor_id, title, description, price, stock, category, images, status, created_at FROM products WHERE vendor_id = ? ORDER BY created_at DESC LIMIT 200"
        ).bind(vendorId).all();

        return respond(request, env, {
          success: true,
          products: results || [],
        });
      }

      if (path === "/api/admin/orders" && method === "GET") {
        const user = await getSessionUser(request, env);

        requireRole(user, ["admin"]);

        const { results } = await env.DB.prepare(
          "SELECT id, customer_name, customer_phone, customer_email, county, town, delivery_address, items_json, subtotal, shipping_cost, total_amount, payment_method, payment_status, fulfilment_status, created_at FROM orders ORDER BY created_at DESC LIMIT 500"
        ).all();

        return respond(request, env, {
          success: true,
          orders: results || [],
        });
      }

      if (path === "/api/admin/vendors" && method === "GET") {
        const user = await getSessionUser(request, env);

        requireRole(user, ["admin"]);

        const { results } = await env.DB.prepare(
          "SELECT * FROM vendor_applications ORDER BY created_at DESC LIMIT 500"
        ).all();

        return respond(request, env, {
          success: true,
          vendors: results || [],
        });
      }

      if (path === "/api/admin/verify-secret" && method === "POST") {
        throw new HttpError(
          410,
          "This legacy endpoint has been disabled. Sign in using your account instead."
        );
      }

      if (path === "/api/admin/register-bio" && method === "POST") {
        throw new HttpError(
          501,
          "Biometric login is not enabled. Use password-based sign-in until WebAuthn is implemented."
        );
      }

      return respond(
        request,
        env,
        {
          success: false,
          error: "API endpoint not found.",
        },
        404
      );

    } catch (error) {
      const status =
        error instanceof HttpError ? error.status : 500;

      if (status >= 500) {
        console.error(
          "ZAVO Worker error:",
          error && error.stack ? error.stack : String(error)
        );
      }

      const message =
        error instanceof HttpError
          ? error.message
          : `The request could not be completed. Contact ${PUBLIC_CONTACT_EMAIL} if the problem continues.`;

      return respond(
        request,
        env,
        { success: false, error: message },
        status
      );
    }
  },
};
