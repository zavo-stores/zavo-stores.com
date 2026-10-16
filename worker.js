/**
 * ZAVO Cloudflare Worker — Synchronized & Hardened Backend
 */

const PAYSTACK_API = "https://api.paystack.co";
const PUBLIC_CONTACT_EMAIL = "zavo.org@proton.me";
const SESSION_COOKIE = "__Host-zavo_session";
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7;
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

function corsHeaders(request) {
  const origin = request.headers.get("Origin") || "*";
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-CSRF-Token",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };
}

function respond(request, env, data, status = 200, extraHeaders = {}) {
  return jsonResponse(data, status, {
    ...corsHeaders(request),
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
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function hashPassword(password, saltHex = randomHex(16)) {
  const salt = Uint8Array.from(saltHex.match(/.{2}/g), (byte) => parseInt(byte, 16));
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" }, key, 256);
  const hashHex = Array.from(new Uint8Array(bits), (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `pbkdf2_sha256$${PBKDF2_ITERATIONS}$${saltHex}$${hashHex}`;
}

async function verifyPassword(password, encoded) {
  const parts = encoded.split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2_sha256") return false;
  const iterations = Number(parts[1]);
  if (!Number.isSafeInteger(iterations) || iterations < 100000 || iterations > PBKDF2_ITERATIONS) return false;
  const saltHex = parts[2];
  const expectedHex = parts[3];
  const salt = Uint8Array.from(saltHex.match(/.{2}/g), (byte) => parseInt(byte, 16));
  try {
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations, hash: "SHA-256" }, key, 256);
    const actual = Array.from(new Uint8Array(bits), (byte) => byte.toString(16).padStart(2, "0")).join("");
    return constantTimeEqual(actual.toLowerCase(), expectedHex.toLowerCase());
  } catch {
    return false;
  }
}

function constantTimeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
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
    throw new HttpError(415, "Send data using Content-Type: application/json.");
  }
  const length = Number(request.headers.get("Content-Length") || 0);
  if (length > MAX_JSON_BYTES) {
    throw new HttpError(413, "Request body is too large.");
  }
  const raw = await request.text();
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
  return typeof value === "string" && value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
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
  if (!user) throw new HttpError(401, "Please sign in to continue.");
  if (!roles.includes(user.role)) {
    throw new HttpError(403, "You are not authorized to perform this action.");
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();
    const cors = corsHeaders(request);

    if (method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }

    try {
      if (!env.DB) throw new HttpError(503, "Database is not configured.");

      if (path === "/api/health" && method === "GET") {
        return respond(request, env, { success: true, service: "zavo-api" });
      }

      if (path === "/api/auth/csrf" && method === "GET") {
        const token = randomHex(24);
        return respond(request, env, { success: true, csrfToken: token }, 200, {
          "Set-Cookie": `zavo_csrf=${token}; Path=/; Secure; SameSite=None; Max-Age=3600`,
        });
      }

      // Authentication: Login
      if (path === "/api/auth/login" && method === "POST") {
        const body = await readJson(request);
        const email = cleanString(body.email, 254).toLowerCase();
        const password = typeof body.password === "string" ? body.password : "";

        const user = await env.DB.prepare(`
          SELECT id, name, email, password_hash, role, is_active
          FROM users WHERE email = ? LIMIT 1
        `).bind(email).first();

        if (!user || Number(user.is_active) !== 1 || !(await verifyPassword(password, user.password_hash))) {
          throw new HttpError(401, "Email or password is incorrect.");
        }

        const session = await createSession(env, user.id);
        const csrf = randomHex(24);
        const redirectTo = user.role === "admin" ? "/admin.html" : user.role === "vendor" ? "/vendor.html" : "/";

        return respond(request, env, {
          success: true,
          user: { id: user.id, name: user.name, email: user.email, role: user.role },
          redirectTo
        }, 200, {
          "Set-Cookie": [cookieHeader(session), `zavo_csrf=${csrf}; Path=/; Secure; SameSite=None; Max-Age=3600`]
        });
      }

      if (path === "/api/auth/me" && method === "GET") {
        const user = await getSessionUser(request, env);
        if (!user) throw new HttpError(401, "You are not signed in.");
        return respond(request, env, { success: true, user });
      }

      // Public Products Retrieval
      if (path === "/api/products" && method === "GET") {
        const { results } = await env.DB.prepare(`
          SELECT id, title, description, price, stock, category, images, videos, rating, reviews, created_at
          FROM products
          WHERE status IN ('active', 'pending') AND stock >= 0
          ORDER BY created_at DESC
          LIMIT 200
        `).all();

        return respond(request, env, { success: true, products: results || [] });
      }

      // Product Submission with Multi-Media, Ratings & Shipping
      if (path === "/api/vendor/products" && method === "POST") {
        const user = await getSessionUser(request, env);
        requireRole(user, ["vendor", "admin"]);

        const body = await readJson(request);
        const title = cleanString(body.title, 120);
        const description = cleanString(body.description, 3000);
        const category = cleanString(body.category, 80);
        const price = Number(body.price);
        const stock = Number(body.stock);
        const rating = Number(body.rating || 4);
        const reviews = cleanString(body.reviews, 2000);

        const images = Array.isArray(body.images) ? body.images.slice(0, 10) : [];
        const videos = Array.isArray(body.videos) ? body.videos.slice(0, 5) : [];

        if (!title || !price || images.length === 0) {
          throw new HttpError(400, "Title, price, and at least 1 image are required.");
        }

        const productId = `prod_${crypto.randomUUID().replace(/-/g, "")}`;
        const vendorId = user.role === "admin" ? "sys_admin_01" : (user.vendor_id || "sys_admin_01");

        await env.DB.prepare(`
          INSERT INTO products (
            id, vendor_id, title, description, price, stock,
            category, images, videos, rating, reviews, status, created_at
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', CURRENT_TIMESTAMP)
        `).bind(
          productId,
          vendorId,
          title,
          description,
          price,
          stock,
          category,
          JSON.stringify(images),
          JSON.stringify(videos),
          rating,
          reviews
        ).run();

        return respond(request, env, { success: true, product_id: productId }, 201);
      }

      return respond(request, env, { success: false, error: "API endpoint not found." }, 404);

    } catch (error) {
      const status = error instanceof HttpError ? error.status : 500;
      const message = error instanceof HttpError ? error.message : "The request could not be completed.";
      return respond(request, env, { success: false, error: message }, status);
    }
  },
};
