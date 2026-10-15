/**
 * ZAVO Marketplace Backend Worker
 * Compatible with Cloudflare D1 (DB binding) and schema.sql
 */

const CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;
        const method = request.method;

        // Handle CORS preflight requests
        if (method === "OPTIONS") {
            return new Response(null, { headers: CORS_HEADERS });
        }

        try {
            // 1. Health Check Endpoint
            if (path === "/api/health" && method === "GET") {
                return jsonResponse({ status: "OK", message: "ZAVO API is healthy and running." });
            }

            // 2. Get Public Products (For Customers & Guests)
            if (path === "/api/products" && method === "GET") {
                const { results } = await env.DB.prepare(
                    "SELECT id, vendor_id, title, description, price, stock, status, created_at FROM products WHERE status = 'active'"
                ).all();
                return jsonResponse({ success: true, products: results || [] });
            }

            // 3. User Registration (Customer / Vendor / Reseller)
            if (path === "/api/auth/register" && method === "POST") {
                const body = await request.json();
                const { email, password, role } = body;

                if (!email || !password) {
                    return jsonResponse({ success: false, error: "Email and password are required." }, 400);
                }

                const userId = "usr_" + Date.now() + "_" + Math.random().toString(36.substring(2, 7));
                const assignedRole = ["admin", "vendor", "reseller", "customer"].includes(role) ? role : "customer";
                
                // Note: In production, use Web Crypto API for secure hashing. Storing mock hash for setup foundation.
                const passwordHash = btoa(password); 

                try {
                    await env.DB.prepare(
                        "INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, ?, ?)"
                    ).bind(userId, email, passwordHash, assignedRole).run();

                    return jsonResponse({ success: true, message: "User registered successfully.", userId });
                } catch (err) {
                    return jsonResponse({ success: false, error: "Email already exists or invalid data." }, 400);
                }
            }

            // 4. User Login Endpoint
            if (path === "/api/auth/login" && method === "POST") {
                const body = await request.json();
                const { email, password } = body;

                if (!email || !password) {
                    return jsonResponse({ success: false, error: "Email and password are required." }, 400);
                }

                const passwordHash = btoa(password);
                const user = await env.DB.prepare(
                    "SELECT id, email, role FROM users WHERE email = ? AND password_hash = ?"
                ).bind(email, passwordHash).first();

                if (!user) {
                    return jsonResponse({ success: false, error: "Invalid email or password." }, 401);
                }

                return jsonResponse({ success: true, message: "Login successful.", user });
            }

            // Fallback for unmatched routes
            return jsonResponse({ success: false, error: "Endpoint not found." }, 404);

        } catch (err) {
            return jsonResponse({ success: false, error: err.message }, 500);
        }
    }
};

function jsonResponse(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            "Content-Type": "application/json",
            ...CORS_HEADERS
        }
    });
}
