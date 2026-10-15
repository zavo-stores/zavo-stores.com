// Cloudflare Pages Function for /api/health
export async function onRequest(context) {
    const { env } = context;
    
    // Test database connection if needed
    let dbStatus = "Connected";
    try {
        await env.DB.prepare("SELECT 1").first();
    } catch (e) {
        dbStatus = "Error connecting to DB: " + e.message;
    }

    return new Response(JSON.stringify({ 
        status: "OK", 
        message: "ZAVO API is healthy and running via Pages Functions.",
        database: dbStatus
    }), {
        headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*"
        }
    });
}
