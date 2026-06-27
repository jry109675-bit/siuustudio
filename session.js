// functions/api/session.js
//
// POST /api/session   — exchange a Supabase JWT for an HttpOnly cookie
// DELETE /api/session — clear the session cookie (sign-out)
//
// Why this exists:
//   Client-side JS (even with a custom storage adapter) can only write cookies
//   that are readable by JS — it cannot set HttpOnly. Only a server response
//   header can do that. This function is the "edge handshake": the browser
//   sends the token here once after sign-in, and this function echoes it back
//   via Set-Cookie with HttpOnly; Secure; SameSite=Lax so no JS can ever
//   read it again.
//
// Cookie name mirrors the Supabase default so the JS client still finds it
// when we hand it back via /api/session GET (see siuustudio.html bootstrap).

const COOKIE_NAME = 'sb-session';
const COOKIE_MAX_AGE = 60 * 60 * 24 * 7; // 7 days

function cookieHeader(value, maxAge) {
    return [
        `${COOKIE_NAME}=${encodeURIComponent(value)}`,
        `Max-Age=${maxAge}`,
        'Path=/',
        'HttpOnly',
        'Secure',
        'SameSite=Lax',
    ].join('; ');
}

function corsHeaders(origin) {
    // Restrict to your own origin only — never wildcard for credentialed cookies
    const allowed = 'https://siuustudio.com';
    return {
        'Access-Control-Allow-Origin':      allowed,
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Allow-Methods':     'GET, POST, DELETE, OPTIONS',
        'Access-Control-Allow-Headers':     'Content-Type',
        'Vary':                             'Origin',
    };
}

export async function onRequest(context) {
    const { request, env } = context;
    const method = request.method.toUpperCase();
    const cors   = corsHeaders(request.headers.get('Origin') || '');

    // ── Preflight ────────────────────────────────────────────────────────────
    if (method === 'OPTIONS') {
        return new Response(null, { status: 204, headers: cors });
    }

    // ── POST /api/session — set HttpOnly cookie ───────────────────────────────
    if (method === 'POST') {
        let body;
        try {
            body = await request.json();
        } catch {
            return new Response(JSON.stringify({ error: 'Invalid JSON' }), {
                status: 400,
                headers: { 'Content-Type': 'application/json', ...cors },
            });
        }

        const { access_token, refresh_token, expires_at } = body;

        if (!access_token || !refresh_token) {
            return new Response(JSON.stringify({ error: 'Missing tokens' }), {
                status: 400,
                headers: { 'Content-Type': 'application/json', ...cors },
            });
        }

        // Verify the token is actually valid before issuing the cookie
        const SUPABASE_URL      = env.SUPABASE_URL;
        const SERVICE_KEY       = env.SUPABASE_SERVICE_ROLE_KEY;

        if (!SUPABASE_URL || !SERVICE_KEY) {
            return new Response(JSON.stringify({ error: 'Server misconfiguration' }), {
                status: 500,
                headers: { 'Content-Type': 'application/json', ...cors },
            });
        }

        const verify = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
            headers: {
                'apikey':        SERVICE_KEY,
                'Authorization': `Bearer ${access_token}`,
            },
        });

        if (!verify.ok) {
            return new Response(JSON.stringify({ error: 'Invalid token' }), {
                status: 401,
                headers: { 'Content-Type': 'application/json', ...cors },
            });
        }

        // Store both tokens as JSON in the single HttpOnly cookie
        const payload = JSON.stringify({ access_token, refresh_token, expires_at });

        return new Response(JSON.stringify({ ok: true }), {
            status: 200,
            headers: {
                'Content-Type': 'application/json',
                'Set-Cookie':   cookieHeader(payload, COOKIE_MAX_AGE),
                ...cors,
            },
        });
    }

    // ── GET /api/session — return access_token so client can init Supabase ───
    // Called once on page load by siuustudio.html to bootstrap the JS client
    // without ever touching localStorage.
    if (method === 'GET') {
        const cookieHeader_ = request.headers.get('Cookie') || '';
        const match = cookieHeader_.match(
            new RegExp('(?:^|; )' + COOKIE_NAME + '=([^;]*)')
        );

        if (!match) {
            return new Response(JSON.stringify({ session: null }), {
                status: 200,
                headers: { 'Content-Type': 'application/json', ...cors },
            });
        }

        let payload;
        try {
            payload = JSON.parse(decodeURIComponent(match[1]));
        } catch {
            return new Response(JSON.stringify({ session: null }), {
                status: 200,
                headers: { 'Content-Type': 'application/json', ...cors },
            });
        }

        return new Response(JSON.stringify({ session: payload }), {
            status: 200,
            headers: { 'Content-Type': 'application/json', ...cors },
        });
    }

    // ── DELETE /api/session — clear cookie (sign-out) ────────────────────────
    if (method === 'DELETE') {
        return new Response(JSON.stringify({ ok: true }), {
            status: 200,
            headers: {
                'Content-Type': 'application/json',
                'Set-Cookie':   cookieHeader('', 0), // Max-Age=0 deletes it
                ...cors,
            },
        });
    }

    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
        status: 405,
        headers: { 'Content-Type': 'application/json', ...cors },
    });
}
