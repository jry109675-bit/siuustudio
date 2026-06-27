// functions/api/_auth.js
// Shared auth + ban guard — imported by nvidia.js, cerebras.js, tavily.js etc.
//
// Usage:
//   import { requireAuth } from './_auth.js';
//   const deny = await requireAuth(context);
//   if (deny) return deny;
//
// Session source priority:
//   1. HttpOnly cookie  `sb-session`  (set by /api/session POST after sign-in)
//   2. Authorization: Bearer <token>  (fallback for non-browser clients / API)

const COOKIE_NAME = 'sb-session';

function _getTokenFromRequest(request) {
    // 1 — HttpOnly cookie (preferred, set by session.js)
    const cookieStr = request.headers.get('Cookie') || '';
    const match = cookieStr.match(
        new RegExp('(?:^|; )' + COOKIE_NAME + '=([^;]*)')
    );
    if (match) {
        try {
            const payload = JSON.parse(decodeURIComponent(match[1]));
            if (payload?.access_token) return payload.access_token;
        } catch (_) {}
    }

    // 2 — Authorization header (fallback)
    const authHeader = request.headers.get('Authorization') || '';
    if (authHeader.startsWith('Bearer ')) return authHeader.slice(7);

    return null;
}

/**
 * Verifies the request is authenticated and not banned.
 * Returns null if the caller is allowed to proceed.
 * Returns a Response (401/403/5xx) if the request should be rejected.
 *
 * Required env vars:
 *   SUPABASE_URL              — https://<project-ref>.supabase.co
 *   SUPABASE_SERVICE_ROLE_KEY — service role key from Supabase API settings
 */
export async function requireAuth(context) {
    const { request, env } = context;

    const SUPABASE_URL = env.SUPABASE_URL;
    const SERVICE_KEY  = env.SUPABASE_SERVICE_ROLE_KEY;

    // ── 1. Extract token ──────────────────────────────────────────────────────
    const token = _getTokenFromRequest(request);

    if (!token) {
        return _deny(401, 'Authentication required');
    }

    if (!SUPABASE_URL || !SERVICE_KEY) {
        console.error('[auth] Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY');
        return _deny(500, 'Server misconfiguration: auth service unavailable');
    }

    // ── 2. Verify JWT with Supabase ───────────────────────────────────────────
    let userId = null;
    try {
        const res = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
            headers: {
                'apikey':        SERVICE_KEY,
                'Authorization': `Bearer ${token}`,
            },
        });
        if (!res.ok) {
            return _deny(401, 'Invalid or expired session — please sign in again');
        }
        const user = await res.json();
        if (!user?.id) {
            return _deny(401, 'Invalid or expired session — please sign in again');
        }
        userId = user.id;
    } catch (e) {
        console.error('[auth] Supabase auth check failed:', e.message);
        return _deny(502, 'Authentication service unreachable');
    }

    // ── 3. Check for an active ban ────────────────────────────────────────────
    const sbHeaders = {
        'Content-Type':  'application/json',
        'apikey':        SERVICE_KEY,
        'Authorization': `Bearer ${SERVICE_KEY}`,
        'Accept':        'application/json',
    };

    const now = new Date().toISOString();

    try {
        const url = new URL(`${SUPABASE_URL}/rest/v1/bans`);
        url.searchParams.set('select',  'id,tier');
        url.searchParams.set('user_id', `eq.${userId}`);
        url.searchParams.set('active',  'eq.true');
        url.searchParams.set('or',      `(expires_at.is.null,expires_at.gt.${now})`);
        url.searchParams.set('limit',   '1');

        const res = await fetch(url.toString(), { headers: sbHeaders });
        if (!res.ok) {
            console.error('[auth] Ban lookup HTTP error:', res.status);
            return _deny(502, 'Could not verify account standing');
        }
        const rows = await res.json();
        if (rows?.length) {
            return _deny(403, 'Your account has been suspended');
        }
    } catch (e) {
        console.error('[auth] Ban lookup failed:', e.message);
        return _deny(502, 'Could not verify account standing');
    }

    // ── 4. All good ───────────────────────────────────────────────────────────
    return null;
}

function _deny(status, message) {
    return new Response(JSON.stringify({ error: message }), {
        status,
        headers: {
            'Content-Type':                'application/json',
            'Access-Control-Allow-Origin': 'https://siuustudio.com',
            'Access-Control-Allow-Credentials': 'true',
        },
    });
}
