// functions/api/_auth.js
// Shared auth + ban guard — imported by nvidia.js, cerebras.js, etc.
//
// Usage:
//   import { requireAuth } from './_auth.js';
//   const deny = await requireAuth(context);
//   if (deny) return deny;

/**
 * Verifies the request is authenticated and not banned.
 *
 * Returns null if the caller is allowed to proceed.
 * Returns a Response (403/401) if the request should be rejected.
 *
 * Required env vars (same ones ban-check.js already uses):
 *   SUPABASE_URL              — https://<project-ref>.supabase.co
 *   SUPABASE_SERVICE_ROLE_KEY — service role key from Supabase API settings
 */
export async function requireAuth(context) {
    const { request, env } = context;

    const SUPABASE_URL  = env.SUPABASE_URL;
    const SERVICE_KEY   = env.SUPABASE_SERVICE_ROLE_KEY;

    // ── 1. Authenticate the caller ────────────────────────────────────────────
    const authHeader = request.headers.get('Authorization') || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

    if (!token) {
        return _deny(401, 'Authentication required');
    }

    // Bail gracefully if Supabase is not configured — don't silently allow through
    if (!SUPABASE_URL || !SERVICE_KEY) {
        console.error('[auth] Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY');
        return _deny(500, 'Server misconfiguration: auth service unavailable');
    }

    // Verify JWT with Supabase Auth
    let userId   = null;
    let userMeta = {};
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
        userId   = user.id;
        userMeta = user.user_metadata ?? {};
    } catch (e) {
        console.error('[auth] Supabase auth check failed:', e.message);
        return _deny(502, 'Authentication service unreachable');
    }

    // ── 2. Check for an active ban ────────────────────────────────────────────
    const sbHeaders = {
        'Content-Type':  'application/json',
        'apikey':        SERVICE_KEY,
        'Authorization': `Bearer ${SERVICE_KEY}`,
        'Accept':        'application/json',
        'Prefer':        'return=representation',
    };

    const now = new Date().toISOString();

    try {
        const url = new URL(`${SUPABASE_URL}/rest/v1/bans`);
        url.searchParams.set('select',   'id,tier');
        url.searchParams.set('user_id',  `eq.${userId}`);
        url.searchParams.set('active',   'eq.true');
        url.searchParams.set('or',       `(expires_at.is.null,expires_at.gt.${now})`);
        url.searchParams.set('limit',    '1');

        const res = await fetch(url.toString(), { headers: sbHeaders });
        if (!res.ok) {
            // If ban check itself errors, err on the side of caution and block
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

    // ── 3. Caller is authenticated and not banned ─────────────────────────────
    return null;
}

function _deny(status, message) {
    return new Response(JSON.stringify({ error: message }), {
        status,
        headers: {
            'Content-Type':                'application/json',
            'Access-Control-Allow-Origin': '*',
        },
    });
}
