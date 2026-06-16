// functions/api/ban-check.js
// Cloudflare Pages Function — Supabase ban check
// Mapped automatically to /api/ban-check by Cloudflare Pages
//
// Required environment variables (Cloudflare Pages → Settings → Environment Variables):
//   SUPABASE_URL              = https://<project-ref>.supabase.co
//   SUPABASE_SERVICE_ROLE_KEY = <service_role key from Supabase API settings>
//
// No dependencies — uses fetch() directly against the Supabase REST API
// so no bundling step is required.

export async function onRequestPost(context) {
    const { request, env } = context;

    const SUPABASE_URL  = env.SUPABASE_URL;
    const SERVICE_KEY   = env.SUPABASE_SERVICE_ROLE_KEY;

    if (!SUPABASE_URL || !SERVICE_KEY) {
        console.error('[ban-check] Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY env vars');
        return ok({ banned: false });
    }

    // ── Supabase REST helpers (no SDK needed) ─────────────────────────────────
    const headers = (extra = {}) => ({
        'Content-Type':  'application/json',
        'apikey':        SERVICE_KEY,
        'Authorization': `Bearer ${SERVICE_KEY}`,
        ...extra,
    });

    const sbGet = async (path, params = {}) => {
        const url = new URL(`${SUPABASE_URL}/rest/v1/${path}`);
        for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
        const res = await fetch(url.toString(), { headers: headers({ 'Accept': 'application/json', 'Prefer': 'return=representation' }) });
        if (!res.ok) throw new Error(`Supabase REST error ${res.status}: ${await res.text()}`);
        return res.json();
    };

    const sbUpsert = async (table, body, onConflict) => {
        const url = `${SUPABASE_URL}/rest/v1/${table}`;
        await fetch(url, {
            method:  'POST',
            headers: headers({ 'Prefer': `resolution=merge-duplicates,return=minimal` }),
            body:    JSON.stringify(body),
        });
    };

    const sbAuthUser = async (token) => {
        const res = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
            headers: { 'apikey': SERVICE_KEY, 'Authorization': `Bearer ${token}` },
        });
        if (!res.ok) return null;
        return res.json();
    };

    // ── Parse request ─────────────────────────────────────────────────────────
    let fingerprint = null;
    try {
        const body = await request.json();
        fingerprint = typeof body?.fingerprint === 'string' ? body.fingerprint : null;
    } catch (_) {}

    const ip =
        request.headers.get('CF-Connecting-IP') ||
        (request.headers.get('x-forwarded-for') || '').split(',')[0].trim() ||
        null;

    // ── Resolve the calling user (if signed in) ───────────────────────────────
    let userId   = null;
    let userMeta = {};
    const authHeader = request.headers.get('Authorization') || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

    if (token) {
        try {
            const user = await sbAuthUser(token);
            if (user?.id) {
                userId   = user.id;
                userMeta = user.user_metadata ?? {};
            }
        } catch (e) {
            console.warn('[ban-check] token verification failed:', e);
        }
    }

    // ── Track device/IP against the account for future ip/hwid_ip bans ───────
    if (userId) {
        try {
            await sbUpsert('user_devices', {
                user_id:     userId,
                fingerprint,
                ip_address:  ip,
                last_seen:   new Date().toISOString(),
            }, 'user_id');
        } catch (e) {
            console.warn('[ban-check] user_devices upsert failed:', e);
        }
    }

    const now = new Date().toISOString();
    let activeBan = null;

    // ── 1. Account-level ban ──────────────────────────────────────────────────
    if (userId) {
        try {
            const rows = await sbGet('bans', {
                select:     'id,tier,reason,custom_message,appealable,expires_at',
                user_id:    `eq.${userId}`,
                active:     'eq.true',
                or:         `(expires_at.is.null,expires_at.gt.${now})`,
                order:      'created_at.desc',
                limit:      '1',
            });
            if (rows?.length) activeBan = rows[0];
        } catch (e) {
            console.warn('[ban-check] account ban lookup failed:', e);
        }
    }

    // ── 2. Device/IP-level ban (tiers 5–6) ───────────────────────────────────
    if (!activeBan && (fingerprint || ip)) {
        try {
            const orParts = [];
            if (fingerprint) orParts.push(`fingerprint.eq.${fingerprint}`);
            if (ip)          orParts.push(`ip_address.eq.${ip}`);

            const rows = await sbGet('bans', {
                select: 'id,tier,reason,custom_message,appealable,expires_at',
                active: 'eq.true',
                tier:   'in.(ip,hwid_ip)',
                or:     `(${orParts.join(',')})`,
                order:  'created_at.desc',
                limit:  '1',
            });
            if (rows?.length) activeBan = rows[0];
        } catch (e) {
            console.warn('[ban-check] device/ip ban lookup failed:', e);
        }
    }

    if (!activeBan) {
        // ── 3. Lifted-but-unacknowledged ban — show reactivation screen ───────
        if (userId) {
            try {
                const rows = await sbGet('bans', {
                    select:  'id,tier,reason,custom_message,appealable,expires_at',
                    user_id: `eq.${userId}`,
                    active:  'eq.false',
                    order:   'created_at.desc',
                    limit:   '1',
                });
                const data = rows?.[0];
                if (data && userMeta.ban_reactivated_for !== data.id) {
                    return ok({
                        banned:         false,
                        lifted:         true,
                        id:             data.id,
                        tier:           data.tier,
                        reason:         data.reason,
                        custom_message: data.custom_message,
                        expires_at:     data.expires_at,
                        appealable:     data.appealable,
                    });
                }
            } catch (e) {
                console.warn('[ban-check] lifted-ban lookup failed:', e);
            }
        }
        return ok({ banned: false });
    }

    return ok({
        banned:         true,
        id:             activeBan.id,
        tier:           activeBan.tier,
        reason:         activeBan.reason,
        custom_message: activeBan.custom_message,
        expires_at:     activeBan.expires_at,
        appealable:     activeBan.appealable,
    });
}

export async function onRequestOptions() {
    return new Response(null, {
        status: 204,
        headers: {
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        },
    });
}

function ok(data) {
    return new Response(JSON.stringify(data), {
        status: 200,
        headers: {
            'Content-Type':                'application/json',
            'Access-Control-Allow-Origin': '*',
        },
    });
}
