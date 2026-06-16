// functions/api/ban-check.js
// Cloudflare Pages Function — Supabase ban check
// Mapped automatically to /api/ban-check by Cloudflare Pages
//
// Required environment variables (Cloudflare Pages → Settings → Environment Variables):
//   SUPABASE_URL              = https://<project-ref>.supabase.co
//   SUPABASE_SERVICE_ROLE_KEY = <service_role key from Supabase API settings>

import { createClient } from '@supabase/supabase-js';

export async function onRequestPost(context) {
    const { request, env } = context;

    const SUPABASE_URL  = env.SUPABASE_URL;
    const SERVICE_KEY   = env.SUPABASE_SERVICE_ROLE_KEY;

    if (!SUPABASE_URL || !SERVICE_KEY) {
        console.error('[ban-check] Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY env vars');
        return ok({ banned: false });
    }

    const admin = createClient(SUPABASE_URL, SERVICE_KEY, {
        auth: { persistSession: false, autoRefreshToken: false },
    });

    let fingerprint = null;
    try {
        const body = await request.json();
        fingerprint = typeof body?.fingerprint === 'string' ? body.fingerprint : null;
    } catch (_) {
        // no/invalid body — fingerprint stays null
    }

    // Cloudflare sets CF-Connecting-IP; fall back to x-forwarded-for
    const ip =
        request.headers.get('CF-Connecting-IP') ||
        (request.headers.get('x-forwarded-for') || '').split(',')[0].trim() ||
        null;

    // ── Resolve the calling user (if signed in) ──────────────────────────────
    let userId   = null;
    let userMeta = {};
    const authHeader = request.headers.get('Authorization') || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

    if (token) {
        try {
            const { data, error } = await admin.auth.getUser(token);
            if (!error && data?.user) {
                userId   = data.user.id;
                userMeta = data.user.user_metadata ?? {};
            }
        } catch (e) {
            console.warn('[ban-check] token verification failed:', e);
        }
    }

    // ── Track device/IP against the account for future ip/hwid_ip bans ──────
    if (userId) {
        try {
            await admin
                .from('user_devices')
                .upsert(
                    { user_id: userId, fingerprint, ip_address: ip, last_seen: new Date().toISOString() },
                    { onConflict: 'user_id' }
                );
        } catch (e) {
            console.warn('[ban-check] user_devices upsert failed:', e);
        }
    }

    const now = new Date().toISOString();
    let activeBan = null;

    // ── 1. Account-level ban ─────────────────────────────────────────────────
    if (userId) {
        try {
            const { data, error } = await admin
                .from('bans')
                .select('id, tier, reason, custom_message, appealable, expires_at')
                .eq('user_id', userId)
                .eq('active', true)
                .or(`expires_at.is.null,expires_at.gt.${now}`)
                .order('created_at', { ascending: false })
                .limit(1)
                .maybeSingle();
            if (!error && data) activeBan = data;
        } catch (e) {
            console.warn('[ban-check] account ban lookup failed:', e);
        }
    }

    // ── 2. Device/IP-level ban (tiers 5–6) ──────────────────────────────────
    if (!activeBan && (fingerprint || ip)) {
        try {
            const orParts = [];
            if (fingerprint) orParts.push(`fingerprint.eq.${fingerprint}`);
            if (ip)          orParts.push(`ip_address.eq.${ip}`);

            const { data, error } = await admin
                .from('bans')
                .select('id, tier, reason, custom_message, appealable, expires_at')
                .eq('active', true)
                .in('tier', ['ip', 'hwid_ip'])
                .or(orParts.join(','))
                .order('created_at', { ascending: false })
                .limit(1)
                .maybeSingle();
            if (!error && data) activeBan = data;
        } catch (e) {
            console.warn('[ban-check] device/ip ban lookup failed:', e);
        }
    }

    if (!activeBan) {
        // ── 3. Lifted-but-unacknowledged ban — show reactivation screen ──────
        if (userId) {
            try {
                const { data, error } = await admin
                    .from('bans')
                    .select('id, tier, reason, custom_message, appealable, expires_at')
                    .eq('user_id', userId)
                    .eq('active', false)
                    .order('created_at', { ascending: false })
                    .limit(1)
                    .maybeSingle();
                if (!error && data && userMeta.ban_reactivated_for !== data.id) {
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
