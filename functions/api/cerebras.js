// functions/api/cerebras.js
// Cloudflare Pages Function — Cerebras API proxy
// Mapped automatically to /api/cerebras by Cloudflare Pages

import { requireAuth } from './_auth.js';

export async function onRequestPost(context) {
    const { request, env } = context;

    // Reject unauthenticated or banned callers before touching the API key
    const deny = await requireAuth(context);
    if (deny) return deny;

    const apiKey = env.CEREBRAS_API_KEY;
    if (!apiKey) {
        return new Response(JSON.stringify({ error: 'API key not configured' }), {
            status: 500,
            headers: { ...corsHeaders(), 'Content-Type': 'application/json' },
        });
    }

    const body = await request.text();

    const upstream = await fetch('https://api.cerebras.ai/v1/chat/completions', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type':  'application/json',
        },
        body,
    });

    return new Response(upstream.body, {
        status: upstream.status,
        headers: {
            ...corsHeaders(),
            'Content-Type':  upstream.headers.get('Content-Type') || 'application/json',
            'Cache-Control': 'no-store',
        },
    });
}

export async function onRequestOptions() {
    return new Response(null, { status: 204, headers: corsHeaders() });
}

function corsHeaders() {
    return {
        'Access-Control-Allow-Origin':  '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };
}
