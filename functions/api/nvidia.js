// functions/api/nvidia.js
// Cloudflare Pages Function — NVIDIA NIM API proxy
// Mapped automatically to /api/nvidia by Cloudflare Pages

import { requireAuth } from './_auth.js';

const NVIDIA_API_URL = 'https://integrate.api.nvidia.com/v1/chat/completions';
const DEFAULT_MODEL  = 'qwen/qwen3.5-397b-a17b';

export async function onRequestPost(context) {
    const { request, env } = context;

    // Reject unauthenticated or banned callers before touching the API key
    const deny = await requireAuth(context);
    if (deny) return deny;

    const apiKey = env.NVIDIA_API_KEY;
    if (!apiKey) {
        return json({ error: 'Server misconfiguration: API key missing' }, 500);
    }

    let body;
    try {
        body = await request.json();
    } catch {
        return json({ error: 'Invalid JSON body' }, 400);
    }

    const { messages, model, stream = true, max_tokens = 16384, temperature = 0.7 } = body;

    if (!messages || !Array.isArray(messages) || messages.length === 0) {
        return json({ error: '`messages` array is required' }, 400);
    }

    const payload = {
        model:       model || DEFAULT_MODEL,
        messages,
        stream,
        max_tokens,
        temperature,
    };

    let nimResponse;
    try {
        nimResponse = await fetch(NVIDIA_API_URL, {
            method:  'POST',
            headers: {
                'Authorization': `Bearer ${apiKey.trim()}`,
                'Content-Type':  'application/json',
                'Accept':        stream ? 'text/event-stream' : 'application/json',
            },
            body: JSON.stringify(payload),
        });
    } catch (err) {
        return json({ error: 'Failed to reach NVIDIA API', detail: err.message }, 502);
    }

    if (!nimResponse.ok) {
        const errText = await nimResponse.text().catch(() => '');
        return json({ error: 'NVIDIA API error', status: nimResponse.status, body: errText }, nimResponse.status);
    }

    if (stream) {
        return new Response(nimResponse.body, {
            status: 200,
            headers: {
                ...corsHeaders(),
                'Content-Type':      'text/event-stream',
                'Cache-Control':     'no-cache',
                'X-Accel-Buffering': 'no',
            },
        });
    }

    const data = await nimResponse.json();
    return json(data, 200);
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

function json(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: { ...corsHeaders(), 'Content-Type': 'application/json' },
    });
}
