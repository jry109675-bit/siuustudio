// functions/api/tavily.js
// Cloudflare Pages Function — Tavily Search API proxy
// Mapped automatically to /api/tavily by Cloudflare Pages

export async function onRequestPost(context) {
    const { request, env } = context;

    const apiKey = env.TAVILY_API_KEY;
    if (!apiKey) {
        return new Response(JSON.stringify({ error: 'Tavily API key not configured' }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' },
        });
    }

    let body;
    try {
        body = await request.json();
    } catch {
        return new Response(JSON.stringify({ error: 'Invalid JSON body' }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' },
        });
    }

    const upstream = await fetch('https://api.tavily.com/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...body, api_key: apiKey }),
    });

    const data = await upstream.json();

    return new Response(JSON.stringify(data), {
        status: upstream.status,
        headers: {
            'Content-Type':  'application/json',
            'Cache-Control': 'no-store',
            'Access-Control-Allow-Origin': '*',
        },
    });
}

export async function onRequestOptions() {
    return new Response(null, {
        status: 204,
        headers: {
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
        },
    });
}
