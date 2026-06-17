// functions/api/verify-turnstile.js
// Cloudflare Pages Function — Turnstile server-side verification
// Mapped automatically to /api/verify-turnstile by Cloudflare Pages
//
// Required environment variable (Cloudflare Pages → Settings → Environment Variables):
//   TURNSTILE_SECRET_KEY  — your Turnstile secret key

export async function onRequestPost(context) {
    const { request, env } = context;

    const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Content-Type': 'application/json',
    };

    try {
        const { token } = await request.json();

        if (!token) {
            return new Response(JSON.stringify({ success: false, error: 'No token provided' }), {
                status: 400,
                headers: corsHeaders,
            });
        }

        // Verify the token with Cloudflare's Turnstile API
        const formData = new FormData();
        formData.append('secret', env.TURNSTILE_SECRET_KEY);
        formData.append('response', token);
        formData.append('remoteip', request.headers.get('CF-Connecting-IP') || '');

        const verifyRes = await fetch(
            'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            { method: 'POST', body: formData }
        );

        const result = await verifyRes.json();

        if (result.success) {
            return new Response(JSON.stringify({ success: true }), {
                status: 200,
                headers: corsHeaders,
            });
        } else {
            return new Response(JSON.stringify({ success: false, error: result['error-codes'] }), {
                status: 403,
                headers: corsHeaders,
            });
        }
    } catch (err) {
        return new Response(JSON.stringify({ success: false, error: 'Server error' }), {
            status: 500,
            headers: corsHeaders,
        });
    }
}

export async function onRequestOptions() {
    return new Response(null, {
        status: 204,
        headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
        },
    });
}
