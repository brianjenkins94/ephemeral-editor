export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/api/oauth/callback") {
      return handleOAuthCallback(request, env.SESSIONS, env);
    }

    if (url.pathname === "/api/github/user") {
      return handleWhoami(request, env.SESSIONS);
    }

    return new Response("Not found", { status: 404 });
  }
};

// OAuth callback → GitHub token exchange → set session cookie
async function handleOAuthCallback(request, kv, env) {
  const code = new URL(request.url).searchParams.get("code");
  if (!code) return new Response("Missing code", { status: 400 });

  const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: { Accept: "application/json" },
    body: new URLSearchParams({
      client_id: env.GITHUB_CLIENT_ID,
      client_secret: env.GITHUB_CLIENT_SECRET,
      code
    })
  });

  const { access_token } = await tokenRes.json();
  if (!access_token) return new Response("OAuth failed", { status: 401 });

  const sessionId = crypto.randomUUID();
  await kv.put(`session:${sessionId}`, access_token, { expirationTtl: 3600 });

  return new Response(null, {
    status: 302,
    headers: {
      "Location": "/editor",
      "Set-Cookie": [
        `session_id=${sessionId}`,
        `Path=/`,
        `HttpOnly`,
        `Secure`,
        `SameSite=Lax`,
        `Max-Age=3600`
      ].join("; ")
    }
  });
}

// Authenticated endpoint using stored session
async function handleWhoami(request, kv) {
  const cookieHeader = request.headers.get("Cookie") || "";
  const cookies = Object.fromEntries(
    cookieHeader.split("; ").map(c => c.split("=").map(decodeURIComponent))
  );

  const sessionId = cookies.session_id;
  if (!sessionId) return new Response("Unauthorized", { status: 401 });

  const token = await kv.get(`session:${sessionId}`);
  if (!token) return new Response("Session expired", { status: 403 });

  const res = await fetch("https://api.github.com/user", {
    headers: { Authorization: `token ${token}` }
  });

  return new Response(await res.text(), {
    status: res.status,
    headers: { "Content-Type": "application/json" }
  });
}