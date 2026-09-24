/**
 * Contact form endpoint.
 *
 * Verifies a Cloudflare Turnstile token server-side, then relays the message
 * through Resend. The destination address lives only in TO_EMAIL, an encrypted
 * Worker secret — it never appears in the static site or in this repository.
 */

const MAX_LENGTHS = { name: 100, email: 200, message: 5000 };

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const allowed = origin === env.ALLOWED_ORIGIN;

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(env, allowed) });
    }
    if (request.method !== "POST") {
      return json({ error: "Method not allowed." }, 405, env, allowed);
    }
    // Reject cross-origin posts outright. Bots hitting the Worker directly send
    // no Origin header and stop here, before any quota is spent.
    if (!allowed) {
      return json({ error: "Forbidden." }, 403, env, false);
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return json({ error: "Malformed request." }, 400, env, allowed);
    }

    const name = str(body.name);
    const email = str(body.email);
    const message = str(body.message);
    const honeypot = str(body.company);
    const token = str(body.token);

    // A real visitor never sees this field, so anything in it is a bot. Return
    // 200 so the bot records a success and does not retry with a new strategy.
    if (honeypot) {
      return json({ ok: true }, 200, env, allowed);
    }

    if (!name || !email || !message) {
      return json({ error: "Please fill in every field." }, 400, env, allowed);
    }
    for (const [field, limit] of Object.entries(MAX_LENGTHS)) {
      if ({ name, email, message }[field].length > limit) {
        return json({ error: `The ${field} field is too long.` }, 400, env, allowed);
      }
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) {
      return json({ error: "Please enter a valid email address." }, 400, env, allowed);
    }
    if (!token) {
      return json({ error: "Verification missing. Please reload and try again." }, 400, env, allowed);
    }

    if (!(await verifyTurnstile(token, request, env))) {
      return json({ error: "Verification failed. Please reload and try again." }, 403, env, allowed);
    }

    const sent = await sendEmail({ name, email, message }, env);
    if (!sent.ok) {
      console.error("Resend failed:", sent.status, sent.detail);
      return json({ error: "Could not send the message. Please try again later." }, 502, env, allowed);
    }

    return json({ ok: true }, 200, env, allowed);
  },
};

async function verifyTurnstile(token, request, env) {
  const form = new FormData();
  form.append("secret", env.TURNSTILE_SECRET);
  form.append("response", token);
  const ip = request.headers.get("CF-Connecting-IP");
  if (ip) form.append("remoteip", ip);

  try {
    const response = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      { method: "POST", body: form }
    );
    const result = await response.json();
    return result.success === true;
  } catch (error) {
    console.error("Turnstile verification error:", error);
    return false;
  }
}

async function sendEmail({ name, email, message }, env) {
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: env.FROM_EMAIL,
      to: [env.TO_EMAIL],
      reply_to: email,
      subject: `Contact form: ${name}`,
      text: `From: ${name} <${email}>\n\n${message}`,
      html:
        `<p><strong>From:</strong> ${escapeHtml(name)} ` +
        `&lt;${escapeHtml(email)}&gt;</p><hr><p style="white-space:pre-wrap">` +
        `${escapeHtml(message)}</p>`,
    }),
  });

  if (response.ok) return { ok: true };
  return { ok: false, status: response.status, detail: await response.text() };
}

function str(value) {
  return typeof value === "string" ? value.trim() : "";
}

function escapeHtml(value) {
  return value.replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char]);
}

function corsHeaders(env, allowed) {
  const headers = {
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
  };
  if (allowed) headers["Access-Control-Allow-Origin"] = env.ALLOWED_ORIGIN;
  return headers;
}

function json(payload, status, env, allowed) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders(env, allowed) },
  });
}
