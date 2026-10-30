// In development, Vite proxies /api → localhost:8000 (see vite.config.js).
// In production (Vercel), /api is rewritten to the Render backend via vercel.json.
// Override with VITE_API_BASE env var if needed.
const BASE = import.meta.env.VITE_API_BASE ?? "/api";

export async function analyze(payload) {
  let res;
  try {
    res = await fetch(`${BASE}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  } catch {
    throw new Error(
      "Cannot reach the backend. Make sure the FastAPI server is running on port 8000."
    );
  }

  if (!res.ok) {
    let detail = `Request failed (${res.status})`;
    try {
      const body = await res.json();
      if (body?.detail) {
        detail = typeof body.detail === "string"
          ? body.detail
          : JSON.stringify(body.detail);
      }
    } catch {
      try { detail = await res.text() || detail; } catch {}
    }
    if (res.status === 500) {
      detail = `Server error (500). ${detail}. Check the backend terminal for the Python traceback.`;
    }
    throw new Error(detail);
  }
  return res.json();
}

export async function getHistory(limit = 20) {
  try {
    const res = await fetch(`${BASE}/history?limit=${limit}`);
    if (!res.ok) return [];
    return res.json();
  } catch {
    return [];
  }
}
