const crypto = require('crypto');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;
const BC_API_KEY   = process.env.BC_API_KEY || '';
const JWT_SECRET   = process.env.JWT_SECRET || 'change_this_secret_in_vercel';

// ── Auth ──────────────────────────────────────────────────────────────
function verifyToken(token) {
  try {
    const [b64, sig] = token.split('.');
    const payload = Buffer.from(b64, 'base64').toString('utf8');
    const expected = crypto.createHmac('sha256', JWT_SECRET).update(payload).digest('hex');
    if (sig.length !== expected.length) return null;
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
    const data = JSON.parse(payload);
    if (data.exp < Date.now()) return null;
    return data;
  } catch { return null; }
}

// ── Supabase helpers ───────────────────────────────────────────────────
async function sbFetch(path, opts = {}) {
  const url = `${SUPABASE_URL}/rest/v1/${path}`;
  return fetch(url, {
    ...opts,
    headers: {
      apikey: SUPABASE_KEY,
      Authorization: `Bearer ${SUPABASE_KEY}`,
      'Content-Type': 'application/json',
      ...(opts.headers || {}),
    },
  });
}

async function readConfig() {
  const r = await sbFetch('site_config?id=eq.1&select=data');
  const rows = await r.json();
  return rows[0]?.data || {};
}

async function writeConfig(data) {
  const r = await sbFetch('site_config?id=eq.1', {
    method: 'PATCH',
    headers: { Prefer: 'return=minimal' },
    body: JSON.stringify({ data, updated_at: new Date().toISOString() }),
  });
  if (!r.ok) throw new Error(`Supabase error: ${r.status} ${await r.text()}`);
}

// ── Handler ────────────────────────────────────────────────────────────
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') return res.status(200).end();

  // GET — retorna config + bc_api_key do env (nunca exposta no código)
  if (req.method === 'GET') {
    try {
      const cfg = await readConfig();
      return res.json({ ...cfg, bcApiKey: BC_API_KEY });
    } catch (e) {
      console.error(e);
      return res.status(500).json({ error: e.message });
    }
  }

  // POST — salva config (requer JWT válido)
  if (req.method === 'POST') {
    const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
    if (!verifyToken(token)) return res.status(401).json({ error: 'Não autorizado' });

    try {
      // Nunca salva bcApiKey no banco (fica no env var)
      const { bcApiKey: _ignored, ...configData } = req.body;
      await writeConfig(configData);
      return res.json({ ok: true });
    } catch (e) {
      console.error(e);
      return res.status(500).json({ error: e.message });
    }
  }

  res.status(405).end();
};
