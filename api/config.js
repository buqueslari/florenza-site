const crypto = require('crypto');

const GH_TOKEN   = process.env.GH_TOKEN;
const GH_REPO    = 'buqueslari/florenza-site';
const GH_FILE    = 'config.json';
const BC_API_KEY = process.env.BC_API_KEY || '';
const JWT_SECRET = process.env.JWT_SECRET || 'change_me';

// ── Auth ──────────────────────────────────────────────────────────────
function verifyToken(token) {
  try {
    const [b64, sig] = token.split('.');
    const payload = Buffer.from(b64, 'base64').toString('utf8');
    const expected = crypto.createHmac('sha256', JWT_SECRET).update(payload).digest('hex');
    if (sig.length !== expected.length) return null;
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
    const data = JSON.parse(payload);
    return data.exp > Date.now() ? data : null;
  } catch { return null; }
}

// ── GitHub helpers ────────────────────────────────────────────────────
const GH_API = `https://api.github.com/repos/${GH_REPO}/contents/${GH_FILE}`;

async function readConfig() {
  const r = await fetch(GH_API, {
    headers: { Authorization: `token ${GH_TOKEN}`, Accept: 'application/vnd.github.v3+json' }
  });
  const meta = await r.json();
  const content = Buffer.from(meta.content, 'base64').toString('utf8');
  return { data: JSON.parse(content), sha: meta.sha };
}

async function writeConfig(data, sha) {
  const content = Buffer.from(JSON.stringify(data, null, 2)).toString('base64');
  const r = await fetch(GH_API, {
    method: 'PUT',
    headers: {
      Authorization: `token ${GH_TOKEN}`,
      'Content-Type': 'application/json',
      Accept: 'application/vnd.github.v3+json',
    },
    body: JSON.stringify({ message: 'Config atualizada via admin', content, sha }),
  });
  if (!r.ok) {
    const err = await r.json();
    throw new Error(err.message || r.status);
  }
}

// ── Handler ────────────────────────────────────────────────────────────
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  if (req.method === 'GET') {
    try {
      const { data } = await readConfig();
      return res.json({ ...data, bcApiKey: BC_API_KEY });
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  }

  if (req.method === 'POST') {
    const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
    if (!verifyToken(token)) return res.status(401).json({ error: 'Não autorizado' });
    try {
      const { bcApiKey: _ignored, ...configData } = req.body;
      const { sha } = await readConfig();
      await writeConfig(configData, sha);
      return res.json({ ok: true });
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  }

  res.status(405).end();
};
