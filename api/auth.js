const crypto = require('crypto');

// ADMIN_HASH = SHA-256 de "Drak2030#"
// JWT_SECRET = string aleatória longa (configure em Vercel env vars)
const ADMIN_HASH = process.env.ADMIN_HASH || '62bb942352939e19c338bfcc4ef194221dcc45eaa242917286bdaffccd6ee7f1';
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret_in_vercel';

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { password } = req.body || {};
  if (!password) return res.status(400).json({ error: 'Missing password' });

  const hash = crypto.createHash('sha256').update(password).digest('hex');

  if (!crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(ADMIN_HASH))) {
    return res.status(401).json({ error: 'Senha incorreta' });
  }

  const payload = JSON.stringify({ role: 'admin', exp: Date.now() + 4 * 3600 * 1000 });
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(payload).digest('hex');
  const token = Buffer.from(payload).toString('base64') + '.' + sig;

  res.json({ token });
};
