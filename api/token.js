// api/token.js
// Vercel serverless function — runs server-side, credentials never exposed to browser

export default async function handler(req, res) {
  // Allow requests from our own app
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { action } = req.body;

  // ── Action: get a Google Sheets access token ──────────────────────────────
  if (action === 'google_token') {
    try {
      const privateKey = process.env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, '\n');
      const clientEmail = process.env.GOOGLE_CLIENT_EMAIL;

      const now = Math.floor(Date.now() / 1000);
      const header = { alg: 'RS256', typ: 'JWT' };
      const payload = {
        iss: clientEmail,
        scope: 'https://www.googleapis.com/auth/spreadsheets',
        aud: 'https://oauth2.googleapis.com/token',
        exp: now + 3600,
        iat: now
      };

      const b64 = obj => Buffer.from(JSON.stringify(obj))
        .toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

      const signingInput = `${b64(header)}.${b64(payload)}`;

      // Import key using Node crypto
      const { createSign } = await import('crypto');
      const sign = createSign('RSA-SHA256');
      sign.update(signingInput);
      const signature = sign.sign(privateKey, 'base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

      const jwt = `${signingInput}.${signature}`;

      const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`
      });

      const tokenData = await tokenRes.json();

      if (!tokenData.access_token) {
        return res.status(500).json({ error: 'Failed to get token', detail: tokenData });
      }

      return res.status(200).json({ token: tokenData.access_token });

    } catch (err) {
      return res.status(500).json({ error: 'Google auth failed', detail: err.message });
    }
  }

  // ── Action: proxy a Claude API call ──────────────────────────────────────
  if (action === 'claude') {
    try {
      const { messages, system } = req.body;

      const claudeRes = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': process.env.CLAUDE_API_KEY,
          'anthropic-version': '2023-06-01'
        },
        body: JSON.stringify({
          model: 'claude-sonnet-4-6',
          max_tokens: 1000,
          system,
          messages
        })
      });

      const data = await claudeRes.json();
      return res.status(200).json(data);

    } catch (err) {
      return res.status(500).json({ error: 'Claude API failed', detail: err.message });
    }
  }

  return res.status(400).json({ error: 'Unknown action' });
}
