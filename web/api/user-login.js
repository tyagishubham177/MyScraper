import { kv } from '@vercel/kv';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', ['POST']);
    return res.status(405).end(`Method ${req.method} Not Allowed`);
  }

  const { email } = req.body || {};
  if (!email) {
    return res.status(400).json({ message: 'Email required' });
  }

  try {
    const recipients = await kv.get('recipients');
    const exists = Array.isArray(recipients) && recipients.some(r => r.email === email);
    if (exists) {
      return res.status(200).json({ message: 'ok' });
    }
    return res.status(401).json({ message: 'Email not registered' });
  } catch (error) {
    console.error('Error checking recipient list:', error);
    return res.status(500).json({ message: 'Server error' });
  }
}
