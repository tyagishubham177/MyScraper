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

  const ATTEMPT_KEY = `user_login_attempt_${email}`;
  const now = Date.now();
  let attemptData = await kv.get(ATTEMPT_KEY) || { count: 0, delay: 0, lockUntil: 0 };

  if (attemptData.lockUntil && now < attemptData.lockUntil) {
    const wait = Math.ceil((attemptData.lockUntil - now) / 1000);
    return res.status(429).json({ message: `Too many attempts. Try again in ${wait}s`, wait });
  }

  try {
    const recipients = await kv.get('recipients');
    const exists = Array.isArray(recipients) && recipients.some(r => r.email === email);
    if (exists) {
      await kv.del(ATTEMPT_KEY);
      return res.status(200).json({ message: 'ok' });
    }

    attemptData.count = (attemptData.count || 0) + 1;
    if (attemptData.count >= 3) {
      attemptData.delay = attemptData.delay ? attemptData.delay * 2 : 60;
      attemptData.lockUntil = now + attemptData.delay * 1000;
    }
    await kv.set(ATTEMPT_KEY, attemptData);

    if (attemptData.count >= 3) {
      return res.status(429).json({ message: `Too many attempts. Try again in ${attemptData.delay}s`, wait: attemptData.delay });
    }

    return res.status(401).json({ message: 'Email not registered' });
  } catch (error) {
    console.error('Error checking recipient list:', error);
    return res.status(500).json({ message: 'Server error' });
  }
}
