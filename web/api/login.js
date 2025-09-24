import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { kv as defaultKv } from '@vercel/kv';

let kv = defaultKv;
export function __setKv(obj) {
  kv = obj;
}
export function __resetKv() {
  kv = defaultKv;
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', ['POST']);
    return res.status(405).end(`Method ${req.method} Not Allowed`);
  }

  const { email, password } = req.body || {};
  if (!email) {
    return res.status(400).json({ message: 'Email required' });
  }

  const normalizedEmail = String(email).trim().toLowerCase();
  if (!normalizedEmail) {
    return res.status(400).json({ message: 'Email required' });
  }

  // Admin login if password provided
  if (typeof password !== 'undefined') {
    if (!password) {
      return res.status(400).json({ message: 'Email and password required' });
    }

    const ATTEMPT_KEY = 'admin_login_attempts';
    const now = Date.now();
    let attemptData = await kv.get(ATTEMPT_KEY) || { count: 0, delay: 0, lockUntil: 0 };

    async function recordAttempt() {
      attemptData.count = (attemptData.count || 0) + 1;
      if (attemptData.count >= 3) {
        attemptData.delay = attemptData.delay ? attemptData.delay * 2 : 60;
        attemptData.lockUntil = now + attemptData.delay * 1000;
      }
      await kv.set(ATTEMPT_KEY, attemptData);
      if (attemptData.count >= 3) {
        return res.status(429).json({ message: `Too many attempts. Try again in ${attemptData.delay}s`, wait: attemptData.delay, attempt: attemptData.count });
      }
      return null;
    }

    if (attemptData.lockUntil && now < attemptData.lockUntil) {
      const wait = Math.ceil((attemptData.lockUntil - now) / 1000);
      return res.status(429).json({ message: `Too many attempts. Try again in ${wait}s`, wait, attempt: attemptData.count });
    }

    const adminEmail = process.env.ADMIN_EMAIL;
    const passwordHash = process.env.ADMIN_PASSWORD_HASH;
    const jwtSecret = process.env.JWT_SECRET;

    if (!adminEmail || !passwordHash || !jwtSecret) {
      return res.status(500).json({ message: 'Server configuration missing' });
    }

    const adminEmailLower = adminEmail.trim().toLowerCase();

    if (normalizedEmail !== adminEmailLower) {
      const lockRes = await recordAttempt();
      if (lockRes) return lockRes;
      return res.status(401).json({ message: 'Invalid credentials', attempt: attemptData.count });
    }

    const match = await bcrypt.compare(password, passwordHash);
    if (!match) {
      const lockRes = await recordAttempt();
      if (lockRes) return lockRes;
      return res.status(401).json({ message: 'Invalid credentials', attempt: attemptData.count });
    }

    await kv.del(ATTEMPT_KEY);
    const token = jwt.sign({ email: adminEmail, role: 'admin' }, jwtSecret, { expiresIn: '7d' });
    res.status(200).json({ token });
    return;
  }

  // User login path
  const ATTEMPT_KEY = `user_login_attempt_${normalizedEmail}`;
  const now = Date.now();
  let attemptData = await kv.get(ATTEMPT_KEY) || { count: 0, delay: 0, lockUntil: 0 };

  if (attemptData.lockUntil && now < attemptData.lockUntil) {
    const wait = Math.ceil((attemptData.lockUntil - now) / 1000);
    return res.status(429).json({ message: `Too many attempts. Try again in ${wait}s`, wait, attempt: attemptData.count });
  }

  try {
    const recipients = await kv.get('recipients');
    const exists =
      Array.isArray(recipients) &&
      recipients.some(r => typeof r.email === 'string' && r.email.trim().toLowerCase() === normalizedEmail);
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
      return res.status(429).json({ message: `Too many attempts. Try again in ${attemptData.delay}s`, wait: attemptData.delay, attempt: attemptData.count });
    }

    return res.status(401).json({ message: 'Email not registered', attempt: attemptData.count });
  } catch (error) {
    console.error('Error checking recipient list:', error);
    return res.status(500).json({ message: 'Server error' });
  }
}
