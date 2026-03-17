import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { kv as defaultKv } from '@vercel/kv';
import { listRecipients as listRecipientsFromKV } from './_kv-helpers.js';

let kv = defaultKv;
export function __setKv(obj) {
  kv = obj;
}
export function __resetKv() {
  kv = defaultKv;
}

function isKvUsable(client = kv) {
  if (!client) {
    return false;
  }

  if (client === defaultKv) {
    return !!(process.env.KV_REST_API_URL && process.env.KV_REST_API_TOKEN);
  }

  return typeof client.get === 'function' && typeof client.set === 'function';
}

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function getConfiguredAdminEmail() {
  return normalizeEmail(process.env.ADMIN_EMAIL || process.env.ADMIN_MAIL);
}

async function matchesConfiguredAdminPassword(password) {
  const passwordHash = process.env.ADMIN_PASSWORD_HASH;
  const plainPassword = process.env.ADMIN_PASSWORD;

  if (typeof plainPassword === 'string' && plainPassword && password === plainPassword) {
    return true;
  }

  if (typeof passwordHash === 'string' && passwordHash) {
    if (password === passwordHash) {
      return password === passwordHash;
    }
    try {
      return await bcrypt.compare(password, passwordHash);
    } catch (_) {
      return false;
    }
  }

  return false;
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

  const normalizedEmail = normalizeEmail(email);
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
    const canUseKv = isKvUsable();
    let attemptData = canUseKv
      ? (await kv.get(ATTEMPT_KEY)) || { count: 0, delay: 0, lockUntil: 0 }
      : { count: 0, delay: 0, lockUntil: 0 };

    async function recordAttempt() {
      attemptData.count = (attemptData.count || 0) + 1;
      if (attemptData.count >= 3) {
        attemptData.delay = attemptData.delay ? attemptData.delay * 2 : 60;
        attemptData.lockUntil = now + attemptData.delay * 1000;
      }
      if (!canUseKv) {
        return null;
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

    const adminEmail = getConfiguredAdminEmail();
    const jwtSecret = process.env.JWT_SECRET;
    const hasPasswordConfig = !!(process.env.ADMIN_PASSWORD_HASH || process.env.ADMIN_PASSWORD);

    if (!adminEmail || !hasPasswordConfig || !jwtSecret) {
      return res.status(500).json({ message: 'Server configuration missing' });
    }

    if (normalizedEmail !== adminEmail) {
      const lockRes = await recordAttempt();
      if (lockRes) return lockRes;
      return res.status(401).json({ message: 'Invalid credentials', attempt: attemptData.count });
    }

    const match = await matchesConfiguredAdminPassword(password);
    if (!match) {
      const lockRes = await recordAttempt();
      if (lockRes) return lockRes;
      return res.status(401).json({ message: 'Invalid credentials', attempt: attemptData.count });
    }

    if (canUseKv && typeof kv.del === 'function') {
      await kv.del(ATTEMPT_KEY);
    }
    const token = jwt.sign({ email: adminEmail, role: 'admin' }, jwtSecret, { expiresIn: '7d' });
    res.status(200).json({ token });
    return;
  }

  // User login path
  const ATTEMPT_KEY = `user_login_attempt_${normalizedEmail}`;
  const now = Date.now();
  const canUseKv = isKvUsable();
  let attemptData = canUseKv
    ? (await kv.get(ATTEMPT_KEY)) || { count: 0, delay: 0, lockUntil: 0 }
    : { count: 0, delay: 0, lockUntil: 0 };

  if (attemptData.lockUntil && now < attemptData.lockUntil) {
    const wait = Math.ceil((attemptData.lockUntil - now) / 1000);
    return res.status(429).json({ message: `Too many attempts. Try again in ${wait}s`, wait, attempt: attemptData.count });
  }

  try {
    const recipients = await listRecipientsFromKV(kv);
    const exists =
      Array.isArray(recipients) &&
      recipients.some(r => typeof r.email === 'string' && r.email.trim().toLowerCase() === normalizedEmail);
    if (exists) {
      if (canUseKv && typeof kv.del === 'function') {
        await kv.del(ATTEMPT_KEY);
      }
      return res.status(200).json({ message: 'ok' });
    }

    attemptData.count = (attemptData.count || 0) + 1;
    if (attemptData.count >= 3) {
      attemptData.delay = attemptData.delay ? attemptData.delay * 2 : 60;
      attemptData.lockUntil = now + attemptData.delay * 1000;
    }
    if (canUseKv && typeof kv.set === 'function') {
      await kv.set(ATTEMPT_KEY, attemptData);
    }

    if (attemptData.count >= 3) {
      return res.status(429).json({ message: `Too many attempts. Try again in ${attemptData.delay}s`, wait: attemptData.delay, attempt: attemptData.count });
    }

    return res.status(401).json({ message: 'Email not registered', attempt: attemptData.count });
  } catch (error) {
    console.error('Error checking recipient list:', error);
    return res.status(500).json({ message: 'Server error' });
  }
}
