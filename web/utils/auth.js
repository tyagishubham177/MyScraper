import jwt from 'jsonwebtoken';

export function requireAdmin(req, res) {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    res.status(500).json({ message: 'Server configuration missing' });
    return null;
  }
  const authHeader = req.headers['authorization'] || req.headers['Authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ message: 'Missing auth token' });
    return null;
  }
  const token = authHeader.slice(7);
  try {
    const decoded = jwt.verify(token, secret);
    if (decoded.role !== 'admin') {
      res.status(403).json({ message: 'Forbidden' });
      return null;
    }
    return decoded;
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
    return null;
  }
}
