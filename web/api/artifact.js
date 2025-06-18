import { requireAdmin as defaultRequireAdmin } from './auth.js';

let requireAdmin = defaultRequireAdmin;
export function __setRequireAdmin(fn) {
  requireAdmin = fn;
}
export function __resetRequireAdmin() {
  requireAdmin = defaultRequireAdmin;
}

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    res.status(405).send('Method Not Allowed');
    return;
  }
  if (!requireAdmin(req, res)) return;
  const { id } = req.query;
  if (!id) {
    res.status(400).send('Missing id');
    return;
  }
  const repo = process.env.GH_REPO;
  const token = process.env.GH_TOKEN;
  const url = `https://api.github.com/repos/${repo}/actions/artifacts/${id}/zip`;
  const resp = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json'
    }
  });
  if (!resp.ok) {
    const text = await resp.text();
    res.status(resp.status).send(text);
    return;
  }
  const buffer = Buffer.from(await resp.arrayBuffer());
  res.setHeader('Content-Type', 'application/zip');
  res.send(buffer);
}
