import { requireAdmin } from './auth.js';

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    res.status(405).send('Method Not Allowed');
    return;
  }
  if (!requireAdmin(req, res)) return;
  const repo = process.env.GH_REPO;
  const workflow = process.env.GH_WORKFLOW || 'schedule.yml';
  const token = process.env.GH_TOKEN;
  const url = `https://api.github.com/repos/${repo}/actions/workflows/${workflow}`;
  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      'Accept': 'application/vnd.github+json'
    }
  });
  if (!response.ok) {
    const text = await response.text();
    res.status(response.status).send(text);
    return;
  }
  const data = await response.json();
  res.status(200).json({ state: data.state });
}
