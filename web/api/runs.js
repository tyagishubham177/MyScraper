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
  const url = `https://api.github.com/repos/${repo}/actions/workflows/${workflow}/runs?per_page=5`;
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
  const runs = data.workflow_runs.map(run => ({
    id: run.id,
    name: run.name,
    status: run.status,
    conclusion: run.conclusion,
    url: run.html_url,
    created_at: run.created_at,
    updated_at: run.updated_at
  }));
  res.status(200).json({ runs });
}
