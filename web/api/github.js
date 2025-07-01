import { requireAdmin as defaultRequireAdmin } from '../utils/auth.js';
let requireAdmin = defaultRequireAdmin;
export function __setRequireAdmin(fn){requireAdmin = fn;}
export function __resetRequireAdmin(){requireAdmin = defaultRequireAdmin;}


export default async function handler(req, res) {
  if (req.method !== 'GET') {
    res.status(405).send('Method Not Allowed');
    return;
  }
  if (!requireAdmin(req, res)) return;

  const { action, id } = req.query;
  const repo = process.env.GH_REPO;
  const token = process.env.GH_TOKEN;
  const workflow = process.env.GH_WORKFLOW || 'schedule.yml';

  if (!action) {
    res.status(400).json({ message: 'Missing action' });
    return;
  }

  switch (action) {
    case 'status': {
      const url = `https://api.github.com/repos/${repo}/actions/workflows/${workflow}`;
      const resp = await fetch(url, {
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json' }
      });
      if (!resp.ok) {
        const text = await resp.text();
        res.status(resp.status).send(text);
        return;
      }
      const data = await resp.json();
      res.status(200).json({ state: data.state });
      break;
    }
    case 'runs': {
      const url = `https://api.github.com/repos/${repo}/actions/workflows/${workflow}/runs?per_page=5`;
      const resp = await fetch(url, {
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json' }
      });
      if (!resp.ok) {
        const text = await resp.text();
        res.status(resp.status).send(text);
        return;
      }
      const data = await resp.json();
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
      break;
    }
    case 'run': {
      if (!id) {
        res.status(400).send('Missing id');
        return;
      }
      const runDetailsUrl = `https://api.github.com/repos/${repo}/actions/runs/${id}`;
      let runStatus = null, runConclusion = null, runStartedAt = null, runCompletedAt = null, runHtmlUrl = null;
      try {
        const runDetailsRes = await fetch(runDetailsUrl, { headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json' } });
        if (runDetailsRes.ok) {
          const runDetailsData = await runDetailsRes.json();
          runStatus = runDetailsData.status;
          runConclusion = runDetailsData.conclusion;
          runStartedAt = runDetailsData.run_started_at;
          runCompletedAt = runDetailsData.completed_at;
          runHtmlUrl = runDetailsData.html_url;
        }
      } catch (err) {
        console.error(`Error fetching run details from ${runDetailsUrl}: ${err.message}`);
      }
      const jobsUrl = `https://api.github.com/repos/${repo}/actions/runs/${id}/jobs`;
      const jobsRes = await fetch(jobsUrl, { headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json' } });
      if (!jobsRes.ok) {
        const text = await jobsRes.text();
        res.status(jobsRes.status).send(text);
        return;
      }
      const jobsData = await jobsRes.json();
      let stepInfo = null;
      for (const job of jobsData.jobs) {
        if (job.steps) {
          const step = job.steps.find(s => s.name === 'Run stock checker');
          if (step) {
            stepInfo = {
              status: step.status,
              conclusion: step.conclusion,
              started_at: step.started_at,
              completed_at: step.completed_at
            };
            break;
          }
        }
      }
      const artUrl = `https://api.github.com/repos/${repo}/actions/runs/${id}/artifacts`;
      const artRes = await fetch(artUrl, { headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json' } });
      let artifacts = [];
      if (artRes.ok) {
        const artData = await artRes.json();
        artifacts = artData.artifacts.map(a => ({ id: a.id, name: a.name }));
      }
      res.status(200).json({ status: runStatus, conclusion: runConclusion, started_at: runStartedAt, completed_at: runCompletedAt, html_url: runHtmlUrl, step: stepInfo, artifacts });
      break;
    }
    case 'logs': {
      if (!id) {
        res.status(400).send('Missing id');
        return;
      }
      const url = `https://api.github.com/repos/${repo}/actions/runs/${id}/logs`;
      const resp = await fetch(url, { headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json' } });
      if (!resp.ok) {
        const text = await resp.text();
        res.status(resp.status).send(text);
        return;
      }
      const buffer = Buffer.from(await resp.arrayBuffer());
      res.setHeader('Content-Type', 'application/zip');
      res.send(buffer);
      break;
    }
    case 'artifact': {
      if (!id) {
        res.status(400).send('Missing id');
        return;
      }
      const url = `https://api.github.com/repos/${repo}/actions/artifacts/${id}/zip`;
      const resp = await fetch(url, { headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json' } });
      if (!resp.ok) {
        const text = await resp.text();
        res.status(resp.status).send(text);
        return;
      }
      const buffer = Buffer.from(await resp.arrayBuffer());
      res.setHeader('Content-Type', 'application/zip');
      res.send(buffer);
      break;
    }
    default:
      res.status(400).json({ message: 'Invalid action' });
  }
}
