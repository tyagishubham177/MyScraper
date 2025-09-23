import { kv } from '@vercel/kv';
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
      const cacheKey = `gh:status:${workflow}`;
      const cached = await getCachedJson(cacheKey);
      if (cached) {
        res.status(200).json(cached);
        break;
      }
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
      const payload = { state: data.state };
      await setCachedJson(cacheKey, payload, STATUS_CACHE_TTL);
      res.status(200).json(payload);
      break;
    }
    case 'runs': {
      const cacheKey = `gh:runs:${workflow}`;
      const cached = await getCachedJson(cacheKey);
      if (cached) {
        res.status(200).json(cached);
        break;
      }
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
      const payload = { runs };
      await setCachedJson(cacheKey, payload, RUNS_CACHE_TTL);
      res.status(200).json(payload);
      break;
    }
    case 'run': {
      if (!id) {
        res.status(400).send('Missing id');
        return;
      }
      const cacheKey = `gh:run:${id}`;
      const cached = await getCachedJson(cacheKey);
      if (cached) {
        res.status(200).json(cached);
        break;
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
      const payload = { status: runStatus, conclusion: runConclusion, started_at: runStartedAt, completed_at: runCompletedAt, html_url: runHtmlUrl, step: stepInfo, artifacts };
      await setCachedJson(cacheKey, payload, RUN_CACHE_TTL);
      res.status(200).json(payload);
      break;
    }
    case 'logs': {
      if (!id) {
        res.status(400).send('Missing id');
        return;
      }
      const cacheKey = `gh:logs:${id}`;
      const cachedBuffer = await getCachedBuffer(cacheKey);
      if (cachedBuffer) {
        res.setHeader('Content-Type', 'application/zip');
        res.send(cachedBuffer);
        break;
      }
      const url = `https://api.github.com/repos/${repo}/actions/runs/${id}/logs`;
      const resp = await fetch(url, { headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json' } });
      if (!resp.ok) {
        const text = await resp.text();
        res.status(resp.status).send(text);
        return;
      }
      const buffer = Buffer.from(await resp.arrayBuffer());
      await setCachedBuffer(cacheKey, buffer, LOG_CACHE_TTL);
      res.setHeader('Content-Type', 'application/zip');
      res.send(buffer);
      break;
    }
    case 'artifact': {
      if (!id) {
        res.status(400).send('Missing id');
        return;
      }
      const cacheKey = `gh:artifact:${id}`;
      const cachedBuffer = await getCachedBuffer(cacheKey);
      if (cachedBuffer) {
        res.setHeader('Content-Type', 'application/zip');
        res.send(cachedBuffer);
        break;
      }
      const url = `https://api.github.com/repos/${repo}/actions/artifacts/${id}/zip`;
      const resp = await fetch(url, { headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json' } });
      if (!resp.ok) {
        const text = await resp.text();
        res.status(resp.status).send(text);
        return;
      }
      const buffer = Buffer.from(await resp.arrayBuffer());
      await setCachedBuffer(cacheKey, buffer, ARTIFACT_CACHE_TTL);
      res.setHeader('Content-Type', 'application/zip');
      res.send(buffer);
      break;
    }
    default:
      res.status(400).json({ message: 'Invalid action' });
  }
}
const STATUS_CACHE_TTL = 30;
const RUNS_CACHE_TTL = 30;
const RUN_CACHE_TTL = 45;
const LOG_CACHE_TTL = 300;
const ARTIFACT_CACHE_TTL = 300;

async function getCachedJson(key) {
  try {
    return await kv.get(key);
  } catch (err) {
    console.warn(`KV get failed for ${key}:`, err);
    return null;
  }
}

async function setCachedJson(key, value, ttlSeconds) {
  try {
    await kv.set(key, value, { ex: ttlSeconds });
  } catch (err) {
    console.warn(`KV set failed for ${key}:`, err);
  }
}

async function getCachedBuffer(key) {
  try {
    const cached = await kv.get(key);
    if (typeof cached === 'string') {
      return Buffer.from(cached, 'base64');
    }
  } catch (err) {
    console.warn(`KV get buffer failed for ${key}:`, err);
  }
  return null;
}

async function setCachedBuffer(key, buffer, ttlSeconds) {
  try {
    await kv.set(key, buffer.toString('base64'), { ex: ttlSeconds });
  } catch (err) {
    console.warn(`KV set buffer failed for ${key}:`, err);
  }
}
