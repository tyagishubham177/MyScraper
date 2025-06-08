export default async function handler(req, res) {
  if (req.method !== 'GET') {
    res.status(405).send('Method Not Allowed');
    return;
  }
  const { id } = req.query;
  if (!id) {
    res.status(400).send('Missing id');
    return;
  }
  const repo = process.env.GH_REPO;
  const token = process.env.GH_TOKEN;

  const jobsUrl = `https://api.github.com/repos/${repo}/actions/runs/${id}/jobs`;
  const jobsRes = await fetch(jobsUrl, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json'
    }
  });
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
  const artRes = await fetch(artUrl, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json'
    }
  });
  let artifacts = [];
  if (artRes.ok) {
    const artData = await artRes.json();
    artifacts = artData.artifacts.map(a => ({ id: a.id, name: a.name }));
  }

  res.status(200).json({ step: stepInfo, artifacts });
}
