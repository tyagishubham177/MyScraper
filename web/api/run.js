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

  // --- New: Fetch overall run details ---
  const runDetailsUrl = `https://api.github.com/repos/${repo}/actions/runs/${id}`;
  let runStatus = null, runConclusion = null, runStartedAt = null, runCompletedAt = null, runHtmlUrl = null;

  try {
    const runDetailsRes = await fetch(runDetailsUrl, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.github+json'
      }
    });
    if (runDetailsRes.ok) {
      const runDetailsData = await runDetailsRes.json();
      runStatus = runDetailsData.status;
      runConclusion = runDetailsData.conclusion;
      runStartedAt = runDetailsData.run_started_at; // Use run_started_at
      runCompletedAt = runDetailsData.completed_at;
      runHtmlUrl = runDetailsData.html_url;
    } else {
      console.error(`Failed to fetch run details: ${runDetailsRes.status} from ${runDetailsUrl}`);
      // Proceeding, frontend will show N/A or handle nulls for these fields
    }
  } catch (error) {
    console.error(`Error fetching run details from ${runDetailsUrl}: ${error.message}`);
    // Proceeding, frontend will show N/A or handle nulls for these fields
  }
  // --- End new section ---

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

  res.status(200).json({
    status: runStatus,
    conclusion: runConclusion,
    started_at: runStartedAt,
    completed_at: runCompletedAt,
    html_url: runHtmlUrl,
    step: stepInfo,
    artifacts
  });
}
