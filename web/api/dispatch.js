/*
export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).send('Method Not Allowed');
    return;
  }
  const repo = process.env.GH_REPO;
  const workflow = process.env.GH_WORKFLOW || 'schedule.yml';
  const ref = process.env.GH_REF || 'main';
  const token = process.env.GH_TOKEN;
  const url = `https://api.github.com/repos/${repo}/actions/workflows/${workflow}/dispatches`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Accept': 'application/vnd.github+json'
    },
    body: JSON.stringify({ ref })
  });
  if (response.status === 204) {
    res.status(200).send('Workflow dispatched');
  } else {
    const text = await response.text();
    res.status(response.status).send(text);
  }
}
*/
