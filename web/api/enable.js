/*
export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).send('Method Not Allowed');
    return;
  }
  const repo = process.env.GH_REPO;
  const workflow = process.env.GH_WORKFLOW || 'schedule.yml';
  const token = process.env.GH_TOKEN;
  const url = `https://api.github.com/repos/${repo}/actions/workflows/${workflow}/enable`;
  const response = await fetch(url, {
    method: 'PUT',
    headers: {
      Authorization: `Bearer ${token}`,
      'Accept': 'application/vnd.github+json'
    }
  });
  if (response.status === 204) {
    res.status(200).send('Workflow enabled');
  } else {
    const text = await response.text();
    res.status(response.status).send(text);
  }
}
*/
