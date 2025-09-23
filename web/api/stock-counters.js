import { requireAdmin } from '../utils/auth.js';
import { listStockCounters, saveStockCounters } from './data-store.js';

async function handleGet(req, res) {
  try {
    const data = await listStockCounters();
    res.status(200).json(data || {});
  } catch (err) {
    console.error('Error fetching stock counters from KV:', err);
    res.status(500).json({ message: 'Error retrieving counters' });
  }
}

async function handlePut(req, res) {
  if (!requireAdmin(req, res)) return;
  try {
    const { counters } = req.body || {};
    if (!counters || typeof counters !== 'object') {
      return res.status(400).json({ message: 'Invalid counters data' });
    }
    await saveStockCounters(counters);
    res.status(200).json({ message: 'Counters updated' });
  } catch (err) {
    console.error('Error saving stock counters to KV:', err);
    res.status(500).json({ message: 'Error saving counters' });
  }
}

export default async function handler(req, res) {
  const method = req.method;
  switch (method) {
    case 'GET':
      await handleGet(req, res);
      break;
    case 'PUT':
      await handlePut(req, res);
      break;
    default:
      res.setHeader('Allow', ['GET', 'PUT']);
      res.status(405).json({ message: `Method ${method} Not Allowed` });
  }
}
