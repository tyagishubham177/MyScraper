import { kv } from '@vercel/kv';

let kvClient = kv;

export function __setKv(mock) {
  kvClient = mock;
}

export function __resetKv() {
  kvClient = kv;
}

async function getFromKV(key) {
  try {
    const data = await kvClient.get(key);
    return data ? data : [];
  } catch (error) {
    console.error(`Error fetching ${key} from KV:`, error);
    throw error;
  }
}

async function saveToKV(key, data) {
  try {
    await kvClient.set(key, data);
  } catch (error) {
    console.error(`Error saving ${key} to KV:`, error);
    throw new Error(`Could not save ${key} to KV.`);
  }
}


async function handlePost(req, res) {
  try {
    const { recipient_id, product_id, start_time, end_time, paused } = req.body || {};
    if (!recipient_id || !product_id) {
      return res.status(400).json({ message: 'Recipient ID and Product ID are required' });
    }

    const timeRegex = /^([01]\d|2[0-3]):([0-5]\d)$/;
    const start = timeRegex.test(start_time) ? start_time : '00:00';
    const end = timeRegex.test(end_time) ? end_time : '23:59';

    const recipients = await getFromKV('recipients');
    if (!recipients.some(r => r.id === recipient_id)) {
      return res.status(404).json({ message: 'Recipient not found' });
    }

    const products = await getFromKV('products');
    if (!products.some(p => p.id === product_id)) {
      return res.status(404).json({ message: 'Product not found' });
    }

    let subs = await getFromKV('subscriptions');
    subs = subs.map(s => ({
      ...s,
      start_time: s.start_time || '00:00',
      end_time: s.end_time || '23:59',
      paused: !!s.paused
    }));
    const existing = subs.find(s => s.recipient_id === recipient_id && s.product_id === product_id);
    if (existing) {
      existing.start_time = start;
      existing.end_time = end;
      existing.paused = !!paused;
      await saveToKV('subscriptions', subs);
      return res.status(200).json(existing);
    }

    const newSub = {
      id: String(Date.now()),
      recipient_id,
      product_id,
      start_time: start,
      end_time: end,
      paused: !!paused
    };
    subs.push(newSub);
    await saveToKV('subscriptions', subs);
    res.status(201).json(newSub);
  } catch (error) {
    console.error('Error in POST /api/subscriptions:', error);
    res.status(500).json({ message: 'Error creating subscription in KV', error: error.message });
  }
}

async function handleDelete(req, res) {
  try {
    const { recipient_id, product_id } = req.body;
    if (!recipient_id || !product_id) {
      return res.status(400).json({ message: 'Recipient ID and Product ID are required in the request body' });
    }

    let subs = await getFromKV('subscriptions');
    subs = subs.map(s => ({
      ...s,
      start_time: s.start_time || '00:00',
      end_time: s.end_time || '23:59',
      paused: !!s.paused
    }));
    const updated = subs.filter(s => !(s.recipient_id === recipient_id && s.product_id === product_id));
    if (updated.length === subs.length) {
      return res.status(404).json({ message: 'Subscription not found' });
    }

    await saveToKV('subscriptions', updated);
    res.status(200).json({ message: 'Subscription deleted successfully' });
  } catch (error) {
    console.error('Error in DELETE /api/subscriptions:', error);
    res.status(500).json({ message: 'Error deleting subscription from KV', error: error.message });
  }
}

async function handleGet(req, res) {
  try {
    const { recipient_id, product_id } = req.query;
    let subs = await getFromKV('subscriptions');
    subs = subs.map(s => ({
      ...s,
      start_time: s.start_time || '00:00',
      end_time: s.end_time || '23:59',
      paused: !!s.paused
    }));

    if (recipient_id && product_id) {
      return res.status(400).json({ message: 'Provide either recipient_id OR product_id, not both.' });
    }

    if (recipient_id) {
      res.status(200).json(subs.filter(s => s.recipient_id === recipient_id));
    } else if (product_id) {
      res.status(200).json(subs.filter(s => s.product_id === product_id));
    } else {
      res.status(200).json(subs);
    }
  } catch (error) {
    console.error('Error in GET /api/subscriptions:', error);
    res.status(500).json({ message: 'Error retrieving subscriptions from KV', error: error.message });
  }
}

export default async function handler(req, res) {
  const { method } = req;

  switch (method) {
    case 'POST':
      await handlePost(req, res);
      break;
    case 'DELETE':
      await handleDelete(req, res);
      break;
    case 'GET':
      await handleGet(req, res);
      break;
    default:
      res.setHeader('Allow', ['GET', 'POST', 'DELETE']);
      res.status(405).json({ message: `Method ${method} Not Allowed` });
  }
}
