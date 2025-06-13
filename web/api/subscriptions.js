import { kv } from '@vercel/kv';

async function getFromKV(key) {
  try {
    const data = await kv.get(key);
    return data ? data : [];
  } catch (error) {
    console.error(`Error fetching ${key} from KV:`, error);
    return [];
  }
}

async function saveToKV(key, data) {
  try {
    await kv.set(key, data);
  } catch (error) {
    console.error(`Error saving ${key} to KV:`, error);
    throw new Error(`Could not save ${key} to KV.`);
  }
}

export default async function handler(req, res) {
  const { method } = req;

  switch (method) {
    case 'POST':
      try {
        const { recipient_id, product_id } = req.body;
        if (!recipient_id || !product_id) {
          return res.status(400).json({ message: 'Recipient ID and Product ID are required' });
        }

        const recipients = await getFromKV('recipients');
        if (!recipients.some(r => r.id === recipient_id)) {
          return res.status(404).json({ message: 'Recipient not found' });
        }

        const products = await getFromKV('products');
        if (!products.some(p => p.id === product_id)) {
          return res.status(404).json({ message: 'Product not found' });
        }

        const subs = await getFromKV('subscriptions');
        const existing = subs.find(s => s.recipient_id === recipient_id && s.product_id === product_id);
        if (existing) {
          return res.status(200).json(existing);
        }

        const newSub = { id: String(Date.now()), recipient_id, product_id };
        subs.push(newSub);
        await saveToKV('subscriptions', subs);
        res.status(201).json(newSub);
      } catch (error) {
        console.error('Error in POST /api/subscriptions:', error);
        res.status(500).json({ message: 'Error creating subscription in KV', error: error.message });
      }
      break;

    case 'DELETE':
      try {
        const { recipient_id, product_id } = req.body;
        if (!recipient_id || !product_id) {
          return res.status(400).json({ message: 'Recipient ID and Product ID are required in the request body' });
        }

        const subs = await getFromKV('subscriptions');
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
      break;

    case 'GET':
      try {
        const { recipient_id, product_id } = req.query;
        const subs = await getFromKV('subscriptions');

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
      break;

    default:
      res.setHeader('Allow', ['GET', 'POST', 'DELETE']);
      res.status(405).json({ message: `Method ${method} Not Allowed` });
  }
}
