import { kv } from '@vercel/kv';

// KV Helper functions
async function getFromKV(key) {
  try {
    const data = await kv.get(key);
    return data ? data : [];
  } catch (error) {
    console.error(`Error fetching ${key} from KV:`, error);
    return []; // Return empty array on error to prevent breaking main logic
  }
}

async function saveToKV(key, dataArray) {
  try {
    await kv.set(key, dataArray);
  } catch (error) {
    console.error(`Error saving ${key} to KV:`, error);
    throw new Error(`Could not save ${key} to KV.`);
  }
}

// Main request handler
export default async function handler(req, res) {
  const { method } = req;

  switch (method) {
    case 'POST':
      try {
        const { recipient_id, product_id } = req.body;

        if (!recipient_id || !product_id) {
          return res.status(400).json({ message: 'Recipient ID and Product ID are required' });
        }

        // Validate recipient and product existence
        const recipients = await getFromKV('recipients');
        if (!recipients.some(r => r.id === recipient_id)) {
          return res.status(404).json({ message: 'Recipient not found' });
        }

        const products = await getFromKV('products');
        if (!products.some(p => p.id === product_id)) {
          return res.status(404).json({ message: 'Product not found' });
        }

        const currentSubscriptions = await getFromKV('subscriptions');
        const existingSubscription = currentSubscriptions.find(
          s => s.recipient_id === recipient_id && s.product_id === product_id
        );

        if (existingSubscription) {
          return res.status(200).json({ message: 'Subscription already exists', subscription: existingSubscription });
        }

        const newSubscription = {
          id: String(Date.now()), // Simple ID generation
          recipient_id: recipient_id,
          product_id: product_id,
        };

        currentSubscriptions.push(newSubscription);
        await saveToKV('subscriptions', currentSubscriptions);
        res.status(201).json(newSubscription);
      } catch (error) {
        console.error("Error in POST /api/subscriptions:", error);
        res.status(500).json({ message: 'Error creating subscription in KV', error: error.message });
      }
      break;

    case 'DELETE':
      try {
        // Vercel KV and serverless functions typically expect DELETE body for complex identifiers
        const { recipient_id, product_id } = req.body;

        if (!recipient_id || !product_id) {
          return res.status(400).json({ message: 'Recipient ID and Product ID are required in the request body' });
        }

        let currentSubscriptions = await getFromKV('subscriptions');
        const initialCount = currentSubscriptions.length;

        const updatedSubscriptions = currentSubscriptions.filter(
          s => !(s.recipient_id === recipient_id && s.product_id === product_id)
        );

        if (updatedSubscriptions.length === initialCount) {
          return res.status(404).json({ message: 'Subscription not found' });
        }

        await saveToKV('subscriptions', updatedSubscriptions);
        res.status(200).json({ message: 'Subscription deleted successfully' });
      } catch (error) {
        console.error("Error in DELETE /api/subscriptions:", error);
        res.status(500).json({ message: 'Error deleting subscription from KV', error: error.message });
      }
      break;

    case 'GET':
      try {
        const { recipient_id, product_id } = req.query;
        const subscriptions = await getFromKV('subscriptions');

        if (recipient_id && product_id) {
          return res.status(400).json({ message: 'Provide either recipient_id OR product_id, not both.' });
        }

        if (recipient_id) {
          const recipientSubscriptions = subscriptions.filter(s => s.recipient_id === recipient_id);
          res.status(200).json(recipientSubscriptions);
        } else if (product_id) {
          const productSubscriptions = subscriptions.filter(s => s.product_id === product_id);
          res.status(200).json(productSubscriptions);
        } else {
          // As per original logic, require a query parameter
          return res.status(400).json({ message: 'Missing recipient_id or product_id query parameter.' });
          // Alternatively, to return all subscriptions:
          // res.status(200).json(subscriptions);
        }
      } catch (error) {
        console.error("Error in GET /api/subscriptions:", error);
        res.status(500).json({ message: 'Error retrieving subscriptions from KV', error: error.message });
      }
      break;

    default:
      res.setHeader('Allow', ['GET', 'POST', 'DELETE']);
      res.status(405).json({ message: `Method ${method} Not Allowed` });
  }
}
