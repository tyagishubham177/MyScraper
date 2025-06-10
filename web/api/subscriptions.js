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
          // Update existing subscription
          let updated = false;
          if (req.body.frequency !== undefined) {
            existingSubscription.frequency = req.body.frequency;
            updated = true;
          }
          if (req.body.delay_on_stock !== undefined) {
            existingSubscription.delay_on_stock = req.body.delay_on_stock;
            updated = true;
          }
          if (req.body.delay_duration !== undefined) {
            existingSubscription.delay_duration = req.body.delay_duration;
            updated = true;
          }
          if (req.body.last_in_stock_at !== undefined) {
            existingSubscription.last_in_stock_at = req.body.last_in_stock_at;
            updated = true;
          }
          if (req.body.delayed_until !== undefined) {
            existingSubscription.delayed_until = req.body.delayed_until;
            updated = true;
          }

          // Ensure other fields like id, recipient_id, product_id are not accidentally overwritten
          // by ensuring they are not part of the update logic from req.body unless specifically intended
          // (which they are not for this particular update feature)

          if (updated) {
            await saveToKV('subscriptions', currentSubscriptions); // currentSubscriptions contains the modified existingSubscription
            return res.status(200).json(existingSubscription);
          } else {
            // No fields were updated, but subscription exists
            return res.status(200).json({ message: 'Subscription exists, no update fields provided.', subscription: existingSubscription });
          }
        } else {
          // Create new subscription
          const newSubscription = {
            id: String(Date.now()), // Simple ID generation
            recipient_id: recipient_id,
            product_id: product_id,
            frequency: req.body.frequency || "daily",
            delay_on_stock: req.body.delay_on_stock !== undefined ? req.body.delay_on_stock : false,
            delay_duration: req.body.delay_duration || "1_day",
            last_in_stock_at: null,
            delayed_until: null,
          };

          currentSubscriptions.push(newSubscription);
          await saveToKV('subscriptions', currentSubscriptions);
          res.status(201).json(newSubscription);
        }
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
        let subscriptions = await getFromKV('subscriptions');

        // Helper to add default fields to subscriptions if they are missing
        const addDefaultSubscriptionFields = (subscription) => {
          return {
            ...subscription,
            frequency: subscription.frequency || "daily",
            delay_on_stock: subscription.delay_on_stock !== undefined ? subscription.delay_on_stock : false,
            delay_duration: subscription.delay_duration || "1_day",
            last_in_stock_at: subscription.last_in_stock_at || null,
            delayed_until: subscription.delayed_until || null,
          };
        };

        if (recipient_id && product_id) {
          return res.status(400).json({ message: 'Provide either recipient_id OR product_id, not both.' });
        }

        if (recipient_id) {
          const recipientSubscriptions = subscriptions
            .filter(s => s.recipient_id === recipient_id)
            .map(addDefaultSubscriptionFields);
          res.status(200).json(recipientSubscriptions);
        } else if (product_id) {
          const productSubscriptions = subscriptions
            .filter(s => s.product_id === product_id)
            .map(addDefaultSubscriptionFields);
          res.status(200).json(productSubscriptions);
        } else {
          // Return all subscriptions with default fields applied
          const allSubscriptionsWithDefaults = subscriptions.map(addDefaultSubscriptionFields);
          res.status(200).json(allSubscriptionsWithDefaults);
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
