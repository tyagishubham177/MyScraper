import { kv } from '@vercel/kv';
import { requireAdmin } from '../utils/auth.js';

// KV Helper functions for Recipients
async function getRecipientsFromKV() {
  try {
    const recipientsData = await kv.get('recipients');
    return recipientsData ? recipientsData : []; // KV returns the object directly if stored as such
  } catch (error) {
    console.error('Error fetching recipients from KV:', error);
    // Fallback to empty array or throw, depending on desired error handling
    // For this API, returning empty array and letting handler decide on 500 is fine
    return [];
  }
}

async function saveRecipientsToKV(recipientsArray) {
  try {
    await kv.set('recipients', recipientsArray);
  } catch (error) {
    console.error('Error saving recipients to KV:', error);
    throw new Error('Could not save recipients to KV.');
  }
}

// KV Helper functions for Subscriptions (needed for cascading delete)
async function getSubscriptionsFromKV() {
  try {
    const subscriptionsData = await kv.get('subscriptions');
    return subscriptionsData ? subscriptionsData : [];
  } catch (error) {
    console.error('Error fetching subscriptions from KV:', error);
    return [];
  }
}

async function saveSubscriptionsToKV(subscriptionsArray) {
  try {
    await kv.set('subscriptions', subscriptionsArray);
  } catch (error) {
    console.error('Error saving subscriptions to KV:', error);
    throw new Error('Could not save subscriptions to KV.');
  }
}

// Main request handler
export default async function handler(req, res) {
  const { method } = req;

  switch (method) {
    case 'GET':
      try {
        const recipients = await getRecipientsFromKV();
        res.status(200).json(recipients);
      } catch (error) {
        console.error("Error in GET /api/recipients:", error);
        res.status(500).json({ message: 'Error retrieving recipients from KV', error: error.message });
      }
      break;

    case 'POST':
      if (!requireAdmin(req, res)) return;
      try {
        const { email, pincode } = req.body || {};

        if (!email || !/\S+@\S+\.\S+/.test(email)) {
          return res.status(400).json({ message: 'Invalid email address' });
        }

        const currentRecipients = await getRecipientsFromKV();
        if (currentRecipients.find(r => r.email === email)) {
          return res.status(409).json({ message: 'Email already exists' });
        }

        const newRecipient = {
          id: String(Date.now()), // Simple ID generation
          email,
          pincode: typeof pincode === 'string' && pincode.trim() ? pincode.trim() : '201305'
        };

        currentRecipients.push(newRecipient);
        await saveRecipientsToKV(currentRecipients);
        res.status(201).json(newRecipient);
      } catch (error) {
        console.error("Error in POST /api/recipients:", error);
        res.status(500).json({ message: 'Error saving recipient to KV', error: error.message });
      }
      break;

    case 'PUT':
      if (!requireAdmin(req, res)) return;
      try {
        const { id } = req.query;
        const { pincode } = req.body || {};
        if (!id) {
          return res.status(400).json({ message: 'Recipient ID is required' });
        }
        if (!pincode || typeof pincode !== 'string') {
          return res.status(400).json({ message: 'Invalid pincode' });
        }
        const recips = await getRecipientsFromKV();
        const idx = recips.findIndex(r => r.id === id);
        if (idx === -1) {
          return res.status(404).json({ message: 'Recipient not found' });
        }
        recips[idx] = { ...recips[idx], pincode: pincode.trim() };
        await saveRecipientsToKV(recips);
        res.status(200).json(recips[idx]);
      } catch (error) {
        console.error('Error in PUT /api/recipients:', error);
        res.status(500).json({ message: 'Error updating recipient in KV', error: error.message });
      }
      break;

    case 'DELETE':
      if (!requireAdmin(req, res)) return;
      try {
        const { id: recipientIdToDelete } = req.query;

        if (!recipientIdToDelete) {
          return res.status(400).json({ message: 'Recipient ID is required' });
        }

        let currentRecipients = await getRecipientsFromKV();
        const recipientIndex = currentRecipients.findIndex(r => r.id === recipientIdToDelete);

        if (recipientIndex === -1) {
          return res.status(404).json({ message: 'Recipient not found' });
        }

        // Filter out the recipient
        const updatedRecipients = currentRecipients.filter(r => r.id !== recipientIdToDelete);
        await saveRecipientsToKV(updatedRecipients);

        // Remove associated subscriptions
        let currentSubscriptions = await getSubscriptionsFromKV();
        const updatedSubscriptions = currentSubscriptions.filter(s => s.recipient_id !== recipientIdToDelete);

        // Save subscriptions only if they changed
        if (updatedSubscriptions.length < currentSubscriptions.length) {
            await saveSubscriptionsToKV(updatedSubscriptions);
        }

        res.status(200).json({ message: 'Recipient and associated subscriptions deleted successfully' });
      } catch (error) {
        console.error("Error in DELETE /api/recipients:", error);
        res.status(500).json({ message: 'Error deleting recipient from KV', error: error.message });
      }
      break;

    default:
      res.setHeader('Allow', ['GET', 'POST', 'PUT', 'DELETE']);
      res.status(405).json({ message: `Method ${method} Not Allowed` });
  }
}
