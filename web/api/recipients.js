import { requireAdmin } from '../utils/auth.js';
import {
  deleteRecipient as deleteRecipientRecord,
  listRecipients,
  saveRecipient as saveRecipientRecord,
  listSubscriptions,
  deleteSubscription as deleteSubscriptionRecord,
} from './data-store.js';

// Main request handler
export default async function handler(req, res) {
  const { method } = req;

  switch (method) {
    case 'GET':
      try {
        const recipients = await listRecipients();
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

        const currentRecipients = await listRecipients();
        if (currentRecipients.find(r => r.email === email)) {
          return res.status(409).json({ message: 'Email already exists' });
        }

        const newRecipient = {
          id: String(Date.now()), // Simple ID generation
          email,
          pincode: typeof pincode === 'string' && pincode.trim() ? pincode.trim() : '201305'
        };

        await saveRecipientRecord(newRecipient);
        res.status(201).json(newRecipient);
      } catch (error) {
        console.error("Error in POST /api/recipients:", error);
        res.status(500).json({ message: 'Error saving recipient to KV', error: error.message });
      }
      break;

    case 'PUT':
      try {
        const { id } = req.query;
        const { pincode } = req.body || {};
        if (!id) {
          return res.status(400).json({ message: 'Recipient ID is required' });
        }
        if (!pincode || typeof pincode !== 'string') {
          return res.status(400).json({ message: 'Invalid pincode' });
        }
        const recips = await listRecipients();
        const recipient = recips.find(r => r.id === id);
        if (!recipient) {
          return res.status(404).json({ message: 'Recipient not found' });
        }
        const updated = { ...recipient, pincode: pincode.trim() };
        await saveRecipientRecord(updated);
        res.status(200).json(updated);
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

        const recipients = await listRecipients();
        const existing = recipients.find(r => r.id === recipientIdToDelete);

        if (!existing) {
          return res.status(404).json({ message: 'Recipient not found' });
        }

        await deleteRecipientRecord(recipientIdToDelete);

        // Remove associated subscriptions
        const subs = await listSubscriptions();
        const toDelete = subs.filter(s => s.recipient_id === recipientIdToDelete);
        for (const sub of toDelete) {
          await deleteSubscriptionRecord(sub.id);
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
