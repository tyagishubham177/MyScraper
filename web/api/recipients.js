import { kv } from '@vercel/kv';
import { requireAdmin as defaultRequireAdmin } from '../utils/auth.js';
import {
  listRecipients as listRecipientsFromKV,
  saveRecipient as saveRecipientToKV,
  deleteRecipient as deleteRecipientFromKV,
  listSubscriptions as listSubscriptionsFromKV,
  deleteSubscriptionsByIds
} from './_kv-helpers.js';

let kvClient = kv;
let requireAdmin = defaultRequireAdmin;

export function __setKv(mock) {
  kvClient = mock;
}

export function __resetKv() {
  kvClient = kv;
}

export function __setRequireAdmin(fn) {
  requireAdmin = fn;
}

export function __resetRequireAdmin() {
  requireAdmin = defaultRequireAdmin;
}

function normalizeEmail(email) {
  if (typeof email !== 'string') return '';
  return email.trim().toLowerCase();
}

// Main request handler
export default async function handler(req, res) {
  const { method } = req;

  switch (method) {
    case 'GET':
      try {
        const recipients = await listRecipientsFromKV(kvClient);
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
        const trimmedEmail = typeof email === 'string' ? email.trim() : '';
        const normalizedEmail = normalizeEmail(trimmedEmail);

        if (!trimmedEmail || !/\S+@\S+\.\S+/.test(trimmedEmail)) {
          return res.status(400).json({ message: 'Invalid email address' });
        }

        const currentRecipients = await listRecipientsFromKV(kvClient);
        if (currentRecipients.some(r => normalizeEmail(r.email) === normalizedEmail)) {
          return res.status(409).json({ message: 'Email already exists' });
        }

        const newRecipient = {
          id: String(Date.now()), // Simple ID generation
          email: trimmedEmail,
          pincode: typeof pincode === 'string' && pincode.trim() ? pincode.trim() : '201305'
        };

        await saveRecipientToKV(kvClient, newRecipient);
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
        const recips = await listRecipientsFromKV(kvClient);
        const idx = recips.findIndex(r => r.id === id);
        if (idx === -1) {
          return res.status(404).json({ message: 'Recipient not found' });
        }
        const updated = { ...recips[idx], pincode: pincode.trim() };
        await saveRecipientToKV(kvClient, updated);
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

        const currentRecipients = await listRecipientsFromKV(kvClient);
        const recipientIndex = currentRecipients.findIndex(r => r.id === recipientIdToDelete);

        if (recipientIndex === -1) {
          return res.status(404).json({ message: 'Recipient not found' });
        }

        // Remove the recipient record and cascade delete subscriptions
        await deleteRecipientFromKV(kvClient, recipientIdToDelete);

        const subscriptions = await listSubscriptionsFromKV(kvClient);
        const subsToDelete = subscriptions
          .filter(s => s.recipient_id === recipientIdToDelete)
          .map(s => s.id);
        if (subsToDelete.length > 0) {
          await deleteSubscriptionsByIds(kvClient, subsToDelete);
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
