import { kv } from '@vercel/kv';
import {
  listRecipients,
  listProducts,
  listSubscriptions,
  getStockCounters
} from './_kv-helpers.js';

let kvClient = kv;

export function __setKv(mock) {
  kvClient = mock;
}

export function __resetKv() {
  kvClient = kv;
}

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', ['GET']);
    res.status(405).json({ message: `Method ${req.method} Not Allowed` });
    return;
  }

  try {
    const [recipients, products, subscriptions, counters] = await Promise.all([
      listRecipients(kvClient),
      listProducts(kvClient),
      listSubscriptions(kvClient),
      getStockCounters(kvClient)
    ]);

    res.status(200).json({
      recipients,
      products,
      subscriptions,
      stock_counters: counters || {}
    });
  } catch (error) {
    console.error('Error building configuration payload:', error);
    res.status(500).json({ message: 'Error loading configuration', error: error.message });
  }
}
