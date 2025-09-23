import {
  listRecipients,
  listProducts,
  listSubscriptions,
  listStockCounters,
} from './data-store.js';

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', ['GET']);
    res.status(405).json({ message: `Method ${req.method} Not Allowed` });
    return;
  }

  try {
    const [recipients, products, subscriptions, counters] = await Promise.all([
      listRecipients(),
      listProducts(),
      listSubscriptions(),
      listStockCounters(),
    ]);

    res.status(200).json({
      recipients,
      products,
      subscriptions,
      stock_counters: counters,
    });
  } catch (error) {
    console.error('Error loading bulk configuration:', error);
    res.status(500).json({ message: 'Failed to load configuration' });
  }
}

