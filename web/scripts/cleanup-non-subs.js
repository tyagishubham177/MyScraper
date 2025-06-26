import { kv } from '@vercel/kv';

async function cleanupNonSubscribers() {
  try {
    const recipients = (await kv.get('recipients')) || [];
    const subscriptions = (await kv.get('subscriptions')) || [];

    const subscribed = new Set(subscriptions.map(s => s.recipient_id));
    const keepRecipients = recipients.filter(r => subscribed.has(r.id));
    const removedCount = recipients.length - keepRecipients.length;

    if (removedCount === 0) {
      console.log('No non-subscriber recipients to remove.');
      return;
    }

    await kv.set('recipients', keepRecipients);
    console.log(`Removed ${removedCount} recipient(s) with no subscriptions.`);
  } catch (error) {
    console.error('Error during cleanup:', error);
    process.exitCode = 1;
  }
}

cleanupNonSubscribers();
