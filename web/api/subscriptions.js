import { kv } from '@vercel/kv';

// Default values for new granular frequency and delay settings
const DEFAULT_FREQUENCY_DAYS = 1;
const DEFAULT_FREQUENCY_HOURS = 0;
const DEFAULT_FREQUENCY_MINUTES = 0;
const DEFAULT_DELAY_DAYS = 1;
const DEFAULT_DELAY_HOURS = 0;
const DEFAULT_DELAY_MINUTES = 0;

// KV Helper functions
async function getFromKV(key) {
  try {
    const data = await kv.get(key);
    if (!data) return [];

    if (Array.isArray(data)) {
      let migrated = false;
      for (const sub of data) {
        if (sub.recipientId && !sub.recipient_id) {
          sub.recipient_id = sub.recipientId;
          delete sub.recipientId;
          migrated = true;
        }
        if (sub.productId && !sub.product_id) {
          sub.product_id = sub.productId;
          delete sub.productId;
          migrated = true;
        }
      }
      if (migrated) {
        try {
          await kv.set(key, data);
        } catch (e) {
          console.error(`Error persisting migrated ${key} to KV:`, e);
        }
      }
    }

    return data;
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
          s =>
            (s.recipient_id === recipient_id || s.recipientId === recipient_id) &&
            (s.product_id === product_id || s.productId === product_id)
        );

        if (existingSubscription) {
          // Update existing subscription
          let updated = false;

          // Normalize any legacy field names
          if (existingSubscription.recipientId && !existingSubscription.recipient_id) {
            existingSubscription.recipient_id = existingSubscription.recipientId;
            delete existingSubscription.recipientId;
            updated = true;
          }
          if (existingSubscription.productId && !existingSubscription.product_id) {
            existingSubscription.product_id = existingSubscription.productId;
            delete existingSubscription.productId;
            updated = true;
          }
          // Update new granular fields if provided
          if (req.body.frequency_days !== undefined) {
            existingSubscription.frequency_days = parseInt(req.body.frequency_days, 10);
            updated = true;
          }
          if (req.body.frequency_hours !== undefined) {
            existingSubscription.frequency_hours = parseInt(req.body.frequency_hours, 10);
            updated = true;
          }
          if (req.body.frequency_minutes !== undefined) {
            // TODO: Add validation for 5-minute steps if strictly needed, for now, accept value
            existingSubscription.frequency_minutes = parseInt(req.body.frequency_minutes, 10);
            updated = true;
          }
          if (req.body.delay_days !== undefined) {
            existingSubscription.delay_days = parseInt(req.body.delay_days, 10);
            updated = true;
          }
          if (req.body.delay_hours !== undefined) {
            existingSubscription.delay_hours = parseInt(req.body.delay_hours, 10);
            updated = true;
          }
          if (req.body.delay_minutes !== undefined) {
            // TODO: Add validation for 5-minute steps
            existingSubscription.delay_minutes = parseInt(req.body.delay_minutes, 10);
            updated = true;
          }

          // Update other existing fields
          if (req.body.delay_on_stock !== undefined) {
            existingSubscription.delay_on_stock = req.body.delay_on_stock;
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
          if (req.body.last_checked_at !== undefined) { // New field for frequency logic
            existingSubscription.last_checked_at = req.body.last_checked_at;
            updated = true;
          }

          if (updated) {
            // If any of the new granular fields were part of the update,
            // delete the old frequency/delay_duration fields to clean up data model
            if (req.body.frequency_days !== undefined || req.body.frequency_hours !== undefined || req.body.frequency_minutes !== undefined) {
              delete existingSubscription.frequency;
            }
            if (req.body.delay_days !== undefined || req.body.delay_hours !== undefined || req.body.delay_minutes !== undefined) {
              delete existingSubscription.delay_duration;
            }
            await saveToKV('subscriptions', currentSubscriptions);
            return res.status(200).json(existingSubscription);
          } else {
            // No fields relevant to this API were updated, but subscription exists.
            // We might still want to return the transformed version if only GET does transformation.
            // However, current logic is fine: if no *updateable* fields are sent, this path is taken.
            // For consistency, if GET transforms, this could too, but problem asks for update logic.
            return res.status(200).json({ message: 'Subscription exists, no recognized update fields provided.', subscription: existingSubscription });
          }
        } else {
          // Create new subscription
          const newSubscription = {
            id: String(Date.now()),
            recipient_id: recipient_id,
            product_id: product_id,
            frequency_days: req.body.frequency_days ?? DEFAULT_FREQUENCY_DAYS,
            frequency_hours: req.body.frequency_hours ?? DEFAULT_FREQUENCY_HOURS,
            frequency_minutes: req.body.frequency_minutes ?? DEFAULT_FREQUENCY_MINUTES, // TODO: Validate step
            delay_on_stock: req.body.delay_on_stock !== undefined ? req.body.delay_on_stock : false,
            delay_days: req.body.delay_days ?? DEFAULT_DELAY_DAYS,
            delay_hours: req.body.delay_hours ?? DEFAULT_DELAY_HOURS,
            delay_minutes: req.body.delay_minutes ?? DEFAULT_DELAY_MINUTES, // TODO: Validate step
            last_in_stock_at: null,
            delayed_until: null,
            last_checked_at: null, // New field for frequency logic
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
          s => !(
            (s.recipient_id === recipient_id || s.recipientId === recipient_id) &&
            (s.product_id === product_id || s.productId === product_id)
          )
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

        // Helper to add default fields and perform on-the-fly migration for GET requests
        const addDefaultSubscriptionFields = (subscription) => {
          let newSub = { ...subscription }; // Create a mutable copy

          // Migrate legacy field names if present
          if (newSub.recipientId && !newSub.recipient_id) {
            newSub.recipient_id = newSub.recipientId;
            delete newSub.recipientId;
          }
          if (newSub.productId && !newSub.product_id) {
            newSub.product_id = newSub.productId;
            delete newSub.productId;
          }

          // Migration for frequency
          if (newSub.frequency) {
            const oldFreq = newSub.frequency.toLowerCase();
            if (oldFreq === "hourly") {
              newSub.frequency_days = 0;
              newSub.frequency_hours = 1;
              newSub.frequency_minutes = 0;
            } else if (oldFreq === "every_2_hours") {
              newSub.frequency_days = 0;
              newSub.frequency_hours = 2;
              newSub.frequency_minutes = 0;
            } else if (oldFreq === "daily") {
              newSub.frequency_days = 1;
              newSub.frequency_hours = 0;
              newSub.frequency_minutes = 0;
            } else if (oldFreq === "weekly") {
              newSub.frequency_days = 7;
              newSub.frequency_hours = 0;
              newSub.frequency_minutes = 0;
            }
            delete newSub.frequency; // Remove old field from the object being returned
          }

          // Migration for delay_duration
          if (newSub.delay_duration) {
            const parts = newSub.delay_duration.toLowerCase().split('_');
            if (parts.length === 2) {
              try {
                const value = parseInt(parts[0], 10);
                const unit = parts[1];
                if (unit === "day" || unit === "days") {
                  newSub.delay_days = value;
                  newSub.delay_hours = 0;
                  newSub.delay_minutes = 0;
                } else if (unit === "hour" || unit === "hours") {
                  newSub.delay_days = 0;
                  newSub.delay_hours = value;
                  newSub.delay_minutes = 0;
                }
              } catch (e) {
                // Parsing failed, old field might remain if not deleted, defaults will apply below
              }
            }
            delete newSub.delay_duration; // Remove old field
          }

          // Apply defaults for new granular fields if not set (either directly or via migration)
          newSub.frequency_days = newSub.frequency_days ?? DEFAULT_FREQUENCY_DAYS;
          newSub.frequency_hours = newSub.frequency_hours ?? DEFAULT_FREQUENCY_HOURS;
          newSub.frequency_minutes = newSub.frequency_minutes ?? DEFAULT_FREQUENCY_MINUTES;

          newSub.delay_days = newSub.delay_days ?? DEFAULT_DELAY_DAYS;
          newSub.delay_hours = newSub.delay_hours ?? DEFAULT_DELAY_HOURS;
          newSub.delay_minutes = newSub.delay_minutes ?? DEFAULT_DELAY_MINUTES;

          // Ensure other fields are correctly defaulted
          newSub.delay_on_stock = newSub.delay_on_stock ?? false;
          newSub.last_in_stock_at = newSub.last_in_stock_at || null;
          newSub.delayed_until = newSub.delayed_until || null;
          newSub.last_checked_at = newSub.last_checked_at || null; // New field for frequency logic

          return newSub;
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
