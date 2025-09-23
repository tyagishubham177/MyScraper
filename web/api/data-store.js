import { randomUUID } from 'crypto';
import { kv as defaultKv } from '@vercel/kv';

let kv = defaultKv;
export function __setKv(instance) {
  kv = instance;
}
export function __resetKv() {
  kv = defaultKv;
}

const RECIPIENTS_HASH_KEY = 'recipients:v2';
const PRODUCTS_HASH_KEY = 'products:v2';
const SUBSCRIPTIONS_HASH_KEY = 'subscriptions:v2';

async function migrateLegacyArray(key, hashKey) {
  const legacy = await kv.get(key);
  if (!Array.isArray(legacy) || legacy.length === 0) {
    return [];
  }

  const entries = {};
  for (const item of legacy) {
    if (!item || typeof item !== 'object') continue;
    const id = item.id || generateId();
    entries[id] = JSON.stringify({ ...item, id });
  }
  if (Object.keys(entries).length > 0) {
    await kv.hset(hashKey, entries);
  }
  await kv.del(key);
  return legacy;
}

async function readHashCollection(hashKey, legacyKey) {
  let raw;
  try {
    raw = await kv.hgetall(hashKey);
  } catch (err) {
    if (legacyKey) {
      return migrateLegacyArray(legacyKey, hashKey);
    }
    console.error(`Error fetching hash collection for ${hashKey}:`, err);
    return [];
  }

  if (raw && Object.keys(raw).length > 0) {
    return Object.entries(raw).map(([id, value]) => {
      if (typeof value === 'string') {
        try {
          const parsed = JSON.parse(value);
          return parsed && typeof parsed === 'object' ? parsed : { id };
        } catch (err) {
          console.warn(`Failed to parse hash value for ${hashKey}:${id}`, err);
          return { id };
        }
      }
      if (value && typeof value === 'object') {
        return value;
      }
      return { id };
    });
  }

  if (legacyKey) {
    return migrateLegacyArray(legacyKey, hashKey);
  }
  return [];
}

async function writeHashItem(hashKey, item) {
  if (!item || typeof item !== 'object') {
    throw new Error(`Invalid item for ${hashKey}`);
  }
  const id = item.id || generateId();
  const record = { ...item, id };
  await kv.hset(hashKey, { [id]: JSON.stringify(record) });
  return record;
}

async function deleteHashItem(hashKey, id) {
  if (!id) return;
  await kv.hdel(hashKey, id);
}

export async function listRecipients() {
  return readHashCollection(RECIPIENTS_HASH_KEY, 'recipients');
}

export async function saveRecipient(recipient) {
  return writeHashItem(RECIPIENTS_HASH_KEY, recipient);
}

export async function deleteRecipient(id) {
  await deleteHashItem(RECIPIENTS_HASH_KEY, id);
}

export async function listProducts() {
  const products = await readHashCollection(PRODUCTS_HASH_KEY, 'products');
  products.sort((a, b) => (a.name || '').localeCompare(b.name || ''));
  return products;
}

export async function saveProduct(product) {
  return writeHashItem(PRODUCTS_HASH_KEY, product);
}

export async function deleteProduct(id) {
  await deleteHashItem(PRODUCTS_HASH_KEY, id);
}

export async function listSubscriptions() {
  const subscriptions = await readHashCollection(SUBSCRIPTIONS_HASH_KEY, 'subscriptions');
  return subscriptions.map(sub => ({
    id: sub.id || generateId(),
    recipient_id: sub.recipient_id,
    product_id: sub.product_id,
    start_time: sub.start_time || '00:00',
    end_time: sub.end_time || '23:59',
    paused: !!sub.paused,
  }));
}

export async function saveSubscription(subscription) {
  return writeHashItem(SUBSCRIPTIONS_HASH_KEY, subscription);
}

export async function deleteSubscription(id) {
  await deleteHashItem(SUBSCRIPTIONS_HASH_KEY, id);
}

export async function findSubscriptionByRecipientAndProduct(recipientId, productId) {
  if (!recipientId || !productId) return null;
  const all = await listSubscriptions();
  return all.find(sub => sub.recipient_id === recipientId && sub.product_id === productId) || null;
}

export async function listSubscriptionsByRecipient(recipientId) {
  const all = await listSubscriptions();
  return all.filter(sub => sub.recipient_id === recipientId);
}

export async function listSubscriptionsByProduct(productId) {
  const all = await listSubscriptions();
  return all.filter(sub => sub.product_id === productId);
}

export async function listStockCounters() {
  try {
    const counters = await kv.get('stock_counters');
    return counters && typeof counters === 'object' ? counters : {};
  } catch (err) {
    console.error('Error fetching stock counters from KV:', err);
    return {};
  }
}

export async function saveStockCounters(counters) {
  await kv.set('stock_counters', counters);
}

function generateId() {
  try {
    return randomUUID();
  } catch (_) {
    return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  }
}
