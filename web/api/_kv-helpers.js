import { kv } from '@vercel/kv';

const RECIPIENTS_HASH_KEY = 'recipients:data';
const LEGACY_RECIPIENTS_KEY = 'recipients';

const PRODUCTS_HASH_KEY = 'products:data';
const LEGACY_PRODUCTS_KEY = 'products';

const SUBSCRIPTIONS_HASH_KEY = 'subscriptions:data';
const LEGACY_SUBSCRIPTIONS_KEY = 'subscriptions';

const STOCK_COUNTERS_HASH_KEY = 'stock_counters:data';
const LEGACY_STOCK_COUNTERS_KEY = 'stock_counters';

function parseJSON(value, fallback = {}) {
  if (value == null) return { ...fallback };
  if (typeof value === 'object') return { ...fallback, ...value };
  try {
    const parsed = JSON.parse(value);
    if (parsed && typeof parsed === 'object') {
      return { ...fallback, ...parsed };
    }
  } catch (_) {
    // Swallow JSON parse errors and fall back to default
  }
  return { ...fallback };
}

function buildRecipientRecord(id, raw) {
  const data = parseJSON(raw, {});
  return {
    id,
    email: data.email || '',
    pincode: data.pincode || '201305'
  };
}

function buildProductRecord(id, raw) {
  const data = parseJSON(raw, {});
  return {
    id,
    url: data.url || '',
    name: data.name || ''
  };
}

function buildSubscriptionRecord(id, raw) {
  const data = parseJSON(raw, {});
  return {
    id,
    recipient_id: data.recipient_id,
    product_id: data.product_id,
    start_time: data.start_time || '00:00',
    end_time: data.end_time || '23:59',
    paused: !!data.paused
  };
}

function serialiseRecipient({ email, pincode }) {
  return JSON.stringify({ email, pincode: pincode || '201305' });
}

function serialiseProduct({ url, name }) {
  return JSON.stringify({ url, name });
}

function serialiseSubscription({ recipient_id, product_id, start_time, end_time, paused }) {
  return JSON.stringify({ recipient_id, product_id, start_time, end_time, paused: !!paused });
}

function serialiseCounters(counters) {
  const payload = {};
  for (const [key, value] of Object.entries(counters)) {
    payload[key] = JSON.stringify(value);
  }
  return payload;
}

function parseCounters(hash) {
  const counters = {};
  if (!hash) return counters;
  for (const [key, value] of Object.entries(hash)) {
    if (typeof value === 'number') {
      counters[key] = value;
      continue;
    }
    try {
      counters[key] = JSON.parse(value);
    } catch (_) {
      counters[key] = value;
    }
  }
  return counters;
}

async function migrateArrayToHash(kvClient, legacyKey, hashKey, serialiser) {
  if (typeof kvClient.hset !== 'function') return;
  try {
    const legacyData = await kvClient.get(legacyKey);
    if (Array.isArray(legacyData) && legacyData.length > 0) {
      const entries = Object.fromEntries(
        legacyData
          .filter(item => item && item.id)
          .map(item => [item.id, serialiser(item)])
      );
      if (Object.keys(entries).length > 0) {
        await kvClient.hset(hashKey, entries);
        if (typeof kvClient.del === 'function') {
          await kvClient.del(legacyKey);
        }
      }
    }
  } catch (error) {
    console.error(`Error migrating ${legacyKey} to hash storage:`, error);
  }
}

export async function listRecipients(kvClient = kv) {
  if (typeof kvClient.hgetall === 'function') {
    try {
      const data = await kvClient.hgetall(RECIPIENTS_HASH_KEY);
      if (data && Object.keys(data).length > 0) {
        return Object.entries(data)
          .map(([id, raw]) => buildRecipientRecord(id, raw))
          .sort((a, b) => a.email.localeCompare(b.email));
      }
    } catch (error) {
      console.error('Error fetching recipients hash from KV:', error);
    }
  }
  await migrateArrayToHash(kvClient, LEGACY_RECIPIENTS_KEY, RECIPIENTS_HASH_KEY, serialiseRecipient);
  if (typeof kvClient.hgetall === 'function') {
    const data = await kvClient.hgetall(RECIPIENTS_HASH_KEY);
    if (data && Object.keys(data).length > 0) {
      return Object.entries(data)
        .map(([id, raw]) => buildRecipientRecord(id, raw))
        .sort((a, b) => a.email.localeCompare(b.email));
    }
  }
  try {
    const legacy = await kvClient.get(LEGACY_RECIPIENTS_KEY);
    return Array.isArray(legacy) ? legacy : [];
  } catch (error) {
    console.error('Error fetching legacy recipients from KV:', error);
    return [];
  }
}

export async function getRecipient(kvClient = kv, id) {
  if (!id) return null;
  if (typeof kvClient.hget === 'function') {
    try {
      const raw = await kvClient.hget(RECIPIENTS_HASH_KEY, id);
      if (raw) return buildRecipientRecord(id, raw);
    } catch (error) {
      console.error('Error fetching recipient from hash KV:', error);
    }
  }
  const list = await listRecipients(kvClient);
  return list.find(item => item.id === id) || null;
}

export async function saveRecipient(kvClient = kv, recipient) {
  if (!recipient || !recipient.id) throw new Error('Recipient with id is required');
  const payload = serialiseRecipient(recipient);
  if (typeof kvClient.hset === 'function') {
    await kvClient.hset(RECIPIENTS_HASH_KEY, { [recipient.id]: payload });
    return;
  }
  const existing = await listRecipients(kvClient);
  const updated = existing.filter(item => item.id !== recipient.id);
  updated.push(recipient);
  await kvClient.set(LEGACY_RECIPIENTS_KEY, updated);
}

export async function deleteRecipient(kvClient = kv, id) {
  if (!id) return;
  if (typeof kvClient.hdel === 'function') {
    await kvClient.hdel(RECIPIENTS_HASH_KEY, id);
    return;
  }
  const existing = await listRecipients(kvClient);
  const filtered = existing.filter(item => item.id !== id);
  await kvClient.set(LEGACY_RECIPIENTS_KEY, filtered);
}

export async function listProducts(kvClient = kv) {
  if (typeof kvClient.hgetall === 'function') {
    try {
      const data = await kvClient.hgetall(PRODUCTS_HASH_KEY);
      if (data && Object.keys(data).length > 0) {
        return Object.entries(data)
          .map(([id, raw]) => buildProductRecord(id, raw))
          .sort((a, b) => a.name.localeCompare(b.name));
      }
    } catch (error) {
      console.error('Error fetching products hash from KV:', error);
    }
  }
  await migrateArrayToHash(kvClient, LEGACY_PRODUCTS_KEY, PRODUCTS_HASH_KEY, serialiseProduct);
  if (typeof kvClient.hgetall === 'function') {
    const data = await kvClient.hgetall(PRODUCTS_HASH_KEY);
    if (data && Object.keys(data).length > 0) {
      return Object.entries(data)
        .map(([id, raw]) => buildProductRecord(id, raw))
        .sort((a, b) => a.name.localeCompare(b.name));
    }
  }
  try {
    const legacy = await kvClient.get(LEGACY_PRODUCTS_KEY);
    return Array.isArray(legacy) ? legacy : [];
  } catch (error) {
    console.error('Error fetching legacy products from KV:', error);
    return [];
  }
}

export async function getProduct(kvClient = kv, id) {
  if (!id) return null;
  if (typeof kvClient.hget === 'function') {
    try {
      const raw = await kvClient.hget(PRODUCTS_HASH_KEY, id);
      if (raw) return buildProductRecord(id, raw);
    } catch (error) {
      console.error('Error fetching product from hash KV:', error);
    }
  }
  const list = await listProducts(kvClient);
  return list.find(item => item.id === id) || null;
}

export async function saveProduct(kvClient = kv, product) {
  if (!product || !product.id) throw new Error('Product with id is required');
  const payload = serialiseProduct(product);
  if (typeof kvClient.hset === 'function') {
    await kvClient.hset(PRODUCTS_HASH_KEY, { [product.id]: payload });
    return;
  }
  const existing = await listProducts(kvClient);
  const updated = existing.filter(item => item.id !== product.id);
  updated.push(product);
  await kvClient.set(LEGACY_PRODUCTS_KEY, updated);
}

export async function deleteProduct(kvClient = kv, id) {
  if (!id) return;
  if (typeof kvClient.hdel === 'function') {
    await kvClient.hdel(PRODUCTS_HASH_KEY, id);
    return;
  }
  const existing = await listProducts(kvClient);
  const filtered = existing.filter(item => item.id !== id);
  await kvClient.set(LEGACY_PRODUCTS_KEY, filtered);
}

export async function listSubscriptions(kvClient = kv) {
  if (typeof kvClient.hgetall === 'function') {
    try {
      const data = await kvClient.hgetall(SUBSCRIPTIONS_HASH_KEY);
      if (data && Object.keys(data).length > 0) {
        return Object.entries(data).map(([id, raw]) => buildSubscriptionRecord(id, raw));
      }
    } catch (error) {
      console.error('Error fetching subscriptions hash from KV:', error);
    }
  }
  await migrateArrayToHash(kvClient, LEGACY_SUBSCRIPTIONS_KEY, SUBSCRIPTIONS_HASH_KEY, serialiseSubscription);
  if (typeof kvClient.hgetall === 'function') {
    const data = await kvClient.hgetall(SUBSCRIPTIONS_HASH_KEY);
    if (data && Object.keys(data).length > 0) {
      return Object.entries(data).map(([id, raw]) => buildSubscriptionRecord(id, raw));
    }
  }
  try {
    const legacy = await kvClient.get(LEGACY_SUBSCRIPTIONS_KEY);
    return Array.isArray(legacy) ? legacy : [];
  } catch (error) {
    console.error('Error fetching legacy subscriptions from KV:', error);
    return [];
  }
}

export async function getSubscription(kvClient = kv, id) {
  if (!id) return null;
  if (typeof kvClient.hget === 'function') {
    try {
      const raw = await kvClient.hget(SUBSCRIPTIONS_HASH_KEY, id);
      if (raw) return buildSubscriptionRecord(id, raw);
    } catch (error) {
      console.error('Error fetching subscription from hash KV:', error);
    }
  }
  const list = await listSubscriptions(kvClient);
  return list.find(item => item.id === id) || null;
}

export async function saveSubscription(kvClient = kv, subscription) {
  if (!subscription || !subscription.id) throw new Error('Subscription with id is required');
  const payload = serialiseSubscription(subscription);
  if (typeof kvClient.hset === 'function') {
    await kvClient.hset(SUBSCRIPTIONS_HASH_KEY, { [subscription.id]: payload });
    return;
  }
  const existing = await listSubscriptions(kvClient);
  const updated = existing.filter(item => item.id !== subscription.id);
  updated.push(subscription);
  await kvClient.set(LEGACY_SUBSCRIPTIONS_KEY, updated);
}

export async function deleteSubscription(kvClient = kv, id) {
  if (!id) return;
  if (typeof kvClient.hdel === 'function') {
    await kvClient.hdel(SUBSCRIPTIONS_HASH_KEY, id);
    return;
  }
  const existing = await listSubscriptions(kvClient);
  const filtered = existing.filter(item => item.id !== id);
  await kvClient.set(LEGACY_SUBSCRIPTIONS_KEY, filtered);
}

export async function deleteSubscriptionsByIds(kvClient = kv, ids = []) {
  if (!ids || ids.length === 0) return;
  if (typeof kvClient.hdel === 'function') {
    await kvClient.hdel(SUBSCRIPTIONS_HASH_KEY, ...ids);
    return;
  }
  const existing = await listSubscriptions(kvClient);
  const idSet = new Set(ids);
  const filtered = existing.filter(item => !idSet.has(item.id));
  await kvClient.set(LEGACY_SUBSCRIPTIONS_KEY, filtered);
}

export async function getStockCounters(kvClient = kv) {
  if (typeof kvClient.hgetall === 'function') {
    try {
      const data = await kvClient.hgetall(STOCK_COUNTERS_HASH_KEY);
      if (data && Object.keys(data).length > 0) {
        return parseCounters(data);
      }
    } catch (error) {
      console.error('Error fetching stock counters hash from KV:', error);
    }
  }
  try {
    const legacy = await kvClient.get(LEGACY_STOCK_COUNTERS_KEY);
    if (legacy && typeof legacy === 'object') {
      if (typeof kvClient.hset === 'function') {
        await kvClient.hset(STOCK_COUNTERS_HASH_KEY, serialiseCounters(legacy));
        if (typeof kvClient.del === 'function') {
          await kvClient.del(LEGACY_STOCK_COUNTERS_KEY);
        }
      }
      return { ...legacy };
    }
  } catch (error) {
    console.error('Error fetching legacy stock counters from KV:', error);
  }
  return {};
}

export async function saveStockCounters(kvClient = kv, counters) {
  if (!counters || typeof counters !== 'object') {
    throw new Error('Counters object is required');
  }
  if (typeof kvClient.hset === 'function') {
    const existing = await kvClient.hgetall?.(STOCK_COUNTERS_HASH_KEY);
    if (existing && typeof kvClient.hdel === 'function') {
      const toRemove = Object.keys(existing).filter(key => !(key in counters));
      if (toRemove.length > 0) {
        await kvClient.hdel(STOCK_COUNTERS_HASH_KEY, ...toRemove);
      }
    }
    await kvClient.hset(STOCK_COUNTERS_HASH_KEY, serialiseCounters(counters));
    return;
  }
  await kvClient.set(LEGACY_STOCK_COUNTERS_KEY, counters);
}

export {
  RECIPIENTS_HASH_KEY,
  PRODUCTS_HASH_KEY,
  SUBSCRIPTIONS_HASH_KEY,
  STOCK_COUNTERS_HASH_KEY
};
