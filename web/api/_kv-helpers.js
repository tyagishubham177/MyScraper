import { kv } from '@vercel/kv';

const RECIPIENTS_HASH_KEY = 'recipients:data';
const LEGACY_RECIPIENTS_KEY = 'recipients';

const PRODUCTS_HASH_KEY = 'products:data';
const LEGACY_PRODUCTS_KEY = 'products';

const SUBSCRIPTIONS_HASH_KEY = 'subscriptions:data';
const LEGACY_SUBSCRIPTIONS_KEY = 'subscriptions';

const STOCK_COUNTERS_HASH_KEY = 'stock_counters:data';
const LEGACY_STOCK_COUNTERS_KEY = 'stock_counters';

function normalizeEmail(email) {
  if (typeof email !== 'string') return '';
  return email.trim().toLowerCase();
}

function isKvClientUsable(kvClient = kv, methods = []) {
  if (!kvClient) return false;
  if (kvClient === kv && !(process.env.KV_REST_API_URL && process.env.KV_REST_API_TOKEN)) {
    return false;
  }
  return methods.every(method => typeof kvClient[method] === 'function');
}

function parseEmailList(rawValue) {
  if (typeof rawValue !== 'string' || !rawValue.trim()) return [];
  return rawValue
    .split(',')
    .map(value => value.trim())
    .filter(value => /\S+@\S+\.\S+/.test(value));
}

function getFallbackRecipients() {
  const fallbackPincode = process.env.PINCODE || '201305';
  const byEmail = new Map();
  const fallbackSources = [
    process.env.EMAIL_RECIPIENTS,
    process.env.ADMIN_EMAIL,
    process.env.ADMIN_MAIL,
    process.env.EMAIL_SENDER,
    process.env.EMAIL_HOST_USER
  ];

  for (const source of fallbackSources) {
    for (const email of parseEmailList(source)) {
      const normalized = normalizeEmail(email);
      if (!normalized || byEmail.has(normalized)) continue;
      byEmail.set(normalized, {
        id: `env:${normalized}`,
        email: normalized,
        pincode: fallbackPincode
      });
    }
  }

  return Array.from(byEmail.values());
}

function mergeRecipientsWithFallback(recipients = []) {
  const merged = new Map();

  for (const recipient of recipients) {
    const normalized = normalizeEmail(recipient?.email);
    if (!normalized || merged.has(normalized)) continue;
    merged.set(normalized, {
      id: recipient.id || `env:${normalized}`,
      email: typeof recipient.email === 'string' ? recipient.email.trim() : normalized,
      pincode: recipient.pincode || '201305'
    });
  }

  for (const recipient of getFallbackRecipients()) {
    const normalized = normalizeEmail(recipient.email);
    if (!normalized || merged.has(normalized)) continue;
    merged.set(normalized, recipient);
  }

  return Array.from(merged.values()).sort((a, b) => a.email.localeCompare(b.email));
}

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
  if (!isKvClientUsable(kvClient, ['get', 'hset'])) return;
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
    throw error;
  }
}

export async function listRecipients(kvClient = kv) {
  if (isKvClientUsable(kvClient, ['hgetall'])) {
    try {
      const data = await kvClient.hgetall(RECIPIENTS_HASH_KEY);
      if (data && Object.keys(data).length > 0) {
        return mergeRecipientsWithFallback(Object.entries(data)
          .map(([id, raw]) => buildRecipientRecord(id, raw))
        );
      }
    } catch (error) {
      console.error('Error fetching recipients hash from KV:', error);
      throw error;
    }
  }
  await migrateArrayToHash(kvClient, LEGACY_RECIPIENTS_KEY, RECIPIENTS_HASH_KEY, serialiseRecipient);
  if (isKvClientUsable(kvClient, ['hgetall'])) {
    const data = await kvClient.hgetall(RECIPIENTS_HASH_KEY);
    if (data && Object.keys(data).length > 0) {
      return mergeRecipientsWithFallback(Object.entries(data)
        .map(([id, raw]) => buildRecipientRecord(id, raw))
      );
    }
  }
  if (isKvClientUsable(kvClient, ['get'])) {
    try {
      const legacy = await kvClient.get(LEGACY_RECIPIENTS_KEY);
      return mergeRecipientsWithFallback(Array.isArray(legacy) ? legacy : []);
    } catch (error) {
      console.error('Error fetching legacy recipients from KV:', error);
      throw error;
    }
  }
  return mergeRecipientsWithFallback([]);
}

export async function getRecipient(kvClient = kv, id) {
  if (!id) return null;
  if (isKvClientUsable(kvClient, ['hget'])) {
    try {
      const raw = await kvClient.hget(RECIPIENTS_HASH_KEY, id);
      if (raw) return buildRecipientRecord(id, raw);
    } catch (error) {
      console.error('Error fetching recipient from hash KV:', error);
      throw error;
    }
  }
  const list = await listRecipients(kvClient);
  return list.find(item => item.id === id) || null;
}

export async function saveRecipient(kvClient = kv, recipient) {
  if (!recipient || !recipient.id) throw new Error('Recipient with id is required');
  const payload = serialiseRecipient(recipient);
  if (isKvClientUsable(kvClient, ['hset'])) {
    await kvClient.hset(RECIPIENTS_HASH_KEY, { [recipient.id]: payload });
    return;
  }
  if (!isKvClientUsable(kvClient, ['get', 'set'])) {
    throw new Error('KV storage unavailable');
  }
  const existing = await listRecipients(kvClient);
  const updated = existing.filter(item => item.id !== recipient.id);
  updated.push(recipient);
  await kvClient.set(LEGACY_RECIPIENTS_KEY, updated);
}

export async function deleteRecipient(kvClient = kv, id) {
  if (!id) return;
  if (isKvClientUsable(kvClient, ['hdel'])) {
    await kvClient.hdel(RECIPIENTS_HASH_KEY, id);
    return;
  }
  if (!isKvClientUsable(kvClient, ['get', 'set'])) {
    throw new Error('KV storage unavailable');
  }
  const existing = await listRecipients(kvClient);
  const filtered = existing.filter(item => item.id !== id);
  await kvClient.set(LEGACY_RECIPIENTS_KEY, filtered);
}

export async function listProducts(kvClient = kv) {
  if (isKvClientUsable(kvClient, ['hgetall'])) {
    try {
      const data = await kvClient.hgetall(PRODUCTS_HASH_KEY);
      if (data && Object.keys(data).length > 0) {
        return Object.entries(data)
          .map(([id, raw]) => buildProductRecord(id, raw))
          .sort((a, b) => a.name.localeCompare(b.name));
      }
    } catch (error) {
      console.error('Error fetching products hash from KV:', error);
      throw error;
    }
  }
  await migrateArrayToHash(kvClient, LEGACY_PRODUCTS_KEY, PRODUCTS_HASH_KEY, serialiseProduct);
  if (isKvClientUsable(kvClient, ['hgetall'])) {
    const data = await kvClient.hgetall(PRODUCTS_HASH_KEY);
    if (data && Object.keys(data).length > 0) {
      return Object.entries(data)
        .map(([id, raw]) => buildProductRecord(id, raw))
        .sort((a, b) => a.name.localeCompare(b.name));
    }
  }
  if (isKvClientUsable(kvClient, ['get'])) {
    try {
      const legacy = await kvClient.get(LEGACY_PRODUCTS_KEY);
      return Array.isArray(legacy) ? legacy : [];
    } catch (error) {
      console.error('Error fetching legacy products from KV:', error);
      throw error;
    }
  }
  return [];
}

export async function getProduct(kvClient = kv, id) {
  if (!id) return null;
  if (isKvClientUsable(kvClient, ['hget'])) {
    try {
      const raw = await kvClient.hget(PRODUCTS_HASH_KEY, id);
      if (raw) return buildProductRecord(id, raw);
    } catch (error) {
      console.error('Error fetching product from hash KV:', error);
      throw error;
    }
  }
  const list = await listProducts(kvClient);
  return list.find(item => item.id === id) || null;
}

export async function saveProduct(kvClient = kv, product) {
  if (!product || !product.id) throw new Error('Product with id is required');
  const payload = serialiseProduct(product);
  if (isKvClientUsable(kvClient, ['hset'])) {
    await kvClient.hset(PRODUCTS_HASH_KEY, { [product.id]: payload });
    return;
  }
  if (!isKvClientUsable(kvClient, ['get', 'set'])) {
    throw new Error('KV storage unavailable');
  }
  const existing = await listProducts(kvClient);
  const updated = existing.filter(item => item.id !== product.id);
  updated.push(product);
  await kvClient.set(LEGACY_PRODUCTS_KEY, updated);
}

export async function deleteProduct(kvClient = kv, id) {
  if (!id) return;
  if (isKvClientUsable(kvClient, ['hdel'])) {
    await kvClient.hdel(PRODUCTS_HASH_KEY, id);
    return;
  }
  if (!isKvClientUsable(kvClient, ['get', 'set'])) {
    throw new Error('KV storage unavailable');
  }
  const existing = await listProducts(kvClient);
  const filtered = existing.filter(item => item.id !== id);
  await kvClient.set(LEGACY_PRODUCTS_KEY, filtered);
}

export async function listSubscriptions(kvClient = kv) {
  if (isKvClientUsable(kvClient, ['hgetall'])) {
    try {
      const data = await kvClient.hgetall(SUBSCRIPTIONS_HASH_KEY);
      if (data && Object.keys(data).length > 0) {
        return Object.entries(data).map(([id, raw]) => buildSubscriptionRecord(id, raw));
      }
    } catch (error) {
      console.error('Error fetching subscriptions hash from KV:', error);
      throw error;
    }
  }
  await migrateArrayToHash(kvClient, LEGACY_SUBSCRIPTIONS_KEY, SUBSCRIPTIONS_HASH_KEY, serialiseSubscription);
  if (isKvClientUsable(kvClient, ['hgetall'])) {
    const data = await kvClient.hgetall(SUBSCRIPTIONS_HASH_KEY);
    if (data && Object.keys(data).length > 0) {
      return Object.entries(data).map(([id, raw]) => buildSubscriptionRecord(id, raw));
    }
  }
  if (isKvClientUsable(kvClient, ['get'])) {
    try {
      const legacy = await kvClient.get(LEGACY_SUBSCRIPTIONS_KEY);
      return Array.isArray(legacy) ? legacy : [];
    } catch (error) {
      console.error('Error fetching legacy subscriptions from KV:', error);
      throw error;
    }
  }
  return [];
}

export async function getSubscription(kvClient = kv, id) {
  if (!id) return null;
  if (isKvClientUsable(kvClient, ['hget'])) {
    try {
      const raw = await kvClient.hget(SUBSCRIPTIONS_HASH_KEY, id);
      if (raw) return buildSubscriptionRecord(id, raw);
    } catch (error) {
      console.error('Error fetching subscription from hash KV:', error);
      throw error;
    }
  }
  const list = await listSubscriptions(kvClient);
  return list.find(item => item.id === id) || null;
}

export async function saveSubscription(kvClient = kv, subscription) {
  if (!subscription || !subscription.id) throw new Error('Subscription with id is required');
  const payload = serialiseSubscription(subscription);
  if (isKvClientUsable(kvClient, ['hset'])) {
    await kvClient.hset(SUBSCRIPTIONS_HASH_KEY, { [subscription.id]: payload });
    return;
  }
  if (!isKvClientUsable(kvClient, ['get', 'set'])) {
    throw new Error('KV storage unavailable');
  }
  const existing = await listSubscriptions(kvClient);
  const updated = existing.filter(item => item.id !== subscription.id);
  updated.push(subscription);
  await kvClient.set(LEGACY_SUBSCRIPTIONS_KEY, updated);
}

export async function deleteSubscription(kvClient = kv, id) {
  if (!id) return;
  if (isKvClientUsable(kvClient, ['hdel'])) {
    await kvClient.hdel(SUBSCRIPTIONS_HASH_KEY, id);
    return;
  }
  if (!isKvClientUsable(kvClient, ['get', 'set'])) {
    throw new Error('KV storage unavailable');
  }
  const existing = await listSubscriptions(kvClient);
  const filtered = existing.filter(item => item.id !== id);
  await kvClient.set(LEGACY_SUBSCRIPTIONS_KEY, filtered);
}

export async function deleteSubscriptionsByIds(kvClient = kv, ids = []) {
  if (!ids || ids.length === 0) return;
  if (isKvClientUsable(kvClient, ['hdel'])) {
    await kvClient.hdel(SUBSCRIPTIONS_HASH_KEY, ...ids);
    return;
  }
  if (!isKvClientUsable(kvClient, ['get', 'set'])) {
    throw new Error('KV storage unavailable');
  }
  const existing = await listSubscriptions(kvClient);
  const idSet = new Set(ids);
  const filtered = existing.filter(item => !idSet.has(item.id));
  await kvClient.set(LEGACY_SUBSCRIPTIONS_KEY, filtered);
}

export async function getStockCounters(kvClient = kv) {
  if (isKvClientUsable(kvClient, ['hgetall'])) {
    try {
      const data = await kvClient.hgetall(STOCK_COUNTERS_HASH_KEY);
      if (data && Object.keys(data).length > 0) {
        return parseCounters(data);
      }
    } catch (error) {
      console.error('Error fetching stock counters hash from KV:', error);
      throw error;
    }
  }
  if (isKvClientUsable(kvClient, ['get'])) {
    try {
      const legacy = await kvClient.get(LEGACY_STOCK_COUNTERS_KEY);
      if (legacy && typeof legacy === 'object') {
        if (isKvClientUsable(kvClient, ['hset'])) {
          await kvClient.hset(STOCK_COUNTERS_HASH_KEY, serialiseCounters(legacy));
          if (isKvClientUsable(kvClient, ['del'])) {
            await kvClient.del(LEGACY_STOCK_COUNTERS_KEY);
          }
        }
        return { ...legacy };
      }
    } catch (error) {
      console.error('Error fetching legacy stock counters from KV:', error);
      throw error;
    }
  }
  return {};
}

export async function saveStockCounters(kvClient = kv, counters) {
  if (!counters || typeof counters !== 'object') {
    throw new Error('Counters object is required');
  }
  if (isKvClientUsable(kvClient, ['hset'])) {
    const existing = await kvClient.hgetall?.(STOCK_COUNTERS_HASH_KEY);
    if (existing && isKvClientUsable(kvClient, ['hdel'])) {
      const toRemove = Object.keys(existing).filter(key => !(key in counters));
      if (toRemove.length > 0) {
        await kvClient.hdel(STOCK_COUNTERS_HASH_KEY, ...toRemove);
      }
    }
    await kvClient.hset(STOCK_COUNTERS_HASH_KEY, serialiseCounters(counters));
    return;
  }
  if (!isKvClientUsable(kvClient, ['set'])) {
    throw new Error('KV storage unavailable');
  }
  await kvClient.set(LEGACY_STOCK_COUNTERS_KEY, counters);
}

export {
  RECIPIENTS_HASH_KEY,
  PRODUCTS_HASH_KEY,
  SUBSCRIPTIONS_HASH_KEY,
  STOCK_COUNTERS_HASH_KEY
};
