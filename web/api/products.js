import { kv } from '@vercel/kv';
import { requireAdmin } from './auth.js';

// KV Helper functions for Products
async function getProductsFromKV() {
  try {
    const productsData = await kv.get('products');
    if (productsData) {
      productsData.sort((a, b) => a.name.localeCompare(b.name));
    }
    return productsData ? productsData : [];
  } catch (error) {
    console.error('Error fetching products from KV:', error);
    return [];
  }
}

async function saveProductsToKV(productsArray) {
  try {
    await kv.set('products', productsArray);
  } catch (error) {
    console.error('Error saving products to KV:', error);
    throw new Error('Could not save products to KV.');
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
async function handleGet(req, res) {
  try {
    const products = await getProductsFromKV();
    res.status(200).json(products);
  } catch (error) {
    console.error("Error in GET /api/products:", error);
    res.status(500).json({ message: 'Error retrieving products from KV', error: error.message });
  }
}

async function handlePost(req, res) {
  if (!requireAdmin(req, res)) return;
  try {
    const { url, name } = req.body;

    if (!url || typeof url !== 'string') {
      return res.status(400).json({ message: 'Invalid URL' });
    }
    try {
      const parsed = new URL(url);
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        return res.status(400).json({ message: 'URL must start with http:// or https://' });
      }
    } catch (_) {
      return res.status(400).json({ message: 'Invalid URL format' });
    }
    if (!name || typeof name !== 'string' || name.trim() === '') {
      return res.status(400).json({ message: 'Invalid product name' });
    }

    const currentProducts = await getProductsFromKV();
    if (currentProducts.find(p => p.url === url)) {
      return res.status(409).json({ message: 'Product with this URL already exists' });
    }

    const newProduct = {
      id: String(Date.now()),
      url: url,
      name: name.trim()
    };

    currentProducts.push(newProduct);
    await saveProductsToKV(currentProducts);
    res.status(201).json(newProduct);
  } catch (error) {
    console.error("Error in POST /api/products:", error);
    res.status(500).json({ message: 'Error saving product to KV', error: error.message });
  }
}

async function handlePut(req, res) {
  if (!requireAdmin(req, res)) return;
  try {
    const { id } = req.query;
    const { url, name } = req.body;

    if (!id) {
      return res.status(400).json({ message: 'Product ID is required' });
    }
    if (!url || typeof url !== 'string') {
      return res.status(400).json({ message: 'Invalid URL' });
    }
    try {
      const parsed = new URL(url);
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        return res.status(400).json({ message: 'URL must start with http:// or https://' });
      }
    } catch (_) {
      return res.status(400).json({ message: 'Invalid URL format' });
    }
    if (!name || typeof name !== 'string' || name.trim() === '') {
      return res.status(400).json({ message: 'Invalid product name' });
    }

    let currentProducts = await getProductsFromKV();
    const productIndex = currentProducts.findIndex(p => p.id === id);
    if (productIndex === -1) {
      return res.status(404).json({ message: 'Product not found' });
    }
    currentProducts[productIndex] = {
      ...currentProducts[productIndex],
      url,
      name: name.trim()
    };
    await saveProductsToKV(currentProducts);
    res.status(200).json(currentProducts[productIndex]);
  } catch (error) {
    console.error('Error in PUT /api/products:', error);
    res.status(500).json({ message: 'Error updating product in KV', error: error.message });
  }
}

async function handleDelete(req, res) {
  if (!requireAdmin(req, res)) return;
  try {
    const { id: productIdToDelete } = req.query;

    if (!productIdToDelete) {
      return res.status(400).json({ message: 'Product ID is required' });
    }

    let currentProducts = await getProductsFromKV();
    const productIndex = currentProducts.findIndex(p => p.id === productIdToDelete);

    if (productIndex === -1) {
      return res.status(404).json({ message: 'Product not found' });
    }

    const updatedProducts = currentProducts.filter(p => p.id !== productIdToDelete);
    await saveProductsToKV(updatedProducts);

    let currentSubscriptions = await getSubscriptionsFromKV();
    const updatedSubscriptions = currentSubscriptions.filter(s => s.product_id !== productIdToDelete);

    if (updatedSubscriptions.length < currentSubscriptions.length) {
      await saveSubscriptionsToKV(updatedSubscriptions);
    }

    res.status(200).json({ message: 'Product and associated subscriptions deleted successfully' });
  } catch (error) {
    console.error("Error in DELETE /api/products:", error);
    res.status(500).json({ message: 'Error deleting product from KV', error: error.message });
  }
}

export default async function handler(req, res) {
  const { method } = req;

  switch (method) {
    case 'GET':
      await handleGet(req, res);
      break;
    case 'POST':
      await handlePost(req, res);
      break;
    case 'PUT':
      await handlePut(req, res);
      break;
    case 'DELETE':
      await handleDelete(req, res);
      break;
    default:
      res.setHeader('Allow', ['GET', 'POST', 'PUT', 'DELETE']);
      res.status(405).json({ message: `Method ${method} Not Allowed` });
  }
}
