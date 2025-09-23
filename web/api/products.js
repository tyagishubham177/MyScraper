import { requireAdmin } from '../utils/auth.js';
import {
  deleteProduct as deleteProductRecord,
  listProducts,
  saveProduct as saveProductRecord,
  listSubscriptions,
  deleteSubscription as deleteSubscriptionRecord,
} from './data-store.js';

// Main request handler
async function handleGet(req, res) {
  try {
    const products = await listProducts();
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

    const currentProducts = await listProducts();
    if (currentProducts.find(p => p.url === url)) {
      return res.status(409).json({ message: 'Product with this URL already exists' });
    }

    const newProduct = {
      id: String(Date.now()),
      url: url,
      name: name.trim()
    };

    await saveProductRecord(newProduct);
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

    const products = await listProducts();
    const product = products.find(p => p.id === id);
    if (!product) {
      return res.status(404).json({ message: 'Product not found' });
    }
    const updated = { ...product, url, name: name.trim() };
    await saveProductRecord(updated);
    res.status(200).json(updated);
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

    const products = await listProducts();
    const existing = products.find(p => p.id === productIdToDelete);

    if (!existing) {
      return res.status(404).json({ message: 'Product not found' });
    }

    await deleteProductRecord(productIdToDelete);

    const subs = await listSubscriptions();
    const toDelete = subs.filter(s => s.product_id === productIdToDelete);
    for (const sub of toDelete) {
      await deleteSubscriptionRecord(sub.id);
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
