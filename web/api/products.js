import { kv } from '@vercel/kv';

// KV Helper functions for Products
async function getProductsFromKV() {
  try {
    const productsData = await kv.get('products');
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
export default async function handler(req, res) {
  const { method } = req;

  switch (method) {
    case 'GET':
      try {
        const products = await getProductsFromKV();
        res.status(200).json(products);
      } catch (error) {
        console.error("Error in GET /api/products:", error);
        res.status(500).json({ message: 'Error retrieving products from KV', error: error.message });
      }
      break;

    case 'POST':
      try {
        const { url, name } = req.body;

        if (!url || typeof url !== 'string') {
          return res.status(400).json({ message: 'Invalid URL' });
        }
        try {
          new URL(url); // Validate URL format
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
          id: String(Date.now()), // Simple ID generation
          url: url,
          name: name.trim(),
        };

        currentProducts.push(newProduct);
        await saveProductsToKV(currentProducts);
        res.status(201).json(newProduct);
      } catch (error) {
        console.error("Error in POST /api/products:", error);
        res.status(500).json({ message: 'Error saving product to KV', error: error.message });
      }
      break;

    case 'PUT':
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
          new URL(url);
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
          name: name.trim(),
        };
        await saveProductsToKV(currentProducts);
        res.status(200).json(currentProducts[productIndex]);
      } catch (error) {
        console.error('Error in PUT /api/products:', error);
        res.status(500).json({ message: 'Error updating product in KV', error: error.message });
      }
      break;

    case 'DELETE':
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

        // Filter out the product
        const updatedProducts = currentProducts.filter(p => p.id !== productIdToDelete);
        await saveProductsToKV(updatedProducts);

        // Remove associated subscriptions
        let currentSubscriptions = await getSubscriptionsFromKV();
        const updatedSubscriptions = currentSubscriptions.filter(s => s.productId !== productIdToDelete);

        // Save subscriptions only if they changed
        if (updatedSubscriptions.length < currentSubscriptions.length) {
            await saveSubscriptionsToKV(updatedSubscriptions);
        }

        res.status(200).json({ message: 'Product and associated subscriptions deleted successfully' });
      } catch (error) {
        console.error("Error in DELETE /api/products:", error);
        res.status(500).json({ message: 'Error deleting product from KV', error: error.message });
      }
      break;

    default:
      res.setHeader('Allow', ['GET', 'POST', 'PUT', 'DELETE']);
      res.status(405).json({ message: `Method ${method} Not Allowed` });
  }
}
