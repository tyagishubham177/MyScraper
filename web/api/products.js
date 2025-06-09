const fs = require('fs');
const path = require('path');

const dbPath = path.resolve(process.cwd(), 'web/data/db.json');

// Helper function to read the database
function readDb() {
  try {
    if (fs.existsSync(dbPath)) {
      const dbJson = fs.readFileSync(dbPath, 'utf8');
      return JSON.parse(dbJson);
    }
  } catch (error) {
    console.error("Error reading or parsing db.json:", error);
  }
  return { recipients: [], products: [], subscriptions: [] };
}

// Helper function to write to the database
function writeDb(data) {
  try {
    const dataDir = path.dirname(dbPath);
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }
    fs.writeFileSync(dbPath, JSON.stringify(data, null, 2), 'utf8');
  } catch (error) {
    console.error("Error writing db.json:", error);
    throw new Error('Could not write to database.'); // Re-throw to indicate failure
  }
}

// Main request handler
module.exports = async (req, res) => {
  const { method } = req;
  const db = readDb();

  switch (method) {
    case 'GET':
      try {
        res.status(200).json(db.products);
      } catch (error) {
        res.status(500).json({ message: 'Error retrieving products', error: error.message });
      }
      break;

    case 'POST':
      try {
        const { url, name } = req.body;

        if (!url || typeof url !== 'string' ) { // Basic URL validation
          return res.status(400).json({ message: 'Invalid URL' });
        }
        // Attempt to construct a URL object to validate
        try {
          new URL(url);
        } catch (_) {
          return res.status(400).json({ message: 'Invalid URL format' });
        }


        if (!name || typeof name !== 'string' || name.trim() === '') {
          return res.status(400).json({ message: 'Invalid product name' });
        }

        if (db.products.find(p => p.url === url)) {
          return res.status(409).json({ message: 'Product with this URL already exists' });
        }

        const newProduct = {
          id: String(Date.now()),
          url: url,
          name: name.trim(),
        };

        db.products.push(newProduct);
        writeDb(db);
        res.status(201).json(newProduct);
      } catch (error) {
        console.error("Error in POST /api/products:", error);
        if (error.message === 'Could not write to database.') {
            return res.status(500).json({ message: 'Error saving product: Could not write to database.' });
        }
        res.status(500).json({ message: 'Error saving product', error: error.message });
      }
      break;

    case 'DELETE':
      try {
        const { id } = req.query;

        if (!id) {
          return res.status(400).json({ message: 'Product ID is required' });
        }

        const productExists = db.products.some(p => p.id === id);
        if (!productExists) {
          return res.status(404).json({ message: 'Product not found' });
        }

        db.products = db.products.filter(p => p.id !== id);
        // Also remove associated subscriptions
        db.subscriptions = db.subscriptions.filter(s => s.productId !== id);

        writeDb(db);
        res.status(200).json({ message: 'Product deleted successfully' });
      } catch (error) {
        console.error("Error in DELETE /api/products:", error);
        if (error.message === 'Could not write to database.') {
            return res.status(500).json({ message: 'Error deleting product: Could not write to database.' });
        }
        res.status(500).json({ message: 'Error deleting product', error: error.message });
      }
      break;

    default:
      res.setHeader('Allow', ['GET', 'POST', 'DELETE']);
      res.status(405).json({ message: `Method ${method} Not Allowed` });
  }
};
