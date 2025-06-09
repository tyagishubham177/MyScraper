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
    throw new Error('Could not write to database.');
  }
}

// Main request handler
module.exports = async (req, res) => {
  const { method } = req;
  const db = readDb();

  switch (method) {
    case 'POST':
      try {
        const { recipient_id, product_id } = req.body;

        if (!recipient_id || !product_id) {
          return res.status(400).json({ message: 'Recipient ID and Product ID are required' });
        }

        const recipientExists = db.recipients.some(r => r.id === recipient_id);
        if (!recipientExists) {
          return res.status(404).json({ message: 'Recipient not found' });
        }

        const productExists = db.products.some(p => p.id === product_id);
        if (!productExists) {
          return res.status(404).json({ message: 'Product not found' });
        }

        const existingSubscription = db.subscriptions.find(
          s => s.recipient_id === recipient_id && s.product_id === product_id
        );

        if (existingSubscription) {
          return res.status(200).json({ message: 'Subscription already exists', subscription: existingSubscription });
        }

        const newSubscription = {
          id: String(Date.now()),
          recipient_id: recipient_id,
          product_id: product_id,
        };

        db.subscriptions.push(newSubscription);
        writeDb(db);
        res.status(201).json(newSubscription);
      } catch (error) {
        console.error("Error in POST /api/subscriptions:", error);
        if (error.message === 'Could not write to database.') {
            return res.status(500).json({ message: 'Error creating subscription: Could not write to database.' });
        }
        res.status(500).json({ message: 'Error creating subscription', error: error.message });
      }
      break;

    case 'DELETE':
      try {
        const { recipient_id, product_id } = req.body; // Vercel uses req.body for DELETE by default

        if (!recipient_id || !product_id) {
          return res.status(400).json({ message: 'Recipient ID and Product ID are required in the request body' });
        }

        const initialSubscriptionsCount = db.subscriptions.length;
        db.subscriptions = db.subscriptions.filter(
          s => !(s.recipient_id === recipient_id && s.product_id === product_id)
        );

        if (db.subscriptions.length === initialSubscriptionsCount) {
          return res.status(404).json({ message: 'Subscription not found' });
        }

        writeDb(db);
        res.status(200).json({ message: 'Subscription deleted successfully' });
      } catch (error) {
        console.error("Error in DELETE /api/subscriptions:", error);
        if (error.message === 'Could not write to database.') {
            return res.status(500).json({ message: 'Error deleting subscription: Could not write to database.' });
        }
        res.status(500).json({ message: 'Error deleting subscription', error: error.message });
      }
      break;

    case 'GET':
      try {
        const { recipient_id, product_id } = req.query;

        if (recipient_id && product_id) {
          return res.status(400).json({ message: 'Provide either recipient_id OR product_id, not both.' });
        }

        if (recipient_id) {
          const recipientSubscriptions = db.subscriptions.filter(s => s.recipient_id === recipient_id);
          res.status(200).json(recipientSubscriptions);
        } else if (product_id) {
          const productSubscriptions = db.subscriptions.filter(s => s.product_id === product_id);
          res.status(200).json(productSubscriptions);
        } else {
          // No parameters: return all subscriptions or an error/empty array.
          // For now, let's return all subscriptions, could be changed to an error.
          // res.status(200).json(db.subscriptions);
          return res.status(400).json({ message: 'Missing recipient_id or product_id query parameter.' });
        }
      } catch (error) {
        res.status(500).json({ message: 'Error retrieving subscriptions', error: error.message });
      }
      break;

    default:
      res.setHeader('Allow', ['GET', 'POST', 'DELETE']);
      res.status(405).json({ message: `Method ${method} Not Allowed` });
  }
};
