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
        res.status(200).json(db.recipients);
      } catch (error) {
        res.status(500).json({ message: 'Error retrieving recipients', error: error.message });
      }
      break;

    case 'POST':
      try {
        const { email } = req.body;

        if (!email || !/\S+@\S+\.\S+/.test(email)) {
          return res.status(400).json({ message: 'Invalid email address' });
        }

        if (db.recipients.find(r => r.email === email)) {
          return res.status(409).json({ message: 'Email already exists' });
        }

        const newRecipient = {
          id: String(Date.now()),
          email: email,
        };

        db.recipients.push(newRecipient);
        writeDb(db);
        res.status(201).json(newRecipient);
      } catch (error) {
        console.error("Error in POST /api/recipients:", error);
        if (error.message === 'Could not write to database.') {
            return res.status(500).json({ message: 'Error saving recipient: Could not write to database.' });
        }
        res.status(500).json({ message: 'Error saving recipient', error: error.message });
      }
      break;

    case 'DELETE':
      try {
        const { id } = req.query;

        if (!id) {
          return res.status(400).json({ message: 'Recipient ID is required' });
        }

        const recipientExists = db.recipients.some(r => r.id === id);
        if (!recipientExists) {
          return res.status(404).json({ message: 'Recipient not found' });
        }

        db.recipients = db.recipients.filter(r => r.id !== id);
        // Also remove associated subscriptions
        db.subscriptions = db.subscriptions.filter(s => s.recipientId !== id);

        writeDb(db);
        res.status(200).json({ message: 'Recipient deleted successfully' });
      } catch (error) {
        console.error("Error in DELETE /api/recipients:", error);
         if (error.message === 'Could not write to database.') {
            return res.status(500).json({ message: 'Error deleting recipient: Could not write to database.' });
        }
        res.status(500).json({ message: 'Error deleting recipient', error: error.message });
      }
      break;

    default:
      res.setHeader('Allow', ['GET', 'POST', 'DELETE']);
      res.status(405).json({ message: `Method ${method} Not Allowed` });
  }
};
