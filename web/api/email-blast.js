import { kv } from '@vercel/kv';
import { requireAdmin } from './auth.js'; // Assuming auth.js is in the same directory
import nodemailer from 'nodemailer';

async function getRecipientsFromKV() {
  try {
    const recipientsData = await kv.get('recipients');
    return recipientsData || [];
  } catch (error) {
    console.error('Error fetching recipients from KV:', error);
    return [];
  }
}

async function getSubscriptionsFromKV() {
  try {
    const subscriptionsData = await kv.get('subscriptions');
    return subscriptionsData || [];
  } catch (error) {
    console.error('Error fetching subscriptions from KV:', error);
    return [];
  }
}

export default async function handler(req, res) {
  if (!requireAdmin(req, res)) {
    // requireAdmin will handle the response if not authorized
    return;
  }

  if (req.method !== 'POST') {
    res.setHeader('Allow', ['POST']);
    return res.status(405).json({ message: `Method ${req.method} Not Allowed` });
  }

  const { subject, htmlBody, plainBody, recipientType, adminEmail, extraRecipients = [] } = req.body;

  if (!subject || (!htmlBody && !plainBody)) {
    return res.status(400).json({ message: 'Subject and body (HTML or Plain) are required.' });
  }
  if (!recipientType) {
    return res.status(400).json({ message: 'Recipient type is required.' });
  }

  let targetEmails = [];

  try {
    const allRecipients = await getRecipientsFromKV();

    if (recipientType === 'self') {
      if (adminEmail) {
        targetEmails.push(adminEmail);
      } else {
        // Fallback: try to find admin among recipients if email not passed (less ideal)
        // Or, enforce adminEmail is passed from client for 'self'
        console.warn("Admin email not provided for 'self' recipient type.");
        // For safety, if adminEmail is not explicitly provided for 'self', do not send.
        // This relies on the client sending adminEmail.
        if (!adminEmail) {
            return res.status(400).json({ message: 'Admin email required for "self" recipient type and not provided.' });
        }
      }
    } else if (recipientType === 'all') {
      targetEmails = allRecipients.map(r => r.email);
    } else if (recipientType === 'non-subscribers') {
      const allSubscriptions = await getSubscriptionsFromKV();
      const subscribedRecipientIds = new Set();
      allSubscriptions.forEach(sub => {
        // Consider a subscription active if it's not explicitly paused
        const paused = sub.paused === true || sub.paused === 'true';
        if (!paused) {
          subscribedRecipientIds.add(sub.recipient_id);
        }
      });

      targetEmails = allRecipients
        .filter(r => !subscribedRecipientIds.has(r.id))
        .map(r => r.email);
    } else {
      return res.status(400).json({ message: 'Invalid recipient type specified.' });
    }

    // Merge any extra recipients provided by the admin
    if (Array.isArray(extraRecipients)) {
      extraRecipients.forEach(r => {
        if (r && !targetEmails.includes(r)) targetEmails.push(r);
      });
    }

    if (targetEmails.length === 0) {
      return res.status(200).json({ message: 'No recipients found for the selected criteria. No emails sent.' });
    }

    // Email sending logic using nodemailer
    // Ensure these environment variables are set in your Vercel project
    const transporter = nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: parseInt(process.env.EMAIL_PORT, 10),
      secure: parseInt(process.env.EMAIL_PORT, 10) === 465, // true for 465, false for other ports
      auth: {
        user: process.env.EMAIL_HOST_USER,
        pass: process.env.EMAIL_HOST_PASSWORD,
      },
    });

    let senderEmail = process.env.EMAIL_SENDER;
    if (!senderEmail) {
        // Fallback to EMAIL_HOST_USER when a dedicated sender isn't specified
        senderEmail = process.env.EMAIL_HOST_USER;
        if (!senderEmail) {
            console.error('EMAIL_SENDER environment variable is not set.');
            return res.status(500).json({ message: 'Email sender configuration is missing on the server.' });
        }
    }

    const mailOptions = {
      from: senderEmail,
      to: senderEmail,
      bcc: targetEmails,
      subject: subject,
    };
    if (htmlBody) {
      mailOptions.html = htmlBody;
    }
    if (plainBody) {
      mailOptions.text = plainBody;
    }

    try {
      await transporter.sendMail(mailOptions);
    } catch (error) {
      console.error('Failed to send email blast:', error);
      return res.status(500).json({ message: 'Failed to send email blast.', error: error.message });
    }

    return res.status(200).json({ message: `Email blast sent successfully to ${targetEmails.length} users.` });

  } catch (error) {
    console.error('Error processing email blast:', error);
    return res.status(500).json({ message: 'An unexpected error occurred on the server.', error: error.message });
  }
}
