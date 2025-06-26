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

  const { subject, htmlBody, plainBody, recipientType, adminEmail } = req.body;

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
        if (!sub.paused) {
          subscribedRecipientIds.add(sub.recipient_id);
        }
      });

      targetEmails = allRecipients
        .filter(r => !subscribedRecipientIds.has(r.id))
        .map(r => r.email);
    } else {
      return res.status(400).json({ message: 'Invalid recipient type specified.' });
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

    const senderEmail = process.env.EMAIL_SENDER;
    if (!senderEmail) {
        console.error('EMAIL_SENDER environment variable is not set.');
        return res.status(500).json({ message: 'Email sender configuration is missing on the server.' });
    }

    let emailsSentCount = 0;
    let failedSends = [];

    for (const email of targetEmails) {
      if (!email) continue; // Skip if email is somehow undefined/null

      const mailOptions = {
        from: senderEmail,
        to: email,
        subject: subject,
      };
      if (htmlBody) {
        mailOptions.html = htmlBody;
      }
      if (plainBody) {
        mailOptions.text = plainBody;
      }
      // If both html and text are provided, nodemailer will use html and include text as fallback.
      // If only plainBody is provided, text will be used. If only htmlBody, html will be used.

      try {
        await transporter.sendMail(mailOptions);
        emailsSentCount++;
      } catch (error) {
        console.error(`Failed to send email to ${email}:`, error);
        failedSends.push({ email, error: error.message });
      }
    }

    if (failedSends.length > 0) {
        return res.status(207).json({ // Multi-Status
            message: `Email blast partially completed. Sent to ${emailsSentCount} users. Failed for ${failedSends.length} users.`,
            successful_sends: emailsSentCount,
            failed_sends: failedSends
        });
    }

    return res.status(200).json({ message: `Email blast sent successfully to ${emailsSentCount} users.` });

  } catch (error) {
    console.error('Error processing email blast:', error);
    return res.status(500).json({ message: 'An unexpected error occurred on the server.', error: error.message });
  }
}
