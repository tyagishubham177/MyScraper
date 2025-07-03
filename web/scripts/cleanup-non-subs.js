import nodemailer from 'nodemailer';

// Safely import @vercel/kv only when required variables are present
let kv;
if (process.env.KV_REST_API_URL && process.env.KV_REST_API_TOKEN) {
  ({ kv } = await import('@vercel/kv'));
} else {
  console.error('KV_REST_API_URL and KV_REST_API_TOKEN environment variables are required.');
  process.exit(1);
}

const removalEmailHtml = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Account Status Update</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="margin-bottom: 25px;">
        <h1 style="color: #d32f2f; font-size: 22px; margin-bottom: 8px;">🚨 Account Status Alert 🚨</h1>
    </div>
    <div style="background-color: #f8f9fa; padding: 18px; border-radius: 6px; margin-bottom: 18px;">
        <h2 style="color: #333; margin-top: 0; font-size: 16px;">No Products Subscribed</h2>
        <p style="margin-bottom: 0; color: #666;">We noticed you haven't added any products to your account yet. Hence we are deactiving this email.</p>
    </div>
    <div style="background-color: #fff8e1; padding: 16px; border-radius: 4px; margin-bottom: 16px;">
        <h3 style="color: #e65100; margin-top: 0; font-size: 15px;">Free Tier Notice ⚠️</h3>
        <p style="color: #333; margin-bottom: 12px;">Due to server load on our free tier hosted project, we need to manage resources to ensure fair access for all users.</p>
    </div>
    <div style="background-color: #e3f2fd; padding: 16px; border-radius: 4px; margin-bottom: 20px;">
        <h3 style="color: #1565c0; margin-top: 0; font-size: 15px;">Easy Reactivation 🔄</h3>
        <p style="color: #333; margin-bottom: 0;">You can get your email re-registered at any time if needed. The process is simple and quick.</p>
    </div>
    <hr style="border: none; height: 1px; background-color: #ddd; margin: 20px 0;">
    <div style="text-align: center; color: #666; font-size: 14px;">
        <p style="margin: 0;">Questions? Just reply to this email 📧</p>
    </div>
</body>
</html>`;

async function sendRemovalEmail(emails) {
  const uniqueEmails = Array.from(new Set((emails || []).filter(Boolean)));
  if (uniqueEmails.length === 0) return;

  const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: parseInt(process.env.EMAIL_PORT || '0', 10),
    secure: parseInt(process.env.EMAIL_PORT || '0', 10) === 465,
    auth: {
      user: process.env.EMAIL_HOST_USER,
      pass: process.env.EMAIL_HOST_PASSWORD,
    },
  });

  let senderEmail = process.env.EMAIL_SENDER || process.env.EMAIL_HOST_USER;
  if (!senderEmail) {
    console.error('EMAIL_SENDER environment variable is not set.');
    return;
  }

  const mailOptions = {
    from: senderEmail,
    to: senderEmail,
    bcc: uniqueEmails,
    subject: 'Account Deactivation Alert',
    html: removalEmailHtml,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`Removal notification sent to ${uniqueEmails.length} user(s)`);
  } catch (err) {
    console.error(`Failed to send email to ${uniqueEmails.join(', ')}:`, err);
  }
}

async function cleanupNonSubscribers() {
  try {
    const recipients = (await kv.get('recipients')) || [];
    const subscriptions = (await kv.get('subscriptions')) || [];

    const subscribed = new Set(subscriptions.map(s => s.recipient_id));
    const keepRecipients = recipients.filter(r => subscribed.has(r.id));
    const removedRecipients = recipients.filter(r => !subscribed.has(r.id));
    const removedCount = removedRecipients.length;

    if (removedCount === 0) {
      console.log('No non-subscriber recipients to remove.');
      return;
    }

    await kv.set('recipients', keepRecipients);

    try {
      await sendRemovalEmail(removedRecipients.map(r => r.email));
    } catch (e) {
      console.error('Error sending removal email:', e);
    }

    console.log(`Removed ${removedCount} recipient(s) with no subscriptions.`);
  } catch (error) {
    console.error('Error during cleanup:', error);
    process.exitCode = 1;
  }
}

cleanupNonSubscribers();
