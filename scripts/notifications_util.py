import config
import notifications
from scripts import stock_utils

async def notify_users(
    effective_name,
    product_url,
    subs,
    recipients_map,
    current_time,
    pincode,
):
    current_summary = []
    valid_emails = []
    for sub in subs:
        rid = sub.get("recipient_id")
        info = recipients_map.get(rid)
        email = info.get("email") if info else None
        pincode = info.get("pincode") if info else None
        start_t = sub.get("start_time", "00:00")
        end_t = sub.get("end_time", "23:59")

        if sub.get("paused"):
            status = "Skipped - Paused"
        elif not stock_utils.within_time_window(start_t, end_t, current_time):
            status = "Skipped - Subscription Not Due"
        elif email:
            valid_emails.append(email)
            status = "Sent"
        else:
            status = "Not Sent - Recipient Email Missing"

        current_summary.append({"user_email": email or "Unknown", "status": status})

    sent_count = 0
    if valid_emails and config.EMAIL_HOST and config.EMAIL_SENDER:
        try:
            await notifications.send_email_notification(
                subject=f"{effective_name.strip()} In Stock Alert!",
                body=notifications.format_long_message(effective_name, product_url),
                sender=config.EMAIL_SENDER,
                recipients=valid_emails,
                host=config.EMAIL_HOST,
                port=config.EMAIL_PORT,
                username=config.EMAIL_HOST_USER,
                password=config.EMAIL_HOST_PASSWORD,
            )
            print(f"📨 Email notifications sent for '{effective_name}'.")
            sent_count = len(valid_emails)
        except Exception as e:
            print(f"Error sending email for '{effective_name}': {e}")
            for summary in current_summary:
                if summary["status"] == "Sent":
                    summary["status"] = "Not Sent - Email Send Error"
    else:
        if valid_emails:
            print(f"Email configuration missing for '{effective_name}'.")
            for summary in current_summary:
                if summary["status"] == "Sent":
                    summary["status"] = "Not Sent - Email Config Missing"
    return current_summary, sent_count
