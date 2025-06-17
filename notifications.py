import smtplib
from email.mime.text import MIMEText
import requests # For the commented-out send_fast2sms
import os # For F2S_KEY/TO if they were used directly (they are in the commented out function)
from typing import List

# ——————————————————————————————————————————
# Config from GitHub Secrets / .env (assumed to be in config.py or environment)
# F2S_KEY   = os.getenv("F2S_API_KEY")
# F2S_TO    = os.getenv("F2S_NUMBERS")
# ——————————————————————————————————————————


def format_long_message(product_name: str, url: str) -> str:
    # Basic HTML structure for the email body
    html_body = f"""
    <html>
    <head>
        <style>
        body {{ font-family: sans-serif; margin: 0; padding: 20px; background-color: #f4f4f4; }}
        .container {{ background-color: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333333; }}
        p {{ color: #555555; line-height: 1.6; }}
        .button {{
            display: inline-block;
            padding: 10px 20px;
            margin-top: 15px;
            background-color: #28a745; /* Green */
            color: white !important; /* Ensure text is white */
            text-decoration: none;
            border-radius: 5px;
            font-weight: bold;
        }}
        .button:hover {{ background-color: #218838; }}
        .button-manage {{
            display: inline-block;
            padding: 10px 20px;
            margin-top: 10px; /* Adjusted margin for spacing */
            background-color: #007bff; /* Blue */
            color: white !important; /* Ensure text is white */
            text-decoration: none;
            border-radius: 5px;
            font-weight: bold;
        }}
        .button-manage:hover {{ background-color: #0056b3; }}
        </style>
    </head>
    <body>
        <div class="container">
        <h1>🚀 Stock Alert! 🚀</h1>
        <p>Good news! The product you're watching is back in stock:</p>
        <p><strong>{product_name.strip()}</strong></p>
        <p>Don't miss out! Check it out here:</p>
        <a href="{url}" class="button">View Product Now</a>
        <p style="margin-top: 20px; color: #555555;">
            ⏸️ You can pause notifications for this product in the app, or adjust the window in which the notifications are sent to you. ⚙️
        </p>
        <a href="https://my-scraper-nine.vercel.app/" class="button-manage">Manage Notifications</a>
        <p style="margin-top: 20px; font-size: 0.9em; color: #777;">
            This is an automated notification.
        </p>
        </div>
    </body>
    </html>
    """
    return html_body

def format_summary_email_body(run_timestamp_str: str, summary_data_list: list, total_notifications_sent: int) -> str:
    """Formats the HTML body for the summary email."""
    html_output = f"""<html>
<head>
    <style>
        body {{ font-family: sans-serif; margin: 0; padding: 20px; background-color: #f4f4f4; }}
        .container {{ background-color: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1, h2 {{ color: #333333; }}
        p {{ color: #555555; line-height: 1.6; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ border: 1px solid #dddddd; text-align: left; padding: 8px; }}
        th {{ background-color: #f2f2f2; }}
        .footer {{ margin-top: 20px; font-size: 0.9em; color: #777; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Stock Check Run Summary</h1>
        <p><strong>Run Timestamp:</strong> {run_timestamp_str}</p>
        <p><strong>Total User Notifications Sent:</strong> {total_notifications_sent}</p>
        <h2>Details:</h2>
        <table>
            <thead>
                <tr>
                    <th>Product Name</th>
                    <th>Product URL</th>
                    <th>Email sent to</th>
                    <th>Overall Product Status</th>
                </tr>
            </thead>
            <tbody>
"""

    ignorable_statuses = {
        "Skipped - Subscription Not Due",
        "Skipped - Invalid Subscription Object",
        "Error fetching subscriptions",
        "Not Sent - Delayed",
        "Not Sent - Scraping Error",
        "Skipped - Status Unknown"
    }

    failed_notification_for_instock_statuses = {
        "Not Sent - Email Send Error",
        "Not Sent - Recipient Email Missing",
        "Not Sent - Email Config Missing"
    }

    for product_data in summary_data_list:
        product_name = product_data.get('product_name', 'N/A')
        product_url = product_data.get('product_url', '#')
        subscriptions = product_data.get('subscriptions', [])

        user_emails_list = []
        failed_to_notify_list = []
        is_in_stock_attempted = False  # True if any notification attempt was made (Sent, OOS, or specific failures)
        all_out_of_stock = True  # Assume all OOS until an in-stock or failed (but attempted) notification is found

        if not subscriptions:
            subscribed_emails_csv = "N/A"
            product_status_overall = "No subscriptions for this product."
        else:
            for sub_info in subscriptions:
                user_email = sub_info.get('user_email', 'N/A')
                current_sub_status = sub_info.get('status', 'N/A')

                if current_sub_status == "Sent":
                    if user_email not in user_emails_list:  # Avoid duplicate emails in the list
                        user_emails_list.append(user_email)
                    is_in_stock_attempted = True
                    all_out_of_stock = False
                elif current_sub_status == "Not Sent - Out of Stock":
                    is_in_stock_attempted = True
                    # all_out_of_stock remains true if this is the status for all relevant subs
                elif current_sub_status in failed_notification_for_instock_statuses:
                    is_in_stock_attempted = True
                    all_out_of_stock = False  # Product was in stock, but notification failed
                    if user_email not in failed_to_notify_list:
                        failed_to_notify_list.append(user_email)
                elif current_sub_status not in ignorable_statuses:
                    # Any other non-ignorable status means we can't definitively say all were OOS
                    all_out_of_stock = False

            subscribed_emails_csv = ", ".join(user_emails_list) if user_emails_list else "N/A"

            # Determine product_status_overall
            if not is_in_stock_attempted and all_out_of_stock: # This implies all subscriptions were ignorable
                 product_status_overall = "Status inconclusive (e.g., all subscriptions skipped/delayed)"
            elif all_out_of_stock and is_in_stock_attempted:
                product_status_overall = "Out of stock"
            elif is_in_stock_attempted:
                if failed_to_notify_list:
                    product_status_overall = f"Failed to notify: {', '.join(failed_to_notify_list)}"
                else:
                    product_status_overall = "Notification sent" # Implies in stock and successfully notified or no one to notify
            else: # Should ideally be covered by the first condition, but as a fallback
                product_status_overall = "Status inconclusive (e.g., all subscriptions skipped/delayed)"


        html_output += f"""
    <tr>
        <td>{product_name}</td>
        <td><a href="{product_url}">{product_url}</a></td>
        <td>{subscribed_emails_csv}</td>
        <td>{product_status_overall}</td>
    </tr>
"""

    html_output += """
            </tbody>
        </table>
        <p class="footer">This is an automated summary email.</p>
    </div>
</body>
</html>
"""
    return html_output

def format_short_message(product_name: str) -> str:
    return f"ALERT: {product_name.strip()} is back in stock!"

def send_email_notification(subject: str, body: str, sender: str, recipients: List[str], host: str, port: int, username: str = None, password: str = None):
    """Sends an email notification."""
    if not (host and sender and recipients and all(recipients)):
        print("⚠️ Essential email configuration or recipient list is missing or invalid.")
        return
    try:
        msg = MIMEText(body, 'html')
        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = sender  # Display sender in the "To" field
        # Do not include a visible Bcc header. Recipients are passed to
        # sendmail directly so they will not see each other's addresses.

        with smtplib.SMTP(host, port) as server:
            if username and password:
                server.starttls()  # Upgrade connection to secure
                server.login(username, password)
            # Recipients are passed here so the email is Bcc'd to them
            server.sendmail(sender, recipients, msg.as_string())
        print("Email notification sent successfully.")
    except smtplib.SMTPException as e:
        print(f"SMTP error occurred: {e}")
    except Exception as e:
        print(f"An error occurred while sending email: {e}")

# def send_fast2sms(msg: str):
#     """POST a Quick SMS via Fast2SMS API."""
#     F2S_KEY = os.getenv("F2S_API_KEY") # Added os.getenv here
#     F2S_TO = os.getenv("F2S_NUMBERS") # Added os.getenv here
#     if not (F2S_KEY and F2S_TO):
#         print("⚠️  Fast2SMS credentials missing")
#         return
#     payload = {
#         "message": msg,
#         "language": "english",
#         "route": "q",  # quick SMS route (no DLT template)
#         "numbers": F2S_TO,
#     }
#     headers = {
#         "authorization": F2S_KEY,
#         "Content-Type": "application/x-www-form-urlencoded",
#     }
#     try:
#         r = requests.post(
#             "https://www.fast2sms.com/dev/bulkV2",
#             data=payload,
#             headers=headers,
#             timeout=10,
#         )
#         r.raise_for_status()
#     except requests.RequestException as e:
#         print("Fast2SMS error:", e)
#         return
#     print("Fast2SMS:", r.status_code, r.text)
