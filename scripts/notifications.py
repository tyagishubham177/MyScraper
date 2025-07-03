import smtplib
import asyncio
from email.mime.text import MIMEText

# ——————————————————————————————————————————
# Config from GitHub Secrets / .env (assumed to be in config.py or environment)
# F2S_KEY   = os.getenv("F2S_API_KEY")
# F2S_TO    = os.getenv("F2S_NUMBERS")
# ——————————————————————————————————————————


def format_long_message(product_name: str, url: str) -> str:
    html_body = f"""
    <html>
        <head>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                margin: 0;
                padding: 20px;
                background: #f0f2f5;
                line-height: 1.4;
            }}
            .container {{
                max-width: 500px;
                width: 100%;
                margin: 0 auto;
                background: white;
                border-radius: 12px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.1);
                border: 2px solid #e9ecef;
                overflow: hidden;
            }}
            .header {{
                background: linear-gradient(135deg, #28a745, #20c997);
                padding: 16px;
                text-align: center;
                color: white;
            }}
            .header h1 {{
                margin: 0;
                font-size: 1.5em;
                font-weight: 600;
            }}
            .content {{
                padding: 20px 16px;
                text-align: center;
            }}
            .message {{
                color: #333;
                font-size: 1em;
                margin-bottom: 16px;
            }}
            .product-name {{
                background: #f8f9ff;
                padding: 12px;
                border-radius: 8px;
                margin: 16px 0;
                border-left: 3px solid #667eea;
                font-weight: 600;
                color: #2c3e50;
                font-size: 1.1em;
            }}
            .button {{
                display: block;
                width: calc(100% - 32px);
                max-width: 280px;
                margin: 12px auto;
                padding: 14px 20px;
                background: linear-gradient(135deg, #007bff, #0056b3);
                color: white !important;
                text-decoration: none;
                border-radius: 8px;
                font-weight: 600;
                font-size: 1em;
                transition: all 0.2s ease;
                box-sizing: border-box;
            }}
            .button:hover {{
                transform: translateY(-1px);
                box-shadow: 0 4px 12px rgba(0, 123, 255, 0.3);
            }}
            .settings-note {{
                background: #f8f9fa;
                padding: 20px;
                border-radius: 10px;
                margin: 20px 0;
                font-size: 1em;
                color: #333;
                text-align: left;
                border: 2px solid #e9ecef;
            }}
            .settings-note strong {{
                font-size: 1.1em;
                color: #2c3e50;
                display: block;
                margin-bottom: 12px;
            }}
            .feature-list {{
                margin-top: 12px;
            }}
            .feature-item {{
                padding: 8px 0;
                font-size: 1em;
                font-weight: 500;
                color: #495057;
                border-bottom: 1px solid #e9ecef;
            }}
            .feature-item:last-child {{
                border-bottom: none;
            }}
            .webapp-note {{
                background: #e3f2fd;
                padding: 12px;
                border-radius: 8px;
                margin: 16px 0;
                font-size: 0.95em;
                color: #1976d2;
                font-weight: 500;
                border: 1px solid #bbdefb;
            }}
            .footer {{
                background: #f8f9fa;
                padding: 12px;
                text-align: center;
                color: #6c757d;
                font-size: 0.8em;
                border-top: 1px solid #e9ecef;
            }}

            /* Mobile optimizations */
            @media (max-width: 480px) {{
                body {{ padding: 10px; }}
                .container {{
                    border-radius: 8px;
                    max-width: 100%;
                }}
                .header {{ padding: 12px; }}
                .header h1 {{ font-size: 1.3em; }}
                .content {{ padding: 16px 12px; }}
                .product-name {{ padding: 10px; font-size: 1em; }}
                .button {{ padding: 12px 16px; font-size: 0.95em; }}
                .settings-note {{ padding: 16px; font-size: 0.9em; }}
            }}

            /* Dark mode support */
            @media (prefers-color-scheme: dark) {{
                body {{ background: #1a1a1a; }}
                .container {{ background: #2d2d2d; color: #e0e0e0; border-color: #444; }}
                .product-name {{ background: #3a3a3a; color: #e0e0e0; }}
                .settings-note {{ background: #3a3a3a; color: #e0e0e0; border-color: #555; }}
                .webapp-note {{ background: #1e3a5f; color: #81c784; border-color: #2196f3; }}
                .footer {{ background: #3a3a3a; color: #888; border-color: #555; }}
                .feature-item {{ color: #ccc; border-color: #555; }}
            }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🚀🚀 Stock Alert!</h1>
                </div>
                <div class="content">
                    <div class="message">
                        Your watched product is now available:
                    </div>
                    <div class="product-name">
                        {product_name.strip()}
                    </div>
                    <a href="{url}" class="button">🛍️ View Product</a>
                    <div class="settings-note">
                        <strong>💡 Manage your alerts:</strong>
                        <div class="feature-list">
                            <div class="feature-item">⏸️ Pause notifications temporarily</div>
                            <div class="feature-item">🕐 Adjust timing for your notification window</div>
                            <div class="feature-item">📍 Add your pincode for accurate stock checks</div>
                        </div>
                    </div>
                    <div class="webapp-note">
                        Go to our webapp to adjust all your settings
                    </div>
                    <a href="https://my-scraper-nine.vercel.app/" class="button">⚙️ Open tracker app</a>
                </div>
                <div class="footer">
                    🤖 Automated stock alert
                </div>
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
                    <th>In-Stock Streak</th>
                    <th>Emails</th>
                    <th>Pincode</th>
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

    def summarize_subscriptions(subscriptions: list):
        if not subscriptions:
            return "N/A", "No subscriptions for this product."

        user_emails = []
        failed_to_notify = []
        is_in_stock_attempted = False
        all_out_of_stock = True

        for sub_info in subscriptions:
            user_email = sub_info.get('user_email', 'N/A')
            email_display = user_email
            status = sub_info.get('status', 'N/A')

            if status == "Sent":
                if email_display not in user_emails:
                    user_emails.append(email_display)
                is_in_stock_attempted = True
                all_out_of_stock = False
            elif status == "Not Sent - Out of Stock":
                is_in_stock_attempted = True
            elif status in failed_notification_for_instock_statuses:
                is_in_stock_attempted = True
                all_out_of_stock = False
                if email_display not in failed_to_notify:
                    failed_to_notify.append(email_display)
            elif status not in ignorable_statuses:
                all_out_of_stock = False

        subscribed_emails_csv = ", ".join(user_emails) if user_emails else "N/A"

        if not is_in_stock_attempted and all_out_of_stock:
            product_status_overall = "Status inconclusive (e.g., all subscriptions skipped/delayed)"
        elif all_out_of_stock and is_in_stock_attempted:
            product_status_overall = "Out of stock"
        elif is_in_stock_attempted:
            if failed_to_notify:
                product_status_overall = f"Failed to notify: {', '.join(failed_to_notify)}"
            else:
                product_status_overall = "Notification sent"
        else:
            product_status_overall = "Status inconclusive (e.g., all subscriptions skipped/delayed)"

        return subscribed_emails_csv, product_status_overall

    for product_data in summary_data_list:
        product_name = product_data.get("product_name")
        if not product_name or product_name == "N/A":
            continue  # Skip entries with no meaningful product name

        product_url = product_data.get("product_url", "#")
        subscriptions = product_data.get("subscriptions", [])

        subscribed_emails_csv, _ = summarize_subscriptions(subscriptions)
        if subscribed_emails_csv == "N/A":
            continue  # Skip rows without any subscriber emails
        streak = product_data.get("consecutive_in_stock", 0)
        pin = product_data.get("pincode")
        if not pin and subscriptions:
            pin = subscriptions[0].get("pincode")

        html_output += f"""
    <tr>
        <td><a href="{product_url}">{product_name}</a></td>
        <td>{streak}</td>
        <td>{subscribed_emails_csv}</td>
        <td>{pin or 'N/A'}</td>
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

async def send_email_notification(
    subject: str,
    body: str,
    sender: str,
    recipients: list[str],
    host: str,
    port: int,
    username: str | None = None,
    password: str | None = None,
) -> None:
    """Sends an email notification asynchronously."""

    if not (host and sender and recipients and all(recipients)):
        print("⚠️ Essential email configuration or recipient list is missing or invalid.")
        return

    def _send() -> None:
        try:
            msg = MIMEText(body, "html")
            msg["Subject"] = subject
            msg["From"] = sender
            msg["To"] = sender  # Display sender in the "To" field

            with smtplib.SMTP(host, port) as server:
                if username and password:
                    server.starttls()
                    server.login(username, password)
                server.sendmail(sender, recipients, msg.as_string())
            print("Email notification sent successfully.")
        except smtplib.SMTPException as e:
            print(f"SMTP error occurred: {e}")
        except Exception as e:
            print(f"An error occurred while sending email: {e}")

    await asyncio.to_thread(_send)

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
