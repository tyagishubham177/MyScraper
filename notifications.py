import smtplib
from email.mime.text import MIMEText
import requests # For the commented-out send_fast2sms
import os # For F2S_KEY/TO if they were used directly (they are in the commented out function)

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
        </style>
    </head>
    <body>
        <div class="container">
        <h1>🚀 Stock Alert! 🚀</h1>
        <p>Good news! The product you're watching is back in stock:</p>
        <p><strong>{product_name.strip()}</strong></p>
        <p>Don't miss out! Check it out here:</p>
        <a href="{url}" class="button">View Product Now</a>
        <p style="margin-top: 20px; font-size: 0.9em; color: #777;">
            This is an automated notification.
        </p>
        </div>
    </body>
    </html>
    """
    return html_body

def format_short_message(product_name: str) -> str:
    return f"ALERT: {product_name.strip()} is back in stock!"

def send_email_notification(subject: str, body: str, sender: str, recipients: list[str], host: str, port: int, username: str = None, password: str = None):
    """Sends an email notification."""
    if not (host and sender and recipients and all(recipients)): # Also check if recipients list is not empty or contains empty strings
        print("⚠️ Essential email configuration (EMAIL_HOST, EMAIL_SENDER, EMAIL_RECIPIENTS) is missing or invalid.")
        return
    try:
        msg = MIMEText(body, 'html')
        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = ", ".join(recipients)

        with smtplib.SMTP(host, port) as server:
            if username and password:
                server.starttls()  # Upgrade connection to secure
                server.login(username, password)
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
