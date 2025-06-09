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
    return f"🚨 {product_name.strip()} is IN STOCK! Check it out: {url}"

def format_short_message(product_name: str) -> str:
    return f"ALERT: {product_name.strip()} is back in stock!"

def send_email_notification(subject: str, body: str, sender: str, recipients: list[str], host: str, port: int, username: str = None, password: str = None):
    """Sends an email notification."""
    if not (host and sender and recipients and all(recipients)): # Also check if recipients list is not empty or contains empty strings
        print("⚠️ Essential email configuration (EMAIL_HOST, EMAIL_SENDER, EMAIL_RECIPIENTS) is missing or invalid.")
        return
    try:
        msg = MIMEText(body)
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
