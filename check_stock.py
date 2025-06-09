import os, asyncio
import urllib.parse, requests
from playwright.async_api import async_playwright
import smtplib
from email.mime.text import MIMEText

# ——————————————————————————————————————————
# Config from GitHub Secrets / .env
URL       = ("https://shop.amul.com/en/product/"
             "amul-adrak-chai-instant-tea-mix-14-g-or-pack-of-10-sachets")
PINCODE   = os.getenv("PINCODE",  "110001")
# F2S_KEY   = os.getenv("F2S_API_KEY")             # Fast2SMS auth key
# F2S_TO    = os.getenv("F2S_NUMBERS")             # Comma-separated numbers (e.g. 91xxxxxxxxxx)
EMAIL_HOST = os.getenv("EMAIL_HOST")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", 587))
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD")
EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_RECIPIENTS = os.getenv("EMAIL_RECIPIENTS")
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


async def main():
    """Check the product page and send an SMS alert if in stock (using Playwright)."""
    print("Launching browser with Playwright...")
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True, args=["--no-sandbox"])
        await asyncio.sleep(5)
        page = await browser.new_page()
        await asyncio.sleep(5)

        os.makedirs("artifacts", exist_ok=True)
        step = 0

        async def log(*msgs: object) -> None:
            nonlocal step
            text = " ".join(str(m) for m in msgs)
            print(text)
            step += 1
            safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in text)[:30]
            await page.screenshot(path=f"artifacts/{step:02d}_{safe}.png")
            await asyncio.sleep(5)

        print(f"Navigating to {URL}")
        await page.goto(URL, timeout=60000)
        await asyncio.sleep(5)
        await log("Page loaded")

        # Extract product name
        product_name_element = await page.query_selector("h1.product-name")
        if product_name_element:
            product_name = await product_name_element.text_content()
            product_name = product_name.strip()
            await log("Extracted product name:", product_name)
        else:
            product_name = "The Product" # Fallback
            await log("Product name element (h1.product-name) not found. Using default.")

        modal = await page.query_selector("div.modal-content.bg-transparent")
        if modal:
            pincode_input = await page.query_selector("#search")
            if pincode_input:
                await log("Pincode input found → typing", PINCODE)
                await pincode_input.fill(PINCODE)
                await asyncio.sleep(5)
                await log("Pincode typed")
                try:
                    await page.wait_for_selector("#automatic", timeout=5000)
                    await log("Dropdown shown")
                except Exception:
                    await log("Dropdown not detected")
                suggestion_selector = f"#automatic a.searchitem-name:has-text(\"{PINCODE}\")"
                try:
                    await page.wait_for_selector(suggestion_selector, timeout=5000)
                    await page.click(suggestion_selector)
                except Exception:
                    await page.keyboard.press("ArrowDown")
                    await page.keyboard.press("Enter")
                await asyncio.sleep(5)
                await log("Pincode selected")
                reasons = ["pincode entered"]
            else:
                await log("Pincode input not found in modal")
                reasons = ["modal present, no input"]
        else:
            await log("Pincode modal not found")
            reasons = ["no pincode input"]

        await log("Checking availability indicators…")
        sold_out_elem = await page.query_selector("div.alert.alert-danger.mt-3")
        sold_out_visible = False
        if sold_out_elem:
            sold_out_visible = await sold_out_elem.is_visible()
        so_status = (
            "visible" if sold_out_visible else
            ("hidden" if sold_out_elem else "missing")
        )
        await log("Sold Out indicator:", so_status)
        reasons.append(f"soldout {so_status}")

        disabled_elem = await page.query_selector("a.btn.btn-primary.add-to-cart.disabled")
        disabled_visible = False
        if disabled_elem:
            disabled_visible = await disabled_elem.is_visible()
        disabled_btn = disabled_visible
        db_status = (
            "visible" if disabled_visible else
            ("hidden" if disabled_elem else "missing")
        )
        await log("Add to Cart disabled:", db_status)
        reasons.append(f"disabled {db_status}")

        notify_elem = await page.query_selector("button.btn.btn-primary.product_enquiry")
        notify_visible = False
        if notify_elem:
            notify_visible = await notify_elem.is_visible()
        nm_status = (
            "visible" if notify_visible else
            ("hidden" if notify_elem else "missing")
        )
        await log("Notify Me button:", nm_status)
        reasons.append(f"notify {nm_status}")

        enabled_elem = await page.query_selector("a.btn.btn-primary.add-to-cart:not(.disabled)")
        enabled_visible = False
        if enabled_elem:
            enabled_visible = await enabled_elem.is_visible()
        add_btn = enabled_visible
        ab_status = (
            "visible" if enabled_visible else
            ("hidden" if enabled_elem else "missing")
        )
        await log("Add to Cart enabled:", ab_status)
        reasons.append(f"addbtn {ab_status}")

        in_stock = add_btn and not sold_out_visible and not disabled_btn
        if in_stock:
            reasons.append("button enabled")
            await log("Sending Fast2SMS notification…")
            # send_fast2sms(format_short_message(product_name))
            if EMAIL_HOST and EMAIL_SENDER and EMAIL_RECIPIENTS and all(EMAIL_RECIPIENTS.split(',')):
                email_subject = f"{product_name.strip()} In Stock Alert!"
                email_body = format_long_message(product_name, URL)
                send_email_notification(
                    subject=email_subject,
                    body=email_body,
                    sender=EMAIL_SENDER,
                    recipients=EMAIL_RECIPIENTS.split(','),
                    host=EMAIL_HOST,
                    port=EMAIL_PORT,
                    username=EMAIL_HOST_USER,
                    password=EMAIL_HOST_PASSWORD
                )
            else:
                print("⚠️ Email configuration missing or invalid (EMAIL_HOST, EMAIL_SENDER, EMAIL_RECIPIENTS), cannot send email.")
            await asyncio.sleep(5)
        else:
            await log("Item considered out of stock")

        await log(
            "Decision:",
            "sent alert" if in_stock else "no alert",
            "→", "; ".join(reasons) or "no indicators"
        )

        await browser.close()
        await asyncio.sleep(5)

if __name__ == "__main__":
    asyncio.run(main())
