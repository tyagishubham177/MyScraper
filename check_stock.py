import os, asyncio
import urllib.parse, requests
from playwright.async_api import async_playwright

# ——————————————————————————————————————————
# Config from GitHub Secrets / .env
URL       = ("https://shop.amul.com/en/product/"
             "amul-high-protein-rose-lassi-200-ml-or-pack-of-30")
PINCODE   = os.getenv("PINCODE",  "110001")
F2S_KEY   = os.getenv("F2S_API_KEY")             # Fast2SMS auth key (unused)
F2S_TO    = os.getenv("F2S_NUMBERS")             # Comma-separated numbers (e.g. 91xxxxxxxxxx)

SMTP_HOST = os.getenv("MAIL_HOST")                # SMTP server hostname
SMTP_PORT = int(os.getenv("MAIL_PORT", "587"))    # SMTP port
SMTP_USER = os.getenv("MAIL_USER")
SMTP_PASS = os.getenv("MAIL_PASS")
MAIL_FROM = os.getenv("MAIL_FROM", SMTP_USER)
MAIL_TO   = os.getenv("MAIL_TO")                  # Comma-separated recipients
# ——————————————————————————————————————————

def send_fast2sms(msg: str):
    """POST a Quick SMS via Fast2SMS API (currently unused)."""
    if not (F2S_KEY and F2S_TO):
        print("⚠️  Fast2SMS credentials missing")
        return
    payload = {
        "message": msg,
        "language": "english",
        "route": "q",  # quick SMS route (no DLT template)
        "numbers": F2S_TO,
    }
    headers = {
        "authorization": F2S_KEY,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    try:
        r = requests.post(
            "https://www.fast2sms.com/dev/bulkV2",
            data=payload,
            headers=headers,
            timeout=10,
        )
        r.raise_for_status()
    except requests.RequestException as e:
        print("Fast2SMS error:", e)
        return
    print("Fast2SMS:", r.status_code, r.text)


def send_email(subject: str, body: str) -> None:
    """Send a notification email via SMTP."""
    if not (SMTP_HOST and SMTP_USER and SMTP_PASS and MAIL_TO):
        print("⚠️  Email credentials missing")
        return
    from email.message import EmailMessage
    import smtplib

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = MAIL_FROM
    msg["To"] = MAIL_TO.split(",")
    msg.set_content(body)

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
    except Exception as e:
        print("Email error:", e)
        return
    print("Email sent to", MAIL_TO)


async def main():
    """Check the product page and send an email alert if in stock (using Playwright)."""
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
            await log("Sending email notification…")
            send_email(
                "Amul Rose Lassi in stock",
                "🚨 Amul Rose Lassi pack is now available"
            )
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
