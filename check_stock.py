import os, urllib.parse, requests, asyncio
from bs4 import BeautifulSoup
from pyppeteer import launch

# ——————————————————————————————————————————
# Config from GitHub Secrets / .env
URL       = ("https://shop.amul.com/en/product/"
             "amul-high-protein-rose-lassi-200-ml-or-pack-of-30")
PINCODE   = os.getenv("PINCODE",  "110001")
F2S_KEY   = os.getenv("F2S_API_KEY")            # Fast2SMS auth key
F2S_TO    = os.getenv("F2S_NUMBERS")            # 91xxxxxxxxxx,91yyyyyyyyy  (comma-sep)
# ——————————————————————————————————————————

def send_fast2sms(msg: str):
    """POST → Fast2SMS Quick-SMS route (no DLT)."""
    if not (F2S_KEY and F2S_TO):
        print("⚠️  Fast2SMS creds missing")
        return

    payload = {
        "message": msg,
        "language": "english",
        "route": "q",            # quick-sms route
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


async def main() -> None:
    """Check the product page and send an SMS alert if in stock."""
    print("Opening browser...")
    browser = await launch(headless=True, args=["--no-sandbox"])
    page = await browser.newPage()

    # create artifacts dir and helper logger that also takes screenshots
    os.makedirs("artifacts", exist_ok=True)
    step = 0

    async def log(*msgs: object) -> None:
        nonlocal step
        text = " ".join(str(m) for m in msgs)
        print(text)
        step += 1
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in text)[:30]
        await page.screenshot({'path': f"artifacts/{step:02d}_{safe}.png"})

    await log(f"Navigating to {URL}")
    await page.goto(URL, timeout=60000)

    reasons = []

    # Fetch page content for BeautifulSoup parsing
    html = await page.content()
    soup = BeautifulSoup(html, "html.parser")

    await log("Checking availability indicators…")
    sold_out = soup.select_one("div.alert.alert-danger.mt-3") is not None
    so_status = "found" if sold_out else "missing"
    await log("Sold out indicator:", so_status)
    reasons.append(f"soldout {so_status}")

    disabled_btn = soup.select_one("a.btn.btn-primary.add-to-cart.disabled") is not None
    db_status = "found" if disabled_btn else "missing"
    await log("Add to Cart disabled:", db_status)
    reasons.append("button disabled" if disabled_btn else "button not disabled")

    notify_me = soup.select_one("button.btn.btn-primary.product_enquiry") is not None
    nm_status = "found" if notify_me else "missing"
    await log("Notify Me button:", nm_status)
    reasons.append(f"notify {nm_status}")

    add_btn = soup.select_one("a.btn.btn-primary.add-to-cart:not(.disabled)") is not None
    ab_status = "found" if add_btn else "missing"
    await log("Add to Cart enabled:", ab_status)
    reasons.append(f"addbtn {ab_status}")

    in_stock = add_btn and not sold_out and not disabled_btn
    if in_stock:
        reasons.append("button enabled")
        await log("Sending Fast2SMS notification…")
        # Fast2SMS auto-decodes, so send plain (`payload` encodes)
        send_fast2sms(f"🚨 Amul Rose Lassi in stock! {URL}")
    else:
        await log("Item considered out of stock")

    await log("Decision:", "sent alert" if in_stock else "no alert",
             "→", "; ".join(reasons) or "no indicators")

    await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
