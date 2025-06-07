import os
import time
from datetime import datetime
import requests
from playwright.sync_api import sync_playwright

# ────────────────────────────────────────────────────────────────
# Config from GitHub Secrets / .env
URL = (
    "https://shop.amul.com/en/product/"
    "amul-high-protein-rose-lassi-200-ml-or-pack-of-30"
)
PINCODE = os.getenv("PINCODE", "110001")
F2S_KEY = os.getenv("F2S_API_KEY")  # Fast2SMS auth key
F2S_TO = os.getenv("F2S_NUMBERS")  # 91xxxxxxxxxx,91yyyyyyyyy (comma-sep)
# ────────────────────────────────────────────────────────────────


def send_fast2sms(msg: str) -> None:
    """POST → Fast2SMS Quick-SMS route (no DLT)."""
    if not (F2S_KEY and F2S_TO):
        print("⚠️  Fast2SMS creds missing")
        return

    payload = {
        "message": msg,
        "language": "english",
        "route": "q",  # quick-sms route
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


def check_product_stock() -> None:
    """Check the product page and send an SMS alert if in stock."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs("artifacts", exist_ok=True)
    screenshot_file = f"artifacts/amul_stock_{PINCODE}_{timestamp}.png"
    html_file = f"artifacts/amul_stock_{PINCODE}_{timestamp}.html"

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1280, "height": 800})
        page = context.new_page()

        print(f"Navigating to: {URL}")
        page.goto(URL, timeout=60000)

        # Step 1: Wait for the pincode input
        page.wait_for_selector("input[placeholder='Enter Your Pincode']", timeout=30000)

        # Step 2: Type the pincode
        page.fill("input[placeholder='Enter Your Pincode']", PINCODE)

        # Step 3: Wait for suggestion & select
        try:
            page.wait_for_selector(".ui-menu-item", timeout=10000)
            page.keyboard.press("ArrowDown")
            page.keyboard.press("Enter")
            print(f"Selected pincode: {PINCODE}")
        except Exception:
            print("⚠️ Suggestions not found")

        # Step 4: Wait for modal to (hopefully) close
        try:
            page.wait_for_selector("#locationWidgetModal", state="hidden", timeout=5000)
            print("🎉 Modal closed automatically!")
        except Exception:
            print("⚠️ Modal might still be open—check if you need an extra step.")

        # Allow page to settle
        time.sleep(3)

        # Check availability using page selectors
        sold_out = page.query_selector("div.alert.alert-danger.mt-3") is not None
        disabled_btn = page.query_selector("a.btn.btn-primary.add-to-cart.disabled") is not None
        notify_me = page.query_selector("button.btn.btn-primary.product_enquiry") is not None
        add_btn = page.query_selector("a.btn.btn-primary.add-to-cart:not(.disabled)") is not None

        in_stock = add_btn and not sold_out and not disabled_btn

        reasons = [
            "soldout found" if sold_out else "soldout missing",
            "button disabled" if disabled_btn else "button not disabled",
            "notify found" if notify_me else "notify missing",
            "addbtn found" if add_btn else "addbtn missing",
        ]

        if in_stock:
            reasons.append("button enabled")
            print("Sending Fast2SMS notification…")
            send_fast2sms(f"🚨 Amul Rose Lassi in stock! {URL}")
        else:
            print("Item considered out of stock")

        print("Decision:", "sent alert" if in_stock else "no alert", "→", "; ".join(reasons))

        # Save artifacts
        page.screenshot(path=screenshot_file, full_page=True)
        with open(html_file, "w", encoding="utf-8") as f:
            f.write(page.content())

        print(f"Saved screenshot => {screenshot_file}")
        print(f"Saved HTML => {html_file}")
        browser.close()


if __name__ == "__main__":
    check_product_stock()
