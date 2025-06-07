import os, urllib.parse, requests
from playwright.sync_api import sync_playwright

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


def main() -> None:
    """Check the product page and send an SMS alert if in stock."""
    print("Opening browser...")
    with sync_playwright() as p:
        page = p.chromium.launch(headless=True).new_page()
        print(f"Navigating to {URL}")
        page.goto(URL, timeout=60000)

        reasons = []

        print("Checking pincode popup elements…")
        modal = page.query_selector(".modal-content")
        modal_status = "found" if modal else "missing"
        print("Modal:", modal_status)
        reasons.append(f"modal {modal_status}")

        close_btn = page.query_selector("button[aria-label='Close']")
        cb_status = "found" if close_btn else "missing"
        print("Close button:", cb_status)
        reasons.append(f"close {cb_status}")

        loc_btn = page.query_selector("text=Get my location")
        loc_status = "found" if loc_btn else "missing"
        print("Get my location:", loc_status)
        reasons.append(f"getloc {loc_status}")

        pin_input = page.query_selector("input[placeholder='Enter Your Pincode']")
        if pin_input:
            print("Pincode input found → typing", PINCODE)
            pin_input.fill(PINCODE)
            page.wait_for_timeout(1000)
            suggestion = page.query_selector(f"text={PINCODE}")
            if suggestion:
                print("Pincode suggestion found → clicking")
                suggestion.click()
            else:
                print("Pincode suggestion not found → pressing Enter")
                pin_input.press("Enter")
            page.wait_for_timeout(2000)
            print("Pincode entered")
            reasons.append("pincode entered")
        else:
            print("Pincode input not found")
            reasons.append("no pincode input")

        print("Checking availability indicators…")
        sold_out = page.query_selector("div.alert.alert-danger.mt-3")
        so_status = "found" if sold_out else "missing"
        print("Sold out indicator:", so_status)
        reasons.append(f"soldout {so_status}")

        disabled_btn = page.query_selector("a.btn.btn-primary.add-to-cart.disabled")
        db_status = "found" if disabled_btn else "missing"
        print("Add to Cart disabled:", db_status)
        if disabled_btn:
            reasons.append("button disabled")
        else:
            reasons.append("button not disabled")

        notify_me = page.query_selector("button.btn.btn-primary.product_enquiry")
        nm_status = "found" if notify_me else "missing"
        print("Notify Me button:", nm_status)
        reasons.append(f"notify {nm_status}")

        add_btn = page.query_selector("a.btn.btn-primary.add-to-cart:not(.disabled)")
        in_stock = bool(add_btn)
        ab_status = "found" if in_stock else "missing"
        print("Add to Cart enabled:", ab_status)
        reasons.append(f"addbtn {ab_status}")
        if in_stock:
            reasons.append("button enabled")
            print("Sending Fast2SMS notification…")
            # Fast2SMS auto-decodes, so send plain (`payload` encodes)
            send_fast2sms(f"🚨 Amul Rose Lassi in stock! {URL}")
        else:
            print("Item considered out of stock")

        print("Decision:", "sent alert" if in_stock else "no alert",
              "→", "; ".join(reasons) or "no indicators")


if __name__ == "__main__":
    main()
