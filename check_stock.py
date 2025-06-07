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

    r = requests.post("https://www.fast2sms.com/dev/bulkV2",
                      data=payload, headers=headers, timeout=10)
    print("Fast2SMS:", r.status_code, r.text)

def main():
    with sync_playwright() as p:
        page = p.chromium.launch(headless=True).new_page()
        page.goto(URL, timeout=60000)

        # Enter pincode if modal pops
        try:
            page.fill('input[placeholder="Enter Your Pincode"]', PINCODE)
            page.keyboard.press("Enter")
            page.wait_for_timeout(3000)
        except Exception:
            pass

        html = page.content()
        in_stock = "Add to Cart" in html and "disabled" not in html

        if in_stock:
            text = urllib.parse.quote_plus(       # URL-encode just in case
                f"🚨 Amul Rose Lassi in stock! {URL}"
            )
            # Fast2SMS auto-decodes, so send plain (`payload` encodes)
            send_fast2sms(f"🚨 Amul Rose Lassi in stock! {URL}")

if __name__ == "__main__":
    main()
