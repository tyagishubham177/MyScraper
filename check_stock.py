
import os, requests, urllib.parse
from playwright.sync_api import sync_playwright

URL      = ("https://shop.amul.com/en/product/"
            "amul-high-protein-rose-lassi-200-ml-or-pack-of-30")
PINCODE  = os.getenv("PINCODE", "110001")   # override via secret
PHONE    = os.getenv("WA_PHONE")            # +91xxxxxxxxxx
APIKEY   = os.getenv("WA_KEY")
MSG      = urllib.parse.quote_plus(
          "🚨 Amul Rose Lassi in stock! " + URL)

def notify_whatsapp():
    if PHONE and APIKEY:
        requests.get(f"https://api.callmebot.com/whatsapp.php?"
                     f"phone={PHONE}&text={MSG}&apikey={APIKEY}", timeout=10)

def main():
    with sync_playwright() as p:
        page = p.chromium.launch(headless=True).new_page()
        page.goto(URL, timeout=60000)

        # pincode modal
        try:
            page.fill('input[placeholder="Enter Your Pincode"]', PINCODE)
            page.keyboard.press("Enter")
            page.wait_for_timeout(3000)
        except: pass

        html = page.content()
        if "Add to Cart" in html and "disabled" not in html:
            notify_whatsapp()
            notify_sms()
            notify_email()

if __name__ == "__main__":
    main()
