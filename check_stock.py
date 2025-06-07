import os, asyncio
import urllib.parse, requests
from playwright.async_api import async_playwright

# ——————————————————————————————————————————
# Config from GitHub Secrets / .env
URL       = ("https://shop.amul.com/en/product/"
             "amul-high-protein-rose-lassi-200-ml-or-pack-of-30")
PINCODE   = os.getenv("PINCODE",  "110001")
F2S_KEY   = os.getenv("F2S_API_KEY")             # Fast2SMS auth key
F2S_TO    = os.getenv("F2S_NUMBERS")             # Comma-separated numbers (e.g. 91xxxxxxxxxx)
# ——————————————————————————————————————————

def send_fast2sms(msg: str):
    """POST a Quick SMS via Fast2SMS API."""
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
                suggestion_list = await page.query_selector("#automatic")
                if suggestion_list:
                    suggestion_item = await suggestion_list.query_selector(f"text=247001")
                    if suggestion_item:
                        await suggestion_item.click()
                    else:
                        await page.keyboard.press("ArrowDown")
                        await page.keyboard.press("Enter")
                else:
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
        so_status = "visible" if sold_out_visible else ("hidden" if sold_out_elem else "missing")
        await log("Sold Out indicator:", so_status)
        reasons.append(f"soldout {so_status}")

        disabled_elem = await page.query_selector("a.btn.btn-primary.add-to-cart.disabled")
        disabled_btn = bool(disabled_elem and await disabled_elem.is_visible())
        db_status = "found" if disabled_btn else "missing"
        await log("Add to Cart disabled:", db_status)
        reasons.append("button disabled" if disabled_btn else "button not disabled")

        notify_elem = await page.query_selector("button.btn.btn-primary.product_enquiry")
        notify_me = bool(notify_elem and await notify_elem.is_visible())
        nm_status = "found" if notify_me else "missing"
        await log("Notify Me button:", nm_status)
        reasons.append(f"notify {nm_status}")

        enabled_elem = await page.query_selector("a.btn.btn-primary.add-to-cart:not(.disabled)")
        add_btn = bool(enabled_elem and await enabled_elem.is_visible())
        ab_status = "found" if add_btn else "missing"
        await log("Add to Cart enabled:", ab_status)
        reasons.append(f"addbtn {ab_status}")

        in_stock = add_btn and not sold_out_visible and not disabled_btn
        if in_stock:
            reasons.append("button enabled")
            await log("Sending Fast2SMS notification…")
            send_fast2sms(f"🚨 Amul Rose Lassi is IN STOCK! {URL}")
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
