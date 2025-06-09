import asyncio
import os
from playwright.async_api import async_playwright

async def check_product_availability(url: str, pincode: str) -> tuple[bool, str]:
    """Checks product availability using Playwright."""
    print("Launching browser with Playwright (from scraper.py)...")
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True, args=["--no-sandbox"])
        # await asyncio.sleep(5) # Removed sleep, let's see if it's needed
        page = await browser.new_page()
        # await asyncio.sleep(5) # Removed sleep

        os.makedirs("artifacts", exist_ok=True)
        step = 0

        async def log(*msgs: object) -> None:
            nonlocal step # Ensure we modify the outer step
            text = " ".join(str(m) for m in msgs)
            print(text) # Keep console logging
            step += 1
            safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in text)[:30]
            try:
                await page.screenshot(path=f"artifacts/{step:02d}_{safe}.png")
            except Exception as e:
                print(f"Error taking screenshot: {e}")
            # await asyncio.sleep(5) # Removed sleep

        print(f"Navigating to {url}") # Use the url argument
        await page.goto(url, timeout=60000)
        await asyncio.sleep(3) # Added sleep after navigation
        await log("Page loaded")

        modal = await page.query_selector("div.modal-content.bg-transparent")
        if modal:
            pincode_input_selector = "#search" # Use the pincode argument
            pincode_input = await page.query_selector(pincode_input_selector)
            if pincode_input:
                await log("Pincode input found → typing", pincode)
                await pincode_input.fill(pincode)
                await asyncio.sleep(3) # Added sleep after filling pincode
                await log("Pincode typed")
                try:
                    await page.wait_for_selector("#automatic", timeout=5000)
                    await log("Dropdown shown")
                except Exception:
                    await log("Dropdown not detected")

                suggestion_selector = f"#automatic a.searchitem-name:has-text(\"{pincode}\")"
                try:
                    await page.wait_for_selector(suggestion_selector, timeout=5000)
                    await page.click(suggestion_selector)
                except Exception:
                    # Fallback if exact match click fails (e.g., if it's already selected or UI behaves differently)
                    await log(f"Could not click suggestion for {pincode}, trying keyboard.")
                    await page.keyboard.press("ArrowDown") # Try to select first if not auto-selected
                    await page.keyboard.press("Enter")
                await asyncio.sleep(3) # Added sleep after pincode selection/attempt
                await log("Pincode selected/attempted")
                # reasons = ["pincode entered"] # Not used in this function's return
            else:
                await log("Pincode input not found in modal")
                # reasons = ["modal present, no input"]
        else:
            await log("Pincode modal not found")
            # reasons = ["no pincode input"]

        await log("Checking availability indicators…")
        sold_out_elem = await page.query_selector("div.alert.alert-danger.mt-3")
        sold_out_visible = False
        if sold_out_elem:
            sold_out_visible = await sold_out_elem.is_visible()
        so_status = ("visible" if sold_out_visible else ("hidden" if sold_out_elem else "missing"))
        await log("Sold Out indicator:", so_status)

        disabled_elem = await page.query_selector("a.btn.btn-primary.add-to-cart.disabled")
        disabled_visible = False
        if disabled_elem:
            disabled_visible = await disabled_elem.is_visible()
        disabled_btn = disabled_visible
        db_status = ("visible" if disabled_visible else ("hidden" if disabled_elem else "missing"))
        await log("Add to Cart disabled:", db_status)

        # The "Notify Me" button itself doesn't determine stock, but useful for logging
        notify_elem = await page.query_selector("button.btn.btn-primary.product_enquiry")
        notify_visible = False
        if notify_elem:
            notify_visible = await notify_elem.is_visible()
        nm_status = ("visible" if notify_visible else ("hidden" if notify_elem else "missing"))
        await log("Notify Me button:", nm_status)

        enabled_elem = await page.query_selector("a.btn.btn-primary.add-to-cart:not(.disabled)")
        enabled_visible = False
        if enabled_elem:
            enabled_visible = await enabled_elem.is_visible()
        add_btn = enabled_visible
        ab_status = ("visible" if enabled_visible else ("hidden" if enabled_elem else "missing"))
        await log("Add to Cart enabled:", ab_status)

        # Extract product name
        product_name_element = await page.query_selector("h1.product-name.mb-2.fw-bold.lh-sm.text-dark.h3.mb-4")
        product_name = "The Product" # Default value
        if product_name_element:
            content = await product_name_element.text_content()
            if content:
                product_name = content.strip()
                await log("Extracted product name:", product_name)
            else:
                await log("Product name element found but no text_content. Using default.")
        else:
            await log("Product name element (h1.product-name.mb-2.fw-bold.lh-sm.text-dark.h3.mb-4) not found. Using default.")

        in_stock = add_btn and not sold_out_visible and not disabled_btn

        # Log final decision reason for clarity in scraper logs
        current_reasons = []
        if add_btn: current_reasons.append("add_btn_visible")
        if sold_out_visible: current_reasons.append("sold_out_visible")
        if disabled_btn: current_reasons.append("disabled_btn_visible")
        await log("Scraper decision:", "in_stock" if in_stock else "out_of_stock", "based on:", "; ".join(current_reasons))

        await browser.close()
        # await asyncio.sleep(5) # Removed sleep

        return in_stock, product_name
