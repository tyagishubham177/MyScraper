import asyncio
import os
import re
from playwright.async_api import async_playwright, Page

async def _check_availability_on_page(page: Page, url: str, pincode: str, skip_pincode: bool) -> tuple[bool, str]:
    os.makedirs("artifacts", exist_ok=True)

    async def log(*msgs: object) -> None:
        text = " ".join(str(m) for m in msgs)
        print(text)

    print(f"Navigating to {url}")
    await page.goto(url, timeout=60000)
    await page.wait_for_load_state('networkidle')
    await asyncio.sleep(1)
    await log("Page loaded")

    modal = await page.query_selector("div.modal-content.bg-transparent")
    if modal:
        if skip_pincode:
            await log("Pincode modal shown but skipping entry")
        else:
            pincode_input_selector = "#search"
            pincode_input = await page.query_selector(pincode_input_selector)
            if pincode_input:
                await log("Pincode input found → typing", pincode)
                await pincode_input.fill(pincode)
                await asyncio.sleep(3)
                await log("Pincode typed")
                try:
                    await page.wait_for_selector("#automatic", timeout=5000)
                    await log("Dropdown shown")
                except Exception:
                    await log("Dropdown not detected")

                suggestion_selector = f"#automatic a.searchitem-name:has-text('{pincode}')"
                try:
                    await page.wait_for_selector(suggestion_selector, timeout=5000)
                    await page.click(suggestion_selector)
                except Exception:
                    await log(f"Could not click suggestion for {pincode}, trying keyboard.")
                    await page.keyboard.press("ArrowDown")
                    await page.keyboard.press("Enter")
                await asyncio.sleep(3)
                await page.wait_for_load_state('networkidle')
                await log("Pincode selected/attempted")
            else:
                await log("Pincode input not found in modal")
    else:
        await log("Pincode modal not found")

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

    product_name_element = await page.query_selector("h1.product-name.mb-2.fw-bold.lh-sm.text-dark.h3.mb-4")
    product_name = "The Product"
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

    current_reasons = []
    if add_btn:
        current_reasons.append("add_btn_visible")
    if sold_out_visible:
        current_reasons.append("sold_out_visible")
    if disabled_btn:
        current_reasons.append("disabled_btn_visible")
    await log("Scraper decision:", "in_stock" if in_stock else "out_of_stock", "based on:", "; ".join(current_reasons))

    safe_url_part = re.sub(r'^https?://', '', url)
    safe_url_part = re.sub(r'[^a-zA-Z0-9_-]', '_', safe_url_part)
    safe_filename = f"artifacts/screenshot_{safe_url_part[:100]}.png"

    try:
        print(f"Attempting to take screenshot: {safe_filename}")
        await page.screenshot(path=safe_filename)
        print(f"Screenshot saved: {safe_filename}")
    except Exception as e:
        print(f"Error taking single screenshot for {url}: {e}")

    return in_stock, product_name


async def check_product_availability(url: str, pincode: str, page: Page | None = None, skip_pincode: bool = False) -> tuple[bool, str]:
    """Checks product availability using Playwright."""
    if page is None:
        print("Launching browser with Playwright (from scraper.py)...")
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True, args=["--no-sandbox"])
            page = await browser.new_page()
            result = await _check_availability_on_page(page, url, pincode, skip_pincode)
            await browser.close()
            return result
    else:
        return await _check_availability_on_page(page, url, pincode, skip_pincode)
