import asyncio
import os
import re
from playwright.async_api import async_playwright, Page


async def _check_availability_on_page(
    page: Page,
    url: str,
    pincode: str,
    skip_pincode: bool,
    log_prefix: str = "",
    verbose: bool = True,
) -> tuple[bool, str]:
    os.makedirs("artifacts", exist_ok=True)

    async def log(*msgs: object) -> None:
        if not verbose:
            return
        text = " ".join(str(m) for m in msgs)
        if log_prefix:
            text = f"[{log_prefix}] {text}"
        print(text)

    await log("Navigating to", url)
    await page.goto(url, timeout=60000)
    await page.wait_for_load_state("networkidle")
    await asyncio.sleep(1)
    await log("Page loaded")

    async def handle_pincode_modal():
        modal = await page.query_selector("div.modal-content.bg-transparent")
        if not modal:
            await log("Pincode modal not found")
            return
        if skip_pincode:
            await log("Pincode modal shown but skipping entry")
            return
        pincode_input = await page.query_selector("#search")
        if not pincode_input:
            await log("Pincode input not found in modal")
            return
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
        await page.wait_for_load_state("networkidle")
        await log("Pincode selected/attempted")

    async def element_visibility(selector: str) -> tuple[bool, str]:
        elem = await page.query_selector(selector)
        visible = await elem.is_visible() if elem else False
        status = "visible" if visible else ("hidden" if elem else "missing")
        return visible, status

    await handle_pincode_modal()

    await log("Checking availability indicators…")
    sold_out_visible, so_status = await element_visibility(
        "div.alert.alert-danger.mt-3"
    )
    await log("Sold Out indicator:", so_status)

    disabled_visible, db_status = await element_visibility(
        "a.btn.btn-primary.add-to-cart.disabled"
    )
    await log("Add to Cart disabled:", db_status)
    disabled_btn = disabled_visible

    notify_visible, nm_status = await element_visibility(
        "button.btn.btn-primary.product_enquiry"
    )
    await log("Notify Me button:", nm_status)

    enabled_visible, ab_status = await element_visibility(
        "a.btn.btn-primary.add-to-cart:not(.disabled)"
    )
    await log("Add to Cart enabled:", ab_status)
    add_btn = enabled_visible

    product_name = "The Product"
    elem = await page.query_selector(
        "h1.product-name.mb-2.fw-bold.lh-sm.text-dark.h3.mb-4"
    )
    if elem:
        try:
            content = await elem.text_content()
            if content:  # Ensure content is not None before stripping
                product_name = content.strip() or product_name
            else:  # content is None or empty string
                product_name = product_name  # Keep default
            await log("Extracted product name:", product_name)
        except Exception as e:
            await log(f"Error fetching product name text: {e}. Using default.")
            # product_name remains "The Product"
    else:
        await log("Product name element not found. Using default.")

    in_stock = add_btn and not sold_out_visible and not disabled_btn

    current_reasons = []
    if add_btn:
        current_reasons.append("add_btn_visible")
    if sold_out_visible:
        current_reasons.append("sold_out_visible")
    if disabled_btn:
        current_reasons.append("disabled_btn_visible")
    await log(
        "Scraper decision:",
        "in_stock" if in_stock else "out_of_stock",
        "based on:",
        "; ".join(current_reasons),
    )

    safe_url_part = re.sub(r"^https?://", "", url)
    safe_url_part = re.sub(r"[^a-zA-Z0-9_-]", "_", safe_url_part)
    safe_filename = f"artifacts/screenshot_{safe_url_part[:100]}.png"

    async def capture_screenshot():
        try:
            await log(f"Attempting to take screenshot: {safe_filename}")
            await page.screenshot(path=safe_filename)
            await log(f"Screenshot saved: {safe_filename}")
        except Exception as e:
            await log(f"Error taking single screenshot for {url}: {e}")

    await capture_screenshot()

    return in_stock, product_name


async def check_product_availability(
    url: str,
    pincode: str,
    page: Page | None = None,
    skip_pincode: bool = False,
    log_prefix: str = "",
    *,
    verbose: bool = True,
) -> tuple[bool, str]:
    """Checks product availability using Playwright."""
    if page is None:
        prefix = f"[{log_prefix}] " if log_prefix else ""
        print(f"{prefix}Launching browser with Playwright (from scraper.py)...")
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True, args=["--no-sandbox"])
            page = await browser.new_page()
            result = await _check_availability_on_page(
                page, url, pincode, skip_pincode, log_prefix, verbose
            )
            await browser.close()
            return result
    else:
        return await _check_availability_on_page(
            page, url, pincode, skip_pincode, log_prefix, verbose
        )
