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
) -> tuple[bool, str]:
    os.makedirs("artifacts", exist_ok=True)

    async def log(*msgs: object) -> None:
        if not log_prefix:
            return
        text = " ".join(str(m) for m in msgs)
        print(f"[{log_prefix}] {text}")

    await log("Navigating to", url)
    await page.goto(url, timeout=60000)
    await page.wait_for_load_state("networkidle")
    await asyncio.sleep(1)

    async def handle_pincode_modal():
        modal = await page.query_selector("div.modal-content.bg-transparent")
        if not modal or skip_pincode:
            return
        pincode_input = await page.query_selector("#search")
        if not pincode_input:
            return
        await log("Typing pincode", pincode)
        await pincode_input.fill(pincode)
        await asyncio.sleep(3)
        try:
            await page.wait_for_selector("#automatic", timeout=5000)
        except Exception:
            pass
        suggestion_selector = f"#automatic a.searchitem-name:has-text('{pincode}')"
        try:
            await page.wait_for_selector(suggestion_selector, timeout=5000)
            await page.click(suggestion_selector)
        except Exception:
            await page.keyboard.press("ArrowDown")
            await page.keyboard.press("Enter")
        await asyncio.sleep(3)
        await page.wait_for_load_state("networkidle")

    async def element_visibility(selector: str) -> tuple[bool, str]:
        elem = await page.query_selector(selector)
        visible = await elem.is_visible() if elem else False
        status = "visible" if visible else ("hidden" if elem else "missing")
        return visible, status

    await handle_pincode_modal()

    await log("Checking availability indicators…")
    sold_out_visible, _ = await element_visibility(
        "div.alert.alert-danger.mt-3"
    )

    disabled_visible, _ = await element_visibility(
        "a.btn.btn-primary.add-to-cart.disabled"
    )
    disabled_btn = disabled_visible

    notify_visible, _ = await element_visibility(
        "button.btn.btn-primary.product_enquiry"
    )

    enabled_visible, _ = await element_visibility(
        "a.btn.btn-primary.add-to-cart:not(.disabled)"
    )
    add_btn = enabled_visible

    product_name = "The Product"
    elem = await page.query_selector(
        "h1.product-name.mb-2.fw-bold.lh-sm.text-dark.h3.mb-4"
    )
    if elem:
        try:
            content = await elem.text_content()
            if content:
                product_name = content.strip() or product_name
        except Exception:
            pass

    in_stock = add_btn and not sold_out_visible and not disabled_btn

    current_reasons = []
    if add_btn:
        current_reasons.append("add_btn_visible")
    if sold_out_visible:
        current_reasons.append("sold_out_visible")
    if disabled_btn:
        current_reasons.append("disabled_btn_visible")
    await log(
        "Scraper decision",
        "in_stock" if in_stock else "out_of_stock",
        ";".join(current_reasons),
    )

    safe_url_part = re.sub(r"^https?://", "", url)
    safe_url_part = re.sub(r"[^a-zA-Z0-9_-]", "_", safe_url_part)
    safe_filename = f"artifacts/screenshot_{safe_url_part[:100]}.png"

    async def capture_screenshot():
        try:
            await page.screenshot(path=safe_filename)
            await log(f"Screenshot saved: {safe_filename}")
        except Exception as e:
            await log(f"Screenshot error: {e}")

    await capture_screenshot()

    return in_stock, product_name


async def check_product_availability(
    url: str,
    pincode: str,
    page: Page | None = None,
    skip_pincode: bool = False,
    log_prefix: str = "",
) -> tuple[bool, str]:
    """Checks product availability using Playwright."""
    if page is None:
        prefix = f"[{log_prefix}] " if log_prefix else ""
        print(f"{prefix}Launching browser with Playwright (from scraper.py)...")
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True, args=["--no-sandbox"])
            page = await browser.new_page()
            result = await _check_availability_on_page(
                page, url, pincode, skip_pincode, log_prefix
            )
            await browser.close()
            return result
    else:
        return await _check_availability_on_page(
            page, url, pincode, skip_pincode, log_prefix
        )
