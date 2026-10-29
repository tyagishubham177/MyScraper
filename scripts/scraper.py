import asyncio
import os
import re
from uuid import uuid4
from scripts.validation import product_url, pincode as validate_pincode, CheckError
from playwright.async_api import async_playwright, Page


async def _check_availability_on_page(
    page: Page,
    url: str,
    pincode: str,
    skip_pincode: bool,
    log_prefix: str = "",
) -> tuple[bool, str]:
    url = product_url(url)
    validate_pincode(pincode)
    os.makedirs("artifacts", exist_ok=True)

    async def log(*msgs: object) -> None:
        text = " ".join(str(m) for m in msgs)
        if log_prefix:
            text = f"[{log_prefix}] {text}"
        print(text)

    await log("Navigating to", url)
    response = await page.goto(url, timeout=30000)
    if response is not None and response.status >= 400:
        raise CheckError(f"HTTP {response.status}")
    if getattr(page, "url", url) and product_url(page.url) != url:
        raise CheckError("Unexpected product redirect")
    await page.wait_for_load_state("networkidle")
    await page.wait_for_timeout(500)
    await log("Page loaded")

    async def handle_pincode_modal():
        modal = await page.query_selector("div.modal-content.bg-transparent")
        if not modal or not await modal.is_visible():
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
        await page.wait_for_timeout(500)
        # Selecting a region refreshes the storefront asynchronously. Network
        # idle alone can occur before that refresh has even started.
        try:
            await page.wait_for_selector(
                "div.modal-content.bg-transparent", state="hidden", timeout=15000
            )
        except Exception as exc:
            raise CheckError("Pincode selection did not close the location modal") from exc
        await page.wait_for_load_state("networkidle")
        await log("Pincode selected/attempted")

    async def confirm_pincode(expected: str) -> bool:
        selector = (
            "div.d-flex.flex-column.loc_area.overflow-hidden.text-turncate span"
        )
        try:
            elem = await page.wait_for_selector(selector, timeout=5000)
        except Exception:
            await log("Pincode confirmation element not found")
            return False
        try:
            text = await elem.text_content() or ""
        except Exception as e:
            await log(f"Error reading pincode text: {e}")
            return False
        match = re.search(r"\b(\d{6})\b", text)
        extracted = match.group(1) if match else None
        await log("Displayed pincode:", text)
        if not extracted:
            await log("No pincode found in text")
            return False
        if extracted != expected:
            await log("Pincode mismatch:", extracted, "!=", expected)
            return False
        return True

    async def element_visibility(selector: str) -> tuple[bool, str]:
        elem = await page.query_selector(selector)
        visible = await elem.is_visible() if elem else False
        status = "visible" if visible else ("hidden" if elem else "missing")
        return visible, status

    await handle_pincode_modal()

    # Shared cookies do not prove the delivery location on this page.
    pincode_confirmed = await confirm_pincode(pincode)
    if not pincode_confirmed:
        await log("Pincode verification failed")

    # The location header renders before the product details. Wait for both
    # identity and an explicit stock control rather than reading an empty DOM.
    try:
        await page.wait_for_selector(
            "h1.product-name.mb-2.fw-bold.lh-sm.text-dark.h3.mb-4", timeout=15000
        )
        await page.wait_for_selector(
            "div.alert.alert-danger.mt-3:visible, a.btn.btn-primary.add-to-cart:visible, "
            "button.btn.btn-primary.product_enquiry:visible", timeout=10000
        )
    except Exception:
        await log("Product details did not become ready; validating available evidence")

    # StoreHippo can show an error-page placeholder until the location-specific
    # product has rendered. It is an error only after that transition settles.
    error_page = await page.query_selector("section.error_page")
    if error_page and await error_page.is_visible():
        error_text = await error_page.text_content() or ""
        if "not a functioning page" in error_text.lower():
            raise CheckError("Product page does not exist")

    # The pincode selection may navigate after the initial URL check.
    if product_url(page.url) != url:
        raise CheckError("Unexpected product redirect")

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
    add_btn = False
    if enabled_visible:
        btn_elem = await page.query_selector(
            "a.btn.btn-primary.add-to-cart:not(.disabled)"
        )
        try:
            enabled_state = await btn_elem.is_enabled() if btn_elem else False
        except Exception as e:
            await log(f"Error checking add-to-cart enabled state: {e}")
            enabled_state = False
        await log("Add to Cart is_enabled:", enabled_state)
        add_btn = enabled_state

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

    in_stock = (
        add_btn
        and not sold_out_visible
        and not disabled_btn
        and not notify_visible
        and pincode_confirmed
    )

    current_reasons = []
    if add_btn:
        current_reasons.append("add_btn_visible")
    if sold_out_visible:
        current_reasons.append("sold_out_visible")
    if disabled_btn:
        current_reasons.append("disabled_btn_visible")
    if notify_visible:
        current_reasons.append("notify_visible")
    if not pincode_confirmed:
        current_reasons.append("pincode_mismatch")
    await log(
        "Scraper decision:",
        "in_stock" if in_stock else "out_of_stock",
        "based on:",
        "; ".join(current_reasons),
    )

    safe_url_part = re.sub(r"^https?://", "", url)
    safe_url_part = re.sub(r"[^a-zA-Z0-9_-]", "_", safe_url_part)
    safe_filename = f"artifacts/{pincode}_{safe_url_part[:90]}_{uuid4().hex}.png"

    async def capture_screenshot():
        try:
            await log(f"Attempting to take screenshot: {safe_filename}")
            await page.screenshot(path=safe_filename)
            await log(f"Screenshot saved: {safe_filename}")
        except Exception as e:
            await log(f"Error taking single screenshot for {url}: {e}")

    await capture_screenshot()

    if not pincode_confirmed:
        raise CheckError("Pincode verification failed")
    if product_name == "The Product" or not (add_btn or sold_out_visible or disabled_btn or notify_visible):
        raise CheckError("Product identity or availability indicators missing")
    if add_btn and (sold_out_visible or disabled_btn or notify_visible):
        raise CheckError("Conflicting availability indicators")
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
            try:
                page = await browser.new_page()
                return await _check_availability_on_page(
                    page, url, pincode, skip_pincode, log_prefix
                )
            finally:
                await browser.close()
    else:
        return await _check_availability_on_page(
            page, url, pincode, skip_pincode, log_prefix
        )
