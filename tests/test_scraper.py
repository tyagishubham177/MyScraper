import asyncio
import sys
import types

# Stub playwright module to avoid dependency during import
playwright_module = types.ModuleType("playwright")
async_api = types.ModuleType("playwright.async_api")
async_api.async_playwright = lambda: None
async_api.Page = object
playwright_module.async_api = async_api
sys.modules.setdefault("playwright", playwright_module)
sys.modules.setdefault("playwright.async_api", async_api)

import pytest
from scripts import scraper

# --- Mocks for Playwright objects ---

class MockElementHandle:
    def __init__(self, name="element", visible=True, enabled=True, text_content_val="Text Content", fill_raises=None, click_raises=None, text_content_raises=None):
        self.name = name
        self._visible = visible
        self._enabled = enabled
        self._text_content_val = text_content_val
        self._fill_raises = fill_raises
        self._click_raises = click_raises
        self._text_content_raises = text_content_raises
        self.filled_value = None
        self.clicked_count = 0

    async def is_visible(self):
        return self._visible

    async def is_enabled(self):
        return self._enabled

    async def text_content(self):
        if self._text_content_raises:
            raise self._text_content_raises
        return self._text_content_val

    async def fill(self, value):
        if self._fill_raises:
            raise self._fill_raises
        self.filled_value = value
        # print(f"MockElement({self.name}): Filled with '{value}'")

    async def click(self, **kwargs): # Added **kwargs to accept timeout etc.
        if self._click_raises:
            raise self._click_raises
        self.clicked_count += 1
        # print(f"MockElement({self.name}): Clicked (count: {self.clicked_count})")

    async def query_selector(self, selector): # Mocking element.query_selector for pincode dropdown item
        if selector == "li.tt-suggestion":
            # Simulate finding the first suggestion
            return MockElementHandle(name="pincode_suggestion", text_content_val="Matched Pincode")
        return None

    async def get_attribute(self, name): # For checking disabled state on add-to-cart
        if name == "class" and not self._enabled:
            return "disabled"
        if name == "class" and self._enabled:
            return "" # Or some other class
        return None


class MockKeyboard:
    def __init__(self):
        self.pressed_keys = []

    async def press(self, key):
        self.pressed_keys.append(key)
        # print(f"MockKeyboard: Pressed '{key}'")


class MockPage:
    def __init__(self, selectors_config=None, screenshot_raises=None):
        self.selectors_config = selectors_config if selectors_config else {}
        self.keyboard = MockKeyboard()
        self.screenshot_path = None
        self._screenshot_raises = screenshot_raises
        self.url = "http://testurl.com/product-page" # For screenshot path
        self.clicked_selectors = []
        self.waited_for_load_state = None
        self.goto_url = None
        self._waited_selectors = {} # Store awaited selectors for tests

    async def goto(self, url, timeout=None):
        self.goto_url = url
        # print(f"MockPage: Navigated to {url}")

    async def wait_for_load_state(self, state="load", timeout=None):
        self.waited_for_load_state = state
        # print(f"MockPage: Waited for load state '{state}'")

    async def query_selector(self, selector):
        # print(f"MockPage: Querying selector '{selector}'")
        config = self.selectors_config.get(selector)

        if config is None and selector not in self.selectors_config: # Not configured at all
            # print(f"MockPage: Selector '{selector}' not found (not configured)")
            return None
        if config is None and selector in self.selectors_config: # Explicitly configured as None (not found)
            # print(f"MockPage: Selector '{selector}' not found (configured as None)")
            return None

        if isinstance(config, MockElementHandle): # Already a mock instance
            return config
        if isinstance(config, dict) and "element_instance" in config: # Pre-created instance
             return config["element_instance"]

        # Default attributes if not specified in config (config is a dict here)
        visible = config.get("visible", True)
        enabled = config.get("enabled", True)
        text_content_val = config.get("text_content", f"Content of {selector}")
        fill_raises = config.get("fill_raises", None)
        click_raises = config.get("click_raises", None)
        text_content_raises = config.get("text_content_raises", None)

        return MockElementHandle(
            name=selector,
            visible=visible,
            enabled=enabled,
            text_content_val=text_content_val,
            fill_raises=fill_raises,
            click_raises=click_raises,
            text_content_raises=text_content_raises
        )

    async def wait_for_selector(self, selector, timeout=None, state='visible'):
        # print(f"MockPage: Waiting for selector '{selector}' with state '{state}'")
        self._waited_selectors[selector] = state
        element = await self.query_selector(selector)
        if element:
            if state == 'visible' and await element.is_visible():
                return element
            if state == 'attached' : # query_selector implies attached if element is returned
                return element
            # Add other states if needed, e.g. 'hidden'
        # print(f"MockPage: TimeoutError for selector '{selector}' with state '{state}'")
        raise Exception(f"TimeoutError: waiting for selector `{selector}`") # Playwright raises TimeoutError, using generic Exception for now

    async def click(self, selector, timeout=None):
        self.clicked_selectors.append(selector)
        # print(f"MockPage: Clicked selector '{selector}'")
        # Simulate potential side effects or check if element exists via query_selector
        element = await self.query_selector(selector)
        if element:
            await element.click() # Propagate click to mock element for its internal logic if any
        elif selector == "button.btn.btn-primary.product_select_city_confirm": # Pincode confirm
             # This button might not be "found" by query_selector if it's part of a dynamic modal
             # but the script tries to click it directly.
             pass
        else:
            # print(f"MockPage: Tried to click non-existent selector '{selector}'")
            pass # Or raise an error if that's the expected Playwright behavior for click on non-existent

    async def screenshot(self, path=None):
        if self._screenshot_raises:
            raise self._screenshot_raises
        self.screenshot_path = path
        # print(f"MockPage: Screenshot taken: {path}")

# --- End Mocks ---

@pytest.fixture
def mock_page(monkeypatch):
    # This fixture can be enhanced in each test to set specific selector behaviors
    page = MockPage()
    return page

@pytest.mark.asyncio
async def test_pincode_modal_appears_and_skipped(mock_page, monkeypatch, capsys):
    """Test pincode modal appears, skip_pincode is True."""
    mock_page.selectors_config = {
        "div.modal-content.bg-transparent": {"visible": True},
    }

    in_stock, name = await scraper._check_availability_on_page(mock_page, "http://testurl.com", "123456", skip_pincode=True)

    captured = capsys.readouterr()
    assert "Pincode modal shown but skipping entry" in captured.out # Exact log message
    pincode_input_el = await mock_page.query_selector("#search")
    assert pincode_input_el is None or pincode_input_el.filled_value is None # No input attempt


@pytest.mark.asyncio
async def test_pincode_modal_not_present(mock_page, monkeypatch, capsys):
    """Test pincode modal does not appear."""
    mock_page.selectors_config = {
        "div.modal-content.bg-transparent": None, # Modal element itself is not found
    }

    mock_page.selectors_config.update({
        "div.alert.alert-danger.mt-3": {"visible": False}, # SOLD_OUT_SELECTOR
        "a.btn.btn-primary.add-to-cart.disabled": {"visible": False}, # ADD_TO_CART_DISABLED_SELECTOR
        "a.btn.btn-primary.add-to-cart:not(.disabled)": {"visible": True, "enabled": True}, # ADD_TO_CART_ENABLED_SELECTOR
        "h1.product-name.mb-2.fw-bold.lh-sm.text-dark.h3.mb-4": {"text_content": "Test Product"}, # PRODUCT_NAME_SELECTOR
    })

    in_stock, name = await scraper._check_availability_on_page(mock_page, "http://testurl.com", "123456", skip_pincode=False)

    captured = capsys.readouterr()
    assert "Pincode modal not found" in captured.out # Exact log message
    assert in_stock
    assert name == "Test Product"

@pytest.mark.asyncio
async def test_pincode_modal_appears_input_success_dropdown(mock_page, monkeypatch, capsys):
    """Test pincode modal, successful input, and dropdown selection."""
    pincode = "123456"
    pincode_search_el = MockElementHandle(name="#search")
    suggestion_selector_str = f"#automatic a.searchitem-name:has-text('{pincode}')"
    suggestion_el = MockElementHandle(name=suggestion_selector_str)

    mock_page.selectors_config = {
        "div.modal-content.bg-transparent": {"visible": True},
        "#search": {"element_instance": pincode_search_el, "visible": True},
        "#automatic": {"visible": True}, # For "Dropdown shown" log
        suggestion_selector_str: {"element_instance": suggestion_el, "visible": True}
    }

    # Custom query_selector for the page
    async def custom_page_qs(selector):
        if selector == "#search": return pincode_search_el
        if selector == "#automatic": return MockElementHandle(name="#automatic", visible=True) # Needs to be found by wait_for_selector
        if selector == suggestion_selector_str: return suggestion_el
        # Fallback for stock/product name selectors
        config = mock_page.selectors_config.get(selector, {})
        return MockElementHandle(name=selector,
                                 visible=config.get("visible", False),
                                 enabled=config.get("enabled", True),
                                 text_content_val=config.get("text_content", "Default"))
    monkeypatch.setattr(mock_page, "query_selector", custom_page_qs)

    # Crucially, ensure wait_for_selector will also find these elements.
    # We can reuse custom_page_qs if it's suitable or make a specific one for wait_for_selector.
    async def mock_wait_for_selector(selector, timeout=None, state=None):
        # print(f"mock_wait_for_selector called with: {selector}")
        if selector == "#automatic":
            # print("mock_wait_for_selector: #automatic found")
            return MockElementHandle(name="#automatic", visible=True)
        if selector == suggestion_selector_str:
            # print("mock_wait_for_selector: suggestion_selector_str found")
            return suggestion_el
        # Fallback or raise timeout for other unexpected selectors
        # print(f"mock_wait_for_selector: {selector} caused timeout")
        raise Exception(f"Timeout waiting for {selector}")
    monkeypatch.setattr(mock_page, "wait_for_selector", mock_wait_for_selector)


    mock_page.selectors_config.update({
        "div.alert.alert-danger.mt-3": {"visible": False},
        "a.btn.btn-primary.add-to-cart.disabled": {"visible": False},
        "a.btn.btn-primary.add-to-cart:not(.disabled)": {"visible": True, "enabled": True},
        "h1.product-name.mb-2.fw-bold.lh-sm.text-dark.h3.mb-4": {"text_content": "Test Product"},
    })

    in_stock, name = await scraper._check_availability_on_page(mock_page, "http://testurl.com", pincode, skip_pincode=False)

    assert pincode_search_el.filled_value == pincode
    assert suggestion_el.clicked_count > 0
    assert in_stock
    assert name == "Test Product"
    captured = capsys.readouterr()
    assert "Pincode input found → typing 123456" in captured.out # More exact log
    assert "Dropdown shown" in captured.out
    assert "Pincode selected/attempted" in captured.out


@pytest.mark.asyncio
async def test_pincode_modal_input_no_dropdown_use_keyboard(mock_page, monkeypatch, capsys):
    """Test pincode modal, input, no dropdown, uses keyboard Enter."""
    pincode_search_el = MockElementHandle(name="#search") # Corrected name

    # Mock pincode_search_el to return None for suggestions
    async def mock_pincode_el_qs_no_suggestion(selector):
        if f":has-text('{pincode}')" in selector: # Check for suggestion selector pattern
            return None # Suggestion not found
        return MockElementHandle(name="other_on_pincode_el") # Should not be called for this test path
    monkeypatch.setattr(pincode_search_el, "query_selector", mock_pincode_el_qs_no_suggestion)

    mock_page.selectors_config = {
        "div.modal-content.bg-transparent": {"visible": True}, # Corrected selector
        "#search": {"element_instance": pincode_search_el, "visible": True}, # Corrected selector
        # Confirm button might still be there but not clicked if Enter is pressed first
    }

    # Custom query_selector for the page
    async def custom_page_qs(selector):
        if selector == "#search":
            return pincode_search_el
        # Fallback for stock/product name selectors
        return MockElementHandle(name=selector,
                                 visible=mock_page.selectors_config.get(selector, {}).get("visible", False),
                                 enabled=mock_page.selectors_config.get(selector, {}).get("enabled", True),
                                 text_content_val=mock_page.selectors_config.get(selector, {}).get("text_content", "Default"))
    monkeypatch.setattr(mock_page, "query_selector", custom_page_qs)

    pincode = "123456"
    # Setup for subsequent stock check
    mock_page.selectors_config.update({
        "div.alert.alert-danger.mt-3": {"visible": False},
        "a.btn.btn-primary.add-to-cart.disabled": {"visible": False},
        "a.btn.btn-primary.add-to-cart:not(.disabled)": {"visible": True, "enabled": True},
        "h1.product-name.mb-2.fw-bold.lh-sm.text-dark.h3.mb-4": {"text_content": "Test Product"},
    })

    await scraper._check_availability_on_page(mock_page, "http://testurl.com", pincode, skip_pincode=False) # Added URL

    assert pincode_search_el.filled_value == pincode
    assert "Enter" in mock_page.keyboard.pressed_keys
    captured = capsys.readouterr()
    assert "Pincode selected/attempted" in captured.out # Check if it got past pincode stage


@pytest.mark.asyncio
async def test_pincode_modal_input_field_not_found(mock_page, monkeypatch, capsys):
    """Test pincode modal appears, but input field #search is not found."""
    mock_page.selectors_config = {
        "div.modal-content.bg-transparent": {"visible": True},
        "#search": None, # Input field not found
    }
    # Stock/name selectors not strictly needed as it should return early, but good for consistency
    mock_page.selectors_config.update({
        "h1.product-name.mb-2.fw-bold.lh-sm.text-dark.h3.mb-4": {"text_content": "Test Product Name"},
    })

    in_stock, name = await scraper._check_availability_on_page(mock_page, "http://testurl.com", "123456", skip_pincode=False)

    captured = capsys.readouterr()
    assert "Pincode input not found in modal" in captured.out # Exact log message
    assert not in_stock
    assert name == "Test Product Name" # Name scraping happens after pincode handling


# --- Tests for Stock Availability Logic ---

@pytest.mark.parametrize(
    "sold_out_visible, add_to_cart_disabled_visible, add_to_cart_enabled_config, notify_me_visible, expected_in_stock",
    [
        (True, False, {"visible": False, "enabled": False}, False, False),  # Sold out visible
        (False, True, {"visible": False, "enabled": False}, False, False), # Add to cart disabled
        (False, False, {"visible": True, "enabled": True}, False, True),   # Add to cart enabled
        (True, True, {"visible": False, "enabled": False}, False, False),  # Both Sold out and disabled add to cart
        (True, False, {"visible": True, "enabled": True}, False, False),   # Sold out takes precedence over enabled add to cart
        (False, True, {"visible": True, "enabled": True}, False, False),   # Disabled takes precedence over enabled (though unusual)
        (False, False, {"visible": False, "enabled": False}, True, False), # Notify me visible, no other indicators (defaults to OOS)
        (False, False, {"visible": False, "enabled": False}, False, False),# No indicators at all (defaults to OOS)
    ]
)
@pytest.mark.asyncio
async def test_stock_availability_logic(
    mock_page, monkeypatch, capsys,
    sold_out_visible, add_to_cart_disabled_visible, add_to_cart_enabled_config, notify_me_visible, expected_in_stock
):
    mock_page.selectors_config = {
        "div.modal-content.bg-transparent": {"visible": False}, # Corrected selector
        "div.alert.alert-danger.mt-3": {"visible": sold_out_visible},
        "a.btn.btn-primary.add-to-cart.disabled": {"visible": add_to_cart_disabled_visible},
        "a.btn.btn-primary.add-to-cart:not(.disabled)": add_to_cart_enabled_config,
        "button.btn.btn-primary.product_enquiry": {"visible": notify_me_visible},
        "h1.product-name.mb-2.fw-bold.lh-sm.text-dark.h3.mb-4": {"text_content": "Stock Test Product"},
    }

    in_stock, name = await scraper._check_availability_on_page(mock_page, "http://testurl.com", "000000", skip_pincode=True) # Added URL
    assert in_stock == expected_in_stock
    assert name == "Stock Test Product"


# --- Tests for Product Name Extraction ---

@pytest.mark.asyncio
async def test_product_name_extraction_success(mock_page, monkeypatch):
    mock_page.selectors_config = {
        "div.modal-content.bg-transparent": {"visible": False}, # Corrected selector
        "h1.product-name.mb-2.fw-bold.lh-sm.text-dark.h3.mb-4": {"visible": True, "text_content": "Specific Product Name"},
        "a.btn.btn-primary.add-to-cart:not(.disabled)": {"visible": True, "enabled": True},
    }
    in_stock, name = await scraper._check_availability_on_page(mock_page, "http://testurl.com", "000000", skip_pincode=True) # Added URL
    assert name == "Specific Product Name"
    assert in_stock

@pytest.mark.asyncio
async def test_product_name_extraction_not_found(mock_page, monkeypatch, capsys):
    mock_page.selectors_config = {
        "div.modal-content.bg-transparent": {"visible": False}, # Corrected selector
        "h1.product-name.mb-2.fw-bold.lh-sm.text-dark.h3.mb-4": None,
        "a.btn.btn-primary.add-to-cart:not(.disabled)": {"visible": True, "enabled": True},
    }
    in_stock, name = await scraper._check_availability_on_page(mock_page, "http://testurl.com", "000000", skip_pincode=True) # Added URL
    assert name == "The Product"
    captured = capsys.readouterr()
    assert "Product name element not found. Using default." in captured.out # Exact log
    assert in_stock

@pytest.mark.asyncio
async def test_product_name_extraction_no_text_content(mock_page, monkeypatch, capsys):
    mock_page.selectors_config = {
        "div.modal-content.bg-transparent": {"visible": False},
        "h1.product-name.mb-2.fw-bold.lh-sm.text-dark.h3.mb-4": {"visible": True, "text_content": None},
        "a.btn.btn-primary.add-to-cart:not(.disabled)": {"visible": True, "enabled": True},
    }
    in_stock, name = await scraper._check_availability_on_page(mock_page, "http://testurl.com", "000000", skip_pincode=True)
    assert name == "The Product"
    captured = capsys.readouterr()
    assert "Extracted product name: The Product" in captured.out # Logic implies it uses default
    assert in_stock

@pytest.mark.asyncio
async def test_product_name_extraction_text_content_raises_exception(mock_page, monkeypatch, capsys):
    product_name_selector_str = "h1.product-name.mb-2.fw-bold.lh-sm.text-dark.h3.mb-4"
    product_name_el = MockElementHandle(name=product_name_selector_str, text_content_raises=Exception("Content error"))

    mock_page.selectors_config = {
        "div.modal-content.bg-transparent": {"visible": False},
        product_name_selector_str: {"element_instance": product_name_el, "visible": True},
        "a.btn.btn-primary.add-to-cart:not(.disabled)": {"visible": True, "enabled": True},
    }

    async def custom_page_qs(selector):
        if selector == product_name_selector_str:
            return product_name_el
        elif selector == "a.btn.btn-primary.add-to-cart:not(.disabled)": # ADD_TO_CART_ENABLED_SELECTOR
            # Ensure this is returned as visible and enabled for in_stock=True
            return MockElementHandle(name=selector, visible=True, enabled=True)
        else: # For all other selectors relevant to stock (SOLD_OUT, ADD_TO_CART_DISABLED),
            # returning None means they are not found, thus 'not visible'.
            return None
    monkeypatch.setattr(mock_page, "query_selector", custom_page_qs)

    in_stock, name = await scraper._check_availability_on_page(mock_page, "http://testurl.com", "000000", skip_pincode=True)
    assert name == "The Product"
    captured = capsys.readouterr()
    assert "Error fetching product name text: Content error. Using default." in captured.out
    assert in_stock # This should now be True


# --- Tests for Screenshotting ---

@pytest.mark.asyncio
async def test_screenshot_called_with_correct_path(mock_page, monkeypatch):
    mock_page.url = "http://testurl.com/category/product-slug-123.html"
    mock_page.selectors_config = {
        "div.modal-content.bg-transparent": {"visible": False}, # Corrected selector
        "a.btn.btn-primary.add-to-cart:not(.disabled)": {"visible": True, "enabled": True},
        "h1.product-name.mb-2.fw-bold.lh-sm.text-dark.h3.mb-4": {"text_content": "Screenshot Product"},
    }

    await scraper._check_availability_on_page(mock_page, "http://testurl.com", "000000", skip_pincode=True) # URL used for screenshot name

    assert mock_page.screenshot_path is not None
    expected_filename_part = "testurl_com.png" # Based on URL "http://testurl.com"
    assert expected_filename_part in mock_page.screenshot_path
    assert "artifacts" in mock_page.screenshot_path

@pytest.mark.asyncio
async def test_screenshot_exception_handled(mock_page, monkeypatch, capsys):
    mock_page.url = "http://testurl.com/product-error.html"
    mock_page._screenshot_raises = Exception("Disk full")
    mock_page.selectors_config = {
        "div.modal-content.bg-transparent": {"visible": False},
        "a.btn.btn-primary.add-to-cart:not(.disabled)": {"visible": True, "enabled": True},
        "h1.product-name.mb-2.fw-bold.lh-sm.text-dark.h3.mb-4": {"text_content": "Screenshot Fail Product"},
    }

    await scraper._check_availability_on_page(mock_page, "http://testurl.com", "000000", skip_pincode=True)

    captured = capsys.readouterr()
    assert "Error taking single screenshot for http://testurl.com: Disk full" in captured.out # Exact log


# Original tests, can be refactored or removed if functionality is fully covered by new tests
# For now, keeping them and their DummyPage if they test different aspects of check_product_availability.

class DummyPage: # Keep this if check_product_availability tests still use it
    pass

async def dummy_checker(page, url, pincode, skip): # Keep this?
    pass # Add pass to make it a valid empty function


def test_check_product_availability_with_page(monkeypatch):
    called = {}

    async def fake(page, url, pincode, skip):
        called["args"] = (page, url, pincode, skip)
        return True, "Dummy"

    monkeypatch.setattr(scraper, "_check_availability_on_page", fake)
    page = DummyPage()
    result = asyncio.run(
        scraper.check_product_availability(
            "http://x", "123", page=page, skip_pincode=True
        )
    )
    assert result == (True, "Dummy")
    assert called["args"] == (page, "http://x", "123", True)


def test_check_product_availability_without_page(monkeypatch):
    called = {}

    async def fake_check(page, url, pincode, skip):
        called["args"] = (page, url, pincode, skip)
        return False, "Dummy"

    class DummyBrowser:
        async def new_page(self):
            called["new_page"] = True
            return "page"

        async def close(self):
            called["closed"] = True

    class DummyChromium:
        async def launch(self, headless=True, args=None):
            called["launch"] = True
            return DummyBrowser()

    class DummyPlaywright:
        chromium = DummyChromium()

    class DummyManager:
        async def __aenter__(self):
            called["enter"] = True
            return DummyPlaywright()

        async def __aexit__(self, exc_type, exc, tb):
            called["exit"] = True

    monkeypatch.setattr(scraper, "_check_availability_on_page", fake_check)
    monkeypatch.setattr(scraper, "async_playwright", lambda: DummyManager())

    result = asyncio.run(scraper.check_product_availability("http://x", "111"))
    assert result == (False, "Dummy")
    assert called["args"][0] == "page"
    assert called["closed"]
    assert called["enter"] and called["exit"]
