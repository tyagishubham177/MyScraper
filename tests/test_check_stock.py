import asyncio
import time
from datetime import time as dt_time
import pytest
import sys
import types

# Import aiohttp for mocking
try:
    import aiohttp
except ImportError:  # pragma: no cover - fallback for environments without aiohttp
    class ClientError(Exception):
        pass

    class ClientResponseError(Exception):
        def __init__(self, *, request_info=None, history=None, status=None, message=""):
            super().__init__(message)
            self.request_info = request_info
            self.history = history
            self.status = status
            self.message = message

    aiohttp = types.SimpleNamespace(ClientError=ClientError, ClientResponseError=ClientResponseError)
    sys.modules.setdefault("aiohttp", aiohttp)

# Provide dummy modules for optional dependencies
# sys.modules.setdefault("aiohttp", types.ModuleType("aiohttp")) # Keep real aiohttp for ClientError
playwright_module = types.ModuleType("playwright")
playwright_async = types.ModuleType("playwright.async_api")
playwright_async.async_playwright = lambda: None
playwright_async.Page = object
playwright_module.async_api = playwright_async
sys.modules.setdefault("playwright", playwright_module)
sys.modules.setdefault("playwright.async_api", playwright_async)

import scripts.config as config_module

sys.modules.setdefault("config", config_module)
import scripts.notifications as notifications_module

sys.modules.setdefault("notifications", notifications_module)
import scripts.scraper as scraper_module

sys.modules.setdefault("scraper", scraper_module)
import scripts.notifications_util as notifications_util_module
sys.modules.setdefault("notifications_util", notifications_util_module)
import scripts.product_checker as product_checker_module
sys.modules.setdefault("product_checker", product_checker_module)

from scripts import (
    check_stock,
    api_utils,
    stock_utils,
    config,
    notifications,
    notifications_util,
    product_checker,
)


# Mocks for aiohttp ClientSession
class MockClientResponse:
    def __init__(self, json_data, status_code):
        self._json = json_data
        self.status = status_code

    async def json(self):
        if callable(self._json):
            # If _json is a callable (e.g., a lambda that raises an error), call it.
            # This is used for simulating JSON decoding errors.
            return self._json()
        return self._json

    def raise_for_status(self):
        # Simulate aiohttp's raise_for_status behavior
        if self.status >= 400:
            mock_request_info = types.SimpleNamespace(real_url="http://fakeurl/error")
            raise aiohttp.ClientResponseError(
                request_info=mock_request_info,
                history=None,
                status=self.status,
                message="Client Error Mocked", # More specific message
            )

    async def __aexit__(self, exc_type, exc, tb):
        pass

    async def __aenter__(self):
        return self


class MockClientSession:
    def __init__(self, response_data, status_code=200, raise_exception=None):
        self.response_data = response_data
        self.status_code = status_code
        self.raise_exception = raise_exception

    def get(self, url, **kwargs):
        if self.raise_exception:
            raise self.raise_exception
        return MockClientResponse(self.response_data, self.status_code)


@pytest.mark.asyncio
async def test_fetch_api_data_success():
    """Test fetch_api_data with a successful API call and valid JSON."""
    mock_data = {"key": "value"}
    session = MockClientSession(response_data=mock_data)
    result = await api_utils.fetch_api_data(session, "http://fakeurl")
    assert result == mock_data


@pytest.mark.asyncio
async def test_fetch_api_data_failure():
    """Test fetch_api_data with an API call failure (e.g., network error)."""
    session = MockClientSession(response_data=None, raise_exception=aiohttp.ClientError("Network error Mock"))
    result = await api_utils.fetch_api_data(session, "http://fakeurl")
    assert result is None


@pytest.mark.asyncio
async def test_fetch_api_data_non_200_status():
    """Test fetch_api_data with a non-200 status code."""
    session = MockClientSession(response_data={"error": "failed"}, status_code=404)
    result = await api_utils.fetch_api_data(session, "http://fakeurl")
    assert result is None


@pytest.mark.asyncio
async def test_fetch_api_data_invalid_json():
    """Test fetch_api_data with an invalid JSON response."""
    # Simulate invalid JSON by having .json() raise an error
    session = MockClientSession(response_data=lambda: (_ for _ in ()).throw(ValueError("Invalid JSON")))
    result = await api_utils.fetch_api_data(session, "http://fakeurl")
    assert result is None


@pytest.mark.asyncio
async def test_load_recipients_empty_list(monkeypatch):
    """Test load_recipients with an empty list from fetch_api_data."""
    async def mock_fetch_empty(session, url):
        return []
    monkeypatch.setattr(api_utils, "fetch_api_data", mock_fetch_empty)
    recipients = await api_utils.load_recipients(None)
    assert recipients == {}


@pytest.mark.asyncio
async def test_load_recipients_none_response(monkeypatch):
    """Test load_recipients with None from fetch_api_data."""
    async def mock_fetch_none(session, url):
        return None
    monkeypatch.setattr(api_utils, "fetch_api_data", mock_fetch_none)
    recipients = await api_utils.load_recipients(None)
    assert recipients == {}


@pytest.mark.asyncio
async def test_load_recipients_missing_data(monkeypatch):
    """Test load_recipients with data missing 'id' or 'email'."""
    mock_data = [
        {"id": 1, "email": "valid@example.com"},
        {"email": "no_id@example.com"},
        {"id": 3},
        {},
    ]
    async def mock_fetch(session, url):
        return mock_data
    monkeypatch.setattr(api_utils, "fetch_api_data", mock_fetch)
    recipients = await api_utils.load_recipients(None)
    assert len(recipients) == 1
    assert recipients[1]["email"] == "valid@example.com"
    assert recipients[1]["pincode"] == "201305"


@pytest.mark.asyncio
async def test_load_products_empty_list(monkeypatch):
    """Test load_products with an empty list from fetch_api_data."""
    async def mock_fetch_empty(session, url):
        return []
    monkeypatch.setattr(api_utils, "fetch_api_data", mock_fetch_empty)
    products = await api_utils.load_products(None)
    assert products == []


@pytest.mark.asyncio
async def test_load_products_none_response(monkeypatch):
    """Test load_products with None from fetch_api_data."""
    async def mock_fetch_none(session, url):
        return None
    monkeypatch.setattr(api_utils, "fetch_api_data", mock_fetch_none)
    products = await api_utils.load_products(None)
    assert products is None # Or [] depending on desired behavior, current is None


@pytest.mark.asyncio
async def test_fetch_subscriptions_empty_list(monkeypatch):
    """Test fetch_subscriptions with an empty list from fetch_api_data."""
    async def mock_fetch_empty(session, url):
        return []
    monkeypatch.setattr(api_utils, "fetch_api_data", mock_fetch_empty)
    subscriptions = await api_utils.fetch_subscriptions(None, 1)
    assert subscriptions == []


@pytest.mark.asyncio
async def test_fetch_subscriptions_none_response(monkeypatch):
    """Test fetch_subscriptions with None from fetch_api_data."""
    async def mock_fetch_none(session, url):
        return None
    monkeypatch.setattr(api_utils, "fetch_api_data", mock_fetch_none)
    subscriptions = await api_utils.fetch_subscriptions(None, 1)
    assert subscriptions is None # Or [] depending on desired behavior, current is None


@pytest.mark.asyncio
async def test_save_stock_counters_with_admin_token(monkeypatch):
    """Ensure Authorization header is sent when ADMIN_TOKEN is set."""
    captured = {}

    class DummyResp:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            pass

        def raise_for_status(self):
            captured["raised"] = True

    class DummySession:
        def put(self, url, json=None, headers=None):
            captured["url"] = url
            captured["json"] = json
            captured["headers"] = headers
            return DummyResp()

    monkeypatch.setattr(config, "APP_BASE_URL", "http://api")
    monkeypatch.setattr(config, "ADMIN_TOKEN", "secret")
    await api_utils.save_stock_counters(DummySession(), {"p": 1})
    assert captured["headers"]["Authorization"] == "Bearer secret"


@pytest.mark.asyncio
async def test_load_stock_counters_key_conversion(monkeypatch):
    """Keys with product_id|pincode format should be preserved as strings."""
    async def mock_fetch(session, url, headers=None):
        return {"1|111": 5, "2|222": 3}

    monkeypatch.setattr(api_utils, "fetch_api_data", mock_fetch)
    counters = await api_utils.load_stock_counters(None)
    assert counters == {"1|111": 5, "2|222": 3}
    assert all(isinstance(k, str) for k in counters.keys())


@pytest.mark.asyncio
async def test_process_product_fetch_subscriptions_none(monkeypatch):
    """Test process_product when fetch_subscriptions returns None."""
    product_info = {"id": 1, "name": "Test Product", "url": "http://example.com"}
    recipients_map = {1: {"email": "test@example.com", "pincode": "201305"}}
    current_time = dt_time(12, 0)
    subs_map = {1: None}

    summary, sent_count, needs_pin_reset = await product_checker.process_product(
        None,
        None,
        product_info,
        recipients_map,
        current_time,
        False,
        subs_map,
        "201305",
    )
    # The function now returns a summary even if fetch_subscriptions is None
    assert summary is not None
    assert summary["product_name"] == product_info["name"]
    assert summary["product_url"] == product_info["url"]
    assert len(summary["subscriptions"]) == 1
    assert summary["subscriptions"][0]["status"] == "Error fetching subscriptions"
    assert sent_count == 0
    assert not needs_pin_reset


@pytest.mark.asyncio
async def test_process_product_fetch_subscriptions_empty_list(monkeypatch):
    """Test process_product when fetch_subscriptions returns an empty list."""
    product_info = {"id": 1, "name": "Test Product", "url": "http://example.com"}
    recipients_map = {1: {"email": "test@example.com", "pincode": "201305"}}
    current_time = dt_time(12, 0)
    subs_map = {1: []}

    summary, sent_count, needs_pin_reset = await product_checker.process_product(
        None,
        None,
        product_info,
        recipients_map,
        current_time,
        False,
        subs_map,
        "201305",
    )
    assert summary is not None
    assert summary["product_name"] == product_info["name"]
    # If fetch_subscriptions returns [], it's treated as an error fetching them.
    assert summary["product_name"] == product_info["name"]
    assert summary["product_url"] == product_info["url"]
    assert len(summary["subscriptions"]) == 1
    assert summary["subscriptions"][0]["status"] == "Error fetching subscriptions"
    assert sent_count == 0
    assert not needs_pin_reset


@pytest.mark.asyncio
async def test_process_product_fetch_subscriptions_invalid_data(monkeypatch):
    """Test process_product when fetch_subscriptions returns non-list data."""
    product_info = {"id": 1, "name": "Test Product", "url": "http://example.com"}
    recipients_map = {}  # No recipients needed as it should fail before that
    current_time = dt_time(12, 0)
    subs_map = {1: "not a list"}

    summary, sent_count, needs_pin_reset = await product_checker.process_product(
        None,
        None,
        product_info,
        recipients_map,
        current_time,
        False,
        subs_map,
        "201305",
    )
    assert summary is not None
    assert summary["product_name"] == product_info["name"]
    assert summary["product_url"] == product_info["url"]
    assert len(summary["subscriptions"]) == 1
    assert summary["subscriptions"][0]["status"] == "Error fetching subscriptions"
    assert sent_count == 0
    assert not needs_pin_reset


@pytest.mark.asyncio
async def test_process_product_scraper_exception(monkeypatch):
    """Test process_product when scraper.check_product_availability raises an exception."""
    async def mock_scraper_raises_exception(
        url, pincode, page=None, skip_pincode=False, log_prefix=""
    ):
        raise Exception("Scraper failed")
    monkeypatch.setattr(scraper_module, "check_product_availability", mock_scraper_raises_exception)

    product_info = {"id": 1, "name": "Test Product", "url": "http://example.com"}
    recipients_map = {1: {"email": "test@example.com", "pincode": "201305"}}
    current_time = dt_time(12, 0)

    subs_map = {1: [{"recipient_id": 1, "start_time": "00:00", "end_time": "23:59"}]}

    summary, sent_count, needs_pin_reset = await product_checker.process_product(
        None,
        None,
        product_info,
        recipients_map,
        current_time,
        False,
        subs_map,
        "201305",
    )
    assert summary is not None
    assert summary["product_name"] == product_info["name"]
    assert summary["product_url"] == product_info["url"]
    assert len(summary["subscriptions"]) == 1
    assert summary["subscriptions"][0]["status"] == "Error checking product: Scraper failed" # Matches the f-string in code
    assert sent_count == 0
    assert not needs_pin_reset


@pytest.mark.asyncio
async def test_process_product_missing_id(monkeypatch):
    """Test process_product when product_info is missing 'id'."""
    # No need to mock fetch_subscriptions as it shouldn't be called
    product_info = {"name": "Test Product No ID", "url": "http://example.com"} # Missing 'id'
    recipients_map = {}
    current_time = dt_time(12, 0)

    summary, sent_count, needs_pin_reset = await product_checker.process_product(
        None,
        None,
        product_info,
        recipients_map,
        current_time,
        False,
        {},
        "201305",
    )
    assert summary is None
    assert sent_count == 0
    assert not needs_pin_reset


@pytest.mark.asyncio
async def test_process_product_missing_url(monkeypatch):
    """Test process_product when product_info is missing 'url'."""
    # No need to mock fetch_subscriptions
    product_info = {"id": 1, "name": "Test Product No URL"} # Missing 'url'
    recipients_map = {}
    current_time = dt_time(12, 0)

    summary, sent_count, needs_pin_reset = await product_checker.process_product(
        None,
        None,
        product_info,
        recipients_map,
        current_time,
        False,
        {},
        "201305",
    )
    # If URL is missing, the function logs and returns None early.
    assert summary is None
    assert sent_count == 0
    assert not needs_pin_reset


@pytest.mark.asyncio
async def test_notify_users_email_host_not_set(monkeypatch):
    """Test notify_users when EMAIL_HOST is not set."""
    monkeypatch.setattr(config, "EMAIL_HOST", None)
    monkeypatch.setattr(config, "EMAIL_SENDER", "sender@example.com") # Must be set for this test

    subscriptions = [{"recipient_id": 1, "start_time": "08:00", "end_time": "17:00"}]
    recipients_map = {1: {"email": "test@example.com", "pincode": "201305"}}
    current_time = dt_time(12, 0)

    results, count = await notifications_util.notify_users(
        "Test Product",
        "http://example.com/product",
        subscriptions,
        recipients_map,
        current_time,
        "201305",
    )
    assert count == 0
    assert len(results) == 1
    assert results[0]["status"] == "Not Sent - Email Config Missing"
    assert results[0]["status"] == "Not Sent - Email Config Missing"


@pytest.mark.asyncio
async def test_notify_users_email_sender_not_set(monkeypatch):
    """Test notify_users when EMAIL_SENDER is not set."""
    monkeypatch.setattr(config, "EMAIL_HOST", "smtp.example.com") # Must be set
    monkeypatch.setattr(config, "EMAIL_SENDER", None)

    subscriptions = [{"recipient_id": 1, "start_time": "08:00", "end_time": "17:00", "paused": False}]
    recipients_map = {1: {"email": "test@example.com", "pincode": "201305"}}
    current_time = dt_time(12, 0)

    results, count = await notifications_util.notify_users(
        "Test Product", "http://example.com/product", subscriptions, recipients_map, current_time, "201305"
    )
    assert count == 0
    assert len(results) == 1
    assert results[0]["status"] == "Not Sent - Email Config Missing" # Adjusted to actual message


@pytest.mark.asyncio
async def test_notify_users_send_email_exception(monkeypatch):
    """Test notify_users when send_email_notification raises an exception."""
    monkeypatch.setattr(config, "EMAIL_HOST", "smtp.example.com")
    monkeypatch.setattr(config, "EMAIL_SENDER", "sender@example.com")
    monkeypatch.setattr(config, "EMAIL_PORT", 587) # Ensure all config vars are set
    monkeypatch.setattr(config, "EMAIL_HOST_USER", "user")
    monkeypatch.setattr(config, "EMAIL_HOST_PASSWORD", "pass")

    # Signature matches notifications.send_email_notification, as called by check_stock.notify_users
    async def mock_send_email_raises_exception(subject, body, sender, recipients, host, port, username, password):
        raise Exception("SMTP Error")
    monkeypatch.setattr(notifications_module, "send_email_notification", mock_send_email_raises_exception)

    subscriptions = [{"recipient_id": 1, "start_time": "08:00", "end_time": "17:00", "paused": False}]
    recipients_map = {1: {"email": "test@example.com", "pincode": "201305"}}
    current_time = dt_time(12, 0)

    results, count = await notifications_util.notify_users(
        "Test Product", "http://example.com/product", subscriptions, recipients_map, current_time, "201305"
    )
    assert count == 0
    assert len(results) == 1
    # This status comes from the except block in check_stock.notify_users
    assert results[0]["status"] == "Not Sent - Email Send Error"


@pytest.mark.asyncio
async def test_notify_users_empty_recipients_map(monkeypatch):
    """Test notify_users with an empty recipients_map."""
    monkeypatch.setattr(config, "EMAIL_HOST", "smtp.example.com")
    monkeypatch.setattr(config, "EMAIL_SENDER", "sender@example.com")
    # No need to mock send_email_notification as it shouldn't be called if map is empty before filtering

    subscriptions = [{"recipient_id": 1, "start_time": "08:00", "end_time": "17:00"}] # Sub for recipient 1
    recipients_map = {} # Empty map
    current_time = dt_time(12, 0)

    results, count = await notifications_util.notify_users(
        "Test Product", "http://example.com/product", subscriptions, recipients_map, current_time, "201305"
    )
    assert count == 0
    assert len(results) == 1
    assert results[0]["status"] == "Not Sent - Recipient Email Missing"


@pytest.mark.asyncio
async def test_notify_users_recipient_not_found(monkeypatch):
    """Test notify_users when a recipient_id is not in recipients_map."""
    monkeypatch.setattr(config, "EMAIL_HOST", "smtp.example.com")
    monkeypatch.setattr(config, "EMAIL_SENDER", "sender@example.com")
    monkeypatch.setattr(config, "EMAIL_PORT", 587)
    monkeypatch.setattr(config, "EMAIL_HOST_USER", "user")
    monkeypatch.setattr(config, "EMAIL_HOST_PASSWORD", "pass")

    subscriptions = [{"recipient_id": 2, "start_time": "08:00", "end_time": "17:00", "paused": False}] # Sub for recipient 2
    recipients_map = {1: {"email": "test@example.com", "pincode": "201305"}}  # Recipient 1 exists, but not 2
    current_time = dt_time(12, 0)

    results, count = await notifications_util.notify_users(
        "Test Product",
        "http://example.com/product",
        subscriptions,
        recipients_map,
        current_time,
        "201305",
    )
    assert count == 0
    assert len(results) == 1
    assert results[0]["status"] == "Not Sent - Recipient Email Missing"
    assert results[0]["user_email"] == "Unknown" # Adjusted to actual value


@pytest.mark.asyncio
async def test_notify_users_mixed_subscriptions(monkeypatch):
    """Test notify_users with a mix of paused, active, and out-of-time-window subscriptions."""
    mock_sent_emails = []
    # Signature matches notifications.send_email_notification, as called by check_stock.notify_users
    async def mock_send_email(subject, body, sender, recipients, host, port, username, password):
        # We are interested in the recipients list for this test.
        # In the actual call from notify_users, 'recipients' will be a list of emails.
        for r_email in recipients:
            mock_sent_emails.append(r_email)
    monkeypatch.setattr(notifications_module, "send_email_notification", mock_send_email)
    monkeypatch.setattr(config, "EMAIL_HOST", "smtp.example.com")
    monkeypatch.setattr(config, "EMAIL_SENDER", "sender@example.com") # This sender is passed to mock
    monkeypatch.setattr(config, "EMAIL_PORT", 587)
    monkeypatch.setattr(config, "EMAIL_HOST_USER", "user")
    monkeypatch.setattr(config, "EMAIL_HOST_PASSWORD", "pass")


    subscriptions = [
        {"recipient_id": 1, "paused": True, "start_time": "08:00", "end_time": "17:00"},
        {"recipient_id": 2, "start_time": "10:00", "end_time": "11:00", "paused": False}, # Out of window
        {"recipient_id": 3, "start_time": "11:00", "end_time": "13:00", "paused": False}, # Active
        {"recipient_id": 4, "start_time": "00:00", "end_time": "23:59", "paused": False}, # Active
        {"recipient_id": 5, "paused": False}, # Active (default time window)
    ]
    recipients_map = {
        1: {"email": "paused@example.com", "pincode": "201305"},
        2: {"email": "out_of_window@example.com", "pincode": "201305"},
        3: {"email": "active1@example.com", "pincode": "201305"},
        4: {"email": "active2@example.com", "pincode": "201305"},
        5: {"email": "active_default@example.com", "pincode": "201305"},
    }
    current_time = dt_time(12, 0) # For 12:00 PM

    results, count = await notifications_util.notify_users(
        "Test Product", "http://example.com/product", subscriptions, recipients_map, current_time, "201305"
    )

    assert count == 3 # active1, active2, active_default
    assert len(results) == 5

    expected_statuses = {
        "paused@example.com": "Skipped - Paused", # Corrected expected status
        "out_of_window@example.com": "Skipped - Subscription Not Due", # Corrected based on code logic
        "active1@example.com": "Sent",
        "active2@example.com": "Sent",
        "active_default@example.com": "Sent",
    }
    for result in results:
        assert result["status"] == expected_statuses[result["user_email"]]

    assert "active1@example.com" in mock_sent_emails
    assert "active2@example.com" in mock_sent_emails
    assert "active_default@example.com" in mock_sent_emails
    assert "paused@example.com" not in mock_sent_emails
    assert "out_of_window@example.com" not in mock_sent_emails


@pytest.mark.asyncio
async def test_main_load_recipients_empty(monkeypatch):
    """Test main when load_recipients returns an empty map."""
    async def mock_load_recipients(session):
        return {}
    monkeypatch.setattr(api_utils, "load_recipients", mock_load_recipients)
    
    monkeypatch.setattr(check_stock.config, "ADMIN_TOKEN", "tok")

    # Mock other dependencies to prevent actual calls
    async def mock_load_products_generic(session): return [{"id": 1, "name": "Prod", "url": "url"}]
    monkeypatch.setattr(api_utils, "load_products", mock_load_products_generic)
    async def mock_process_product_generic(s, p, pi, rm, ct, sp, subs, pin):
        return (None, 0, False)  # Ensure this is async
    monkeypatch.setattr(check_stock, "process_product", mock_process_product_generic)
    monkeypatch.setattr(check_stock.config, "APP_BASE_URL", "http://fakeapi")

    # Mock playwright context for main
    class MockBrowser:
        async def new_page(self): return MockPage()
        async def close(self): pass
    class MockPage: # Dummy page, no methods needed if process_product is fully mocked
        pass
    class MockPlaywright:
        def __init__(self): self.chromium = self
        async def launch(self, **kwargs): return MockBrowser()
        async def __aenter__(self): return self
        async def __aexit__(self, exc_type, exc, tb): pass
    monkeypatch.setattr(check_stock, "async_playwright", lambda: MockPlaywright())

    # Capture print output
    from io import StringIO
    import sys
    old_stdout = sys.stdout
    sys.stdout = captured_output = StringIO()

    await check_stock.main()

    sys.stdout = old_stdout # Restore stdout
    output = captured_output.getvalue()
    assert "No recipients found. Notifications may not be sent." in output
    assert "Stock check finished." in output # Check that it didn't exit early


@pytest.mark.asyncio
async def test_main_load_products_none(monkeypatch):
    """Test main when load_products returns None."""
    async def mock_load_products(session):
        return None
    monkeypatch.setattr(api_utils, "load_products", mock_load_products)
    async def mock_load_recipients_for_main(session):
        return {1: {"email": "test@example.com", "pincode": "201305"}}
    monkeypatch.setattr(api_utils, "load_recipients", mock_load_recipients_for_main)
    monkeypatch.setattr(check_stock.config, "APP_BASE_URL", "http://fakeapi")
    monkeypatch.setattr(check_stock.config, "ADMIN_TOKEN", "tok")

    from io import StringIO
    import sys
    old_stdout = sys.stdout
    sys.stdout = captured_output = StringIO()

    await check_stock.main()

    sys.stdout = old_stdout
    output = captured_output.getvalue()
    assert "No products fetched from API. Exiting." in output # Corrected assertion


@pytest.mark.asyncio
async def test_main_load_products_empty_list(monkeypatch):
    """Test main when load_products returns an empty list."""
    async def mock_load_products(session):
        return []
    monkeypatch.setattr(api_utils, "load_products", mock_load_products)
    async def mock_load_recipients_for_main(session):
        return {1: {"email": "test@example.com", "pincode": "201305"}}
    monkeypatch.setattr(api_utils, "load_recipients", mock_load_recipients_for_main)
    monkeypatch.setattr(check_stock.config, "APP_BASE_URL", "http://fakeapi")

    from io import StringIO
    import sys
    old_stdout = sys.stdout
    sys.stdout = captured_output = StringIO()

    await check_stock.main()

    sys.stdout = old_stdout
    output = captured_output.getvalue()
    assert "No products fetched from API. Exiting." in output # Corrected assertion


@pytest.mark.asyncio
async def test_main_summary_email_total_sent_positive(monkeypatch):
    """Test main summary email when total_sent > 0 and EMAIL_SENDER is set."""
    sent_summary_args = {}
    async def mock_send_summary(subject, body, sender, recipients, host, port, username, password): # Corrected signature
        sent_summary_args["subject"] = subject
        sent_summary_args["body"] = body
        sent_summary_args["sender_val"] = sender # Store actual sender
        sent_summary_args["recipients_val"] = recipients # Store actual recipients
    monkeypatch.setattr(notifications_module, "send_email_notification", mock_send_summary)

    async def mock_load_recipients_for_main(session):
        return {1: {"email": "test@example.com", "pincode": "201305"}}
    monkeypatch.setattr(api_utils, "load_recipients", mock_load_recipients_for_main)
    async def mock_load_products_for_main(session): return [{"id": 1, "name": "Test Product", "url": "http://example.com"}]
    monkeypatch.setattr(api_utils, "load_products", mock_load_products_for_main)
    async def mock_load_subscriptions_for_main(session):
        return {1: [{"recipient_id": 1, "start_time": "00:00", "end_time": "23:59"}]}
    monkeypatch.setattr(api_utils, "load_subscriptions", mock_load_subscriptions_for_main)
    # Simulate process_product returning one sent notification
    async def mock_process_product_summary(session, page, product_info, recipients_map, current_time, skip_pincode, subs, pin):
        return {
            "product_id": product_info["id"],
            "product_name": "Test Product",
            "status": "In Stock",
            "subscriptions": [{"user_email": "test@example.com", "status": "Sent", "pincode": "201305"}],
        }, 1, False
    monkeypatch.setattr(check_stock, "process_product", mock_process_product_summary)

    monkeypatch.setattr(check_stock.config, "EMAIL_SENDER", "sender@example.com")
    monkeypatch.setattr(check_stock.config, "EMAIL_HOST", "smtp.example.com")
    monkeypatch.setattr(check_stock.config, "EMAIL_PORT", 587)
    monkeypatch.setattr(check_stock.config, "EMAIL_HOST_USER", "user")
    monkeypatch.setattr(check_stock.config, "EMAIL_HOST_PASSWORD", "pass")
    # monkeypatch.setattr(check_stock.config, "SUMMARY_EMAIL_RECIPIENT", "summary@example.com") # Removed - summary sent to EMAIL_SENDER
    monkeypatch.setattr(check_stock.config, "APP_BASE_URL", "http://fakeapi")
    monkeypatch.setattr(check_stock.config, "ADMIN_TOKEN", "tok")

    # Mock playwright context for main
    class MockBrowser:
        async def new_page(self): return MockPage()
        async def close(self): pass
    class MockPage:
        pass
    class MockPlaywright:
        def __init__(self): self.chromium = self
        async def launch(self, **kwargs): return MockBrowser()
        async def __aenter__(self): return self
        async def __aexit__(self, exc_type, exc, tb): pass
    monkeypatch.setattr(check_stock, "async_playwright", lambda: MockPlaywright())

    await check_stock.main()

    email_sender_in_test = "sender@example.com" # Must match what's set in config by monkeypatch
    assert sent_summary_args.get("recipients_val") == [email_sender_in_test]
    assert "Stock Check Summary" in sent_summary_args.get("subject", "") # Corrected substring
    assert "Total User Notifications Sent:</strong> 1" in sent_summary_args.get("body", "") # More specific HTML check
    assert "Test Product" in sent_summary_args.get("body", "")


@pytest.mark.asyncio
async def test_main_summary_email_total_sent_zero(monkeypatch):
    """Test main summary email when total_sent == 0."""
    sent_summary_args = {}
    mock_send_email_called = False
    async def mock_send_summary(*args, **kwargs): # Signature doesn't matter as much if not called
        nonlocal mock_send_email_called
        mock_send_email_called = True
    monkeypatch.setattr(notifications_module, "send_email_notification", mock_send_summary)

    async def mock_load_recipients_for_main(session):
        return {1: {"email": "test@example.com", "pincode": "201305"}}
    monkeypatch.setattr(api_utils, "load_recipients", mock_load_recipients_for_main)
    async def mock_load_products_for_main(session): return [{"id": 1, "name": "Test Product", "url": "http://example.com"}] # Ensure async mock
    monkeypatch.setattr(api_utils, "load_products", mock_load_products_for_main)
    async def mock_process_product_summary(session, page, product_info, recipients_map, current_time, skip_pincode, subs, pin):  # Ensure async mock
        return {
            "product_id": product_info["id"],
            "product_name": "Test Product",
            "status": "Out of Stock",
            "subscriptions": [{"user_email": "test@example.com", "status": "Not Sent", "pincode": "201305"}],
        }, 0, False
    monkeypatch.setattr(check_stock, "process_product", mock_process_product_summary)

    monkeypatch.setattr(check_stock.config, "EMAIL_SENDER", "sender@example.com")
    monkeypatch.setattr(check_stock.config, "EMAIL_HOST", "smtp.example.com")
    monkeypatch.setattr(check_stock.config, "EMAIL_PORT", 587)
    monkeypatch.setattr(check_stock.config, "EMAIL_HOST_USER", "user")
    monkeypatch.setattr(check_stock.config, "EMAIL_HOST_PASSWORD", "pass")
    monkeypatch.setattr(check_stock.config, "APP_BASE_URL", "http://fakeapi")
    monkeypatch.setattr(check_stock.config, "ADMIN_TOKEN", "tok")

    # Mock playwright context for main
    class MockBrowser:
        async def new_page(self): return MockPage()
        async def close(self): pass
    class MockPage:
        pass
    class MockPlaywright:
        def __init__(self): self.chromium = self
        async def launch(self, **kwargs): return MockBrowser()
        async def __aenter__(self): return self
        async def __aexit__(self, exc_type, exc, tb): pass
    monkeypatch.setattr(check_stock, "async_playwright", lambda: MockPlaywright())

    # Capture print output
    from io import StringIO
    import sys
    old_stdout = sys.stdout
    sys.stdout = captured_output = StringIO()

    await check_stock.main()

    sys.stdout = old_stdout
    output = captured_output.getvalue()

    assert not mock_send_email_called # ಮುಖ್ಯವಾಗಿ, ইমেইল পাঠানো উচিত নয়
    assert "No user notifications were sent. Skipping summary email." in output


@pytest.mark.asyncio
async def test_main_summary_email_sender_not_set(monkeypatch):
    """Test main summary email when EMAIL_SENDER is not set."""
    # This will also test if SUMMARY_EMAIL_RECIPIENT is not set, as send_email_notification won't be called
    mock_send_email_called = False
    async def mock_send_summary(*args, **kwargs):
        nonlocal mock_send_email_called
        mock_send_email_called = True
    monkeypatch.setattr(notifications_module, "send_email_notification", mock_send_summary)

    async def mock_load_recipients_for_main(session):
        return {1: {"email": "test@example.com", "pincode": "201305"}}
    monkeypatch.setattr(api_utils, "load_recipients", mock_load_recipients_for_main)
    async def mock_load_products_for_main(session): return [{"id": 1, "name": "Test Product", "url": "http://example.com"}]
    monkeypatch.setattr(api_utils, "load_products", mock_load_products_for_main)
    async def mock_load_subscriptions_for_main(session):
        return {1: [{"recipient_id": 1, "start_time": "00:00", "end_time": "23:59"}]}
    monkeypatch.setattr(api_utils, "load_subscriptions", mock_load_subscriptions_for_main)
    # Ensure total_sent > 0 so summary sending is attempted
    async def mock_process_product_generic(s, p, pi, rm, ct, sp, subs, pin):
        return (
            {
                "product_id": pi["id"],
                "product_name": "Test Product",
                "status": "In Stock",
                "subscriptions": [{"user_email": "x@x.com", "status": "Sent", "pincode": "201305"}],
            },
            1,
            False,
        )
    monkeypatch.setattr(check_stock, "process_product", mock_process_product_generic)

    monkeypatch.setattr(check_stock.config, "EMAIL_SENDER", None)
    monkeypatch.setattr(check_stock.config, "APP_BASE_URL", "http://fakeapi")
    monkeypatch.setattr(check_stock.config, "ADMIN_TOKEN", "tok")

    # Mock playwright context for main
    class MockBrowser:
        async def new_page(self): return MockPage()
        async def close(self): pass
    class MockPage:
        pass
    class MockPlaywright:
        def __init__(self): self.chromium = self
        async def launch(self, **kwargs): return MockBrowser()
        async def __aenter__(self): return self
        async def __aexit__(self, exc_type, exc, tb): pass
    monkeypatch.setattr(check_stock, "async_playwright", lambda: MockPlaywright())

    # Capture print output
    from io import StringIO
    import sys
    old_stdout = sys.stdout
    sys.stdout = captured_output = StringIO()

    await check_stock.main()

    sys.stdout = old_stdout
    output = captured_output.getvalue()

    assert not mock_send_email_called
    assert "Email sender or host not configured, cannot send summary email." in output


@pytest.mark.asyncio
async def test_main_summary_email_exception(monkeypatch):
    """Test main when send_email_notification for summary email raises an exception."""
    async def mock_send_summary_raises_exception(*args, **kwargs):
        raise Exception("SMTP Summary Error")
    monkeypatch.setattr(notifications_module, "send_email_notification", mock_send_summary_raises_exception)

    async def mock_load_recipients_for_main(session):
        return {1: {"email": "test@example.com", "pincode": "201305"}}
    monkeypatch.setattr(api_utils, "load_recipients", mock_load_recipients_for_main)
    async def mock_load_products_for_main(session): return [{"id": 1, "name": "Test Product", "url": "http://example.com"}]
    monkeypatch.setattr(api_utils, "load_products", mock_load_products_for_main)
    async def mock_load_subscriptions_for_main(session):
        return {1: [{"recipient_id": 1, "start_time": "00:00", "end_time": "23:59"}]}
    monkeypatch.setattr(api_utils, "load_subscriptions", mock_load_subscriptions_for_main)
    # Ensure total_sent > 0 for exception path to be tested
    async def mock_process_product_generic(s, p, pi, rm, ct, sp, subs, pin):
        return (
            {
                "product_id": pi["id"],
                "product_name": "Test Product",
                "status": "In Stock",
                "subscriptions": [{"user_email": "x@x.com", "status": "Sent", "pincode": "201305"}],
            },
            1,
            False,
        )
    monkeypatch.setattr(check_stock, "process_product", mock_process_product_generic)

    monkeypatch.setattr(check_stock.config, "EMAIL_SENDER", "sender@example.com")
    monkeypatch.setattr(check_stock.config, "EMAIL_HOST", "smtp.example.com")
    monkeypatch.setattr(check_stock.config, "EMAIL_PORT", 587)
    monkeypatch.setattr(check_stock.config, "EMAIL_HOST_USER", "user")
    monkeypatch.setattr(check_stock.config, "EMAIL_HOST_PASSWORD", "pass")
    monkeypatch.setattr(check_stock.config, "APP_BASE_URL", "http://fakeapi")

    # Mock playwright context for main
    class MockBrowser:
        async def new_page(self): return MockPage()
        async def close(self): pass
    class MockPage:
        pass
    class MockPlaywright:
        def __init__(self): self.chromium = self
        async def launch(self, **kwargs): return MockBrowser()
        async def __aenter__(self): return self
        async def __aexit__(self, exc_type, exc, tb): pass
    monkeypatch.setattr(check_stock, "async_playwright", lambda: MockPlaywright())

    # Capture print output
    from io import StringIO
    import sys
    old_stdout = sys.stdout
    sys.stdout = captured_output = StringIO()

    await check_stock.main()

    sys.stdout = old_stdout
    output = captured_output.getvalue()

    assert "Error sending summary email: SMTP Summary Error" in output


def test_within_time_window_simple():
    now = dt_time(12, 0)
    assert stock_utils.within_time_window("10:00", "13:00", now)
    assert not stock_utils.within_time_window("13:01", "14:00", now)
    assert stock_utils.within_time_window("23:00", "01:00", dt_time(23, 30))


def test_filter_active_subs():
    now = dt_time(9, 0)
    subs = [
        {"paused": True},
        {"start_time": "08:00", "end_time": "10:00"},
        {"start_time": "10:00", "end_time": "12:00"},
    ]
    active = stock_utils.filter_active_subs(subs, now)
    assert len(active) == 1


def test_build_subs_by_pincode():
    recipients = {
        1: {"email": "a@example.com", "pincode": "111"},
        2: {"email": "b@example.com", "pincode": "222"},
    }
    sub_a = {"recipient_id": 1, "product_id": 10}
    sub_b = {"recipient_id": 2, "product_id": 10}
    sub_c = {"recipient_id": 1, "product_id": 20}
    subs_map = {10: [sub_a, sub_b], 20: [sub_c, {"recipient_id": 3}]}
    result = stock_utils.build_subs_by_pincode(recipients, subs_map)
    assert result == {
        "111": {10: [sub_a], 20: [sub_c]},
        "222": {10: [sub_b]},
    }


def test_aggregate_product_summaries():
    summaries = [
        {
            "product_id": 1,
            "product_name": "ProdA",
            "product_url": "http://a",
            "consecutive_in_stock": 1,
            "subscriptions": [{"user_email": "a@x", "status": "Sent", "pincode": "111"}],
        },
        {
            "product_id": 1,
            "product_name": "ProdA",
            "product_url": "http://a",
            "consecutive_in_stock": 1,
            "subscriptions": [{"user_email": "b@x", "status": "Sent", "pincode": "222"}],
        },
        {
            "product_id": 2,
            "product_name": "ProdB",
            "product_url": "http://b",
            "consecutive_in_stock": 1,
            "subscriptions": [{"user_email": "c@x", "status": "Sent", "pincode": "333"}],
        },
    ]
    result = stock_utils.aggregate_product_summaries(summaries)
    assert len(result) == 3
    combo_keys = {(r["product_id"], r["pincode"]) for r in result}
    assert combo_keys == {(1, "111"), (1, "222"), (2, "333")}


def test_aggregate_product_summaries_streaks_per_pin():
    summaries = [
        {
            "product_id": 1,
            "product_name": "ProdA",
            "product_url": "http://a",
            "pincode": "111",
            "consecutive_in_stock": 2,
            "subscriptions": [],
        },
        {
            "product_id": 1,
            "product_name": "ProdA",
            "product_url": "http://a",
            "pincode": "222",
            "consecutive_in_stock": 5,
            "subscriptions": [],
        },
    ]
    result = stock_utils.aggregate_product_summaries(summaries)
    streak_map = {
        (r["product_id"], r["pincode"]): r["consecutive_in_stock"] for r in result
    }
    assert streak_map[(1, "111")] == 2
    assert streak_map[(1, "222")] == 5


async def _run_notify_users(monkeypatch):
    sent_args = {}

    async def dummy_send_email(*args, **kwargs): # Made async
        sent_args["called"] = True

    monkeypatch.setattr(notifications, "send_email_notification", dummy_send_email)
    monkeypatch.setattr(config, "EMAIL_HOST", "smtp")
    monkeypatch.setattr(config, "EMAIL_SENDER", "sender@example.com")
    monkeypatch.setattr(config, "EMAIL_PORT", 587)
    monkeypatch.setattr(config, "EMAIL_HOST_USER", "")
    monkeypatch.setattr(config, "EMAIL_HOST_PASSWORD", "")
    subs = [{"recipient_id": 1, "start_time": "00:00", "end_time": "23:59"}]
    recipients = {1: {"email": "user@example.com", "pincode": "201305"}}
    result, count = await notifications_util.notify_users(
        "Prod", "url", subs, recipients, dt_time(12, 0), "201305"
    )
    return result, count, sent_args


def test_notify_users(monkeypatch):
    result, count, sent = asyncio.run(_run_notify_users(monkeypatch))
    assert count == 1
    assert sent.get("called")
    assert result[0]["status"] == "Sent"


def test_within_time_window_invalid():
    now = dt_time(12, 0)
    # Invalid time strings should default to True
    assert stock_utils.within_time_window("bad", "time", now)


def test_process_product_missing_data():
    summary, sent, pin = asyncio.run(
        product_checker.process_product(
            None,
            None,
            {"name": "NoID"},
            {},
            dt_time(12, 0),
            False,
            {},
            "201305",
        )
    )
    assert summary is None
    assert sent == 0
    assert not pin


def test_process_product_out_of_stock(monkeypatch):

    async def fake_check(url, pin, page=None, skip_pincode=False, log_prefix=""):
        return False, "Scraped"

    monkeypatch.setattr(scraper_module, "check_product_availability", fake_check)
    recipients = {1: {"email": "u@example.com", "pincode": "201305"}}
    subs_map = {1: [{"recipient_id": 1}]}
    summary, sent, pin = asyncio.run(
        product_checker.process_product(
            None,
            object(),
            {"id": 1, "url": "http://x", "name": "Prod"},
            recipients,
            dt_time(12, 0),
            False,
            subs_map,
            "201305",
        )
    )
    assert sent == 0
    assert summary["product_name"] == "Scraped"
    assert summary["subscriptions"][0]["status"] == "Not Sent - Out of Stock"
    assert pin


def test_process_product_in_stock(monkeypatch):

    async def fake_notify(*a, **k):
        return ([{"user_email": "u@example.com", "status": "Sent"}], 1)

    monkeypatch.setattr(product_checker, "notify_users", fake_notify)

    async def fake_check(url, pin, page=None, skip_pincode=False, log_prefix=""):
        return True, "New"

    monkeypatch.setattr(scraper_module, "check_product_availability", fake_check)
    recipients = {1: {"email": "u@example.com", "pincode": "201305"}}
    subs_map = {1: [{"recipient_id": 1}]}
    summary, sent, pin = asyncio.run(
        product_checker.process_product(
            None,
            object(),
            {"id": 1, "url": "http://x", "name": "Prod"},
            recipients,
            dt_time(12, 0),
            False,
            subs_map,
            "201305",
        )
    )
    assert sent == 1
    assert summary["product_name"] == "New"
    assert summary["subscriptions"][0]["status"] == "Sent"
    assert pin


@pytest.mark.asyncio
async def test_main_parallel_page_checks(monkeypatch):
    monkeypatch.setattr(check_stock.config, "APP_BASE_URL", "http://fakeapi")
    monkeypatch.setattr(check_stock.config, "MAX_PARALLEL_PAGE_CHECKS", 2)
    monkeypatch.setattr(check_stock.config, "EMAIL_HOST", None)
    monkeypatch.setattr(check_stock.config, "EMAIL_SENDER", None)
    monkeypatch.setattr(check_stock.config, "ADMIN_TOKEN", "tok")

    async def mock_load_recipients(session):
        return {1: {"email": "test@example.com", "pincode": "201305"}}

    async def mock_load_products(session):
        return [
            {"id": 1, "name": "P1", "url": "http://p1"},
            {"id": 2, "name": "P2", "url": "http://p2"},
            {"id": 3, "name": "P3", "url": "http://p3"},
        ]

    async def mock_load_subscriptions(session):
        return {
            1: [{"recipient_id": 1}],
            2: [{"recipient_id": 1}],
            3: [{"recipient_id": 1}],
        }

    monkeypatch.setattr(api_utils, "load_recipients", mock_load_recipients)
    monkeypatch.setattr(api_utils, "load_products", mock_load_products)
    monkeypatch.setattr(api_utils, "load_subscriptions", mock_load_subscriptions)
    async def mock_load_stock_counters(session):
        return {}

    async def mock_save_stock_counters(session, counters):
        pass

    monkeypatch.setattr(api_utils, "load_stock_counters", mock_load_stock_counters)
    monkeypatch.setattr(api_utils, "save_stock_counters", mock_save_stock_counters)

    skip_args = []

    async def mock_process_product(
        session,
        page,
        product_info,
        recipients_map,
        current_time,
        skip_pin,
        subs_map,
        pincode,
    ):
        skip_args.append(skip_pin)
        await asyncio.sleep(0.2)
        return (
            {
                "product_id": product_info["id"],
                "product_name": product_info["name"],
                "product_url": product_info["url"],
                "pincode": pincode,
                "subscriptions": [],
            },
            0,
            True,
        )

    monkeypatch.setattr(check_stock, "process_product", mock_process_product)

    class MockBrowser:
        async def new_page(self):
            return MockPage()

        async def close(self):
            pass

    class MockPage:
        async def close(self):
            pass

    class MockPlaywright:
        def __init__(self):
            self.chromium = self

        async def launch(self, **kwargs):
            return MockBrowser()

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            pass

    monkeypatch.setattr(check_stock, "async_playwright", lambda: MockPlaywright())

    start = time.perf_counter()
    await check_stock.main()
    elapsed = time.perf_counter() - start

    assert elapsed < 0.55
    assert skip_args[0] is False
    assert any(arg is True for arg in skip_args[1:])
