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

from scripts import scraper


class DummyPage:
    pass


async def dummy_checker(page, url, pincode, skip):
    return True, "Dummy"


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
