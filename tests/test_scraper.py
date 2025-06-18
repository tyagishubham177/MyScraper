import asyncio
import sys
import types

# Stub playwright module to avoid dependency during import
playwright_module = types.ModuleType('playwright')
async_api = types.ModuleType('playwright.async_api')
async_api.async_playwright = lambda: None
async_api.Page = object
playwright_module.async_api = async_api
sys.modules.setdefault('playwright', playwright_module)
sys.modules.setdefault('playwright.async_api', async_api)

from scripts import scraper


class DummyPage:
    pass


async def dummy_checker(page, url, pincode, skip):
    return True, 'Dummy'

def test_check_product_availability_with_page(monkeypatch):
    called = {}

    async def fake(page, url, pincode, skip):
        called['args'] = (page, url, pincode, skip)
        return True, 'Dummy'

    monkeypatch.setattr(scraper, '_check_availability_on_page', fake)
    page = DummyPage()
    result = asyncio.run(scraper.check_product_availability('http://x', '123', page=page, skip_pincode=True))
    assert result == (True, 'Dummy')
    assert called['args'] == (page, 'http://x', '123', True)
