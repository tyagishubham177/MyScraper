import asyncio
import sys

import atheris

with atheris.instrument_imports():
    from scripts import scraper


class DummyElement:
    def __init__(self, fdp):
        self.fdp = fdp

    async def is_visible(self):
        return self.fdp.ConsumeBool()

    async def text_content(self):
        if self.fdp.ConsumeBool():
            return self.fdp.ConsumeUnicodeNoSurrogates(20)
        return None

    async def fill(self, text):
        return None

    async def click(self, selector=None):
        return None


class DummyPage:
    def __init__(self, fdp):
        self.fdp = fdp
        self.keyboard = self

    async def goto(self, url, timeout=60000):
        return None

    async def wait_for_load_state(self, state):
        return None

    async def query_selector(self, selector):
        if self.fdp.ConsumeBool():
            return DummyElement(self.fdp)
        return None

    async def press(self, key):
        return None

    async def screenshot(self, path):
        return None


class DummyBrowser:
    def __init__(self, fdp):
        self.fdp = fdp

    async def new_page(self):
        return DummyPage(self.fdp)

    async def close(self):
        return None


class DummyPlaywright:
    def __init__(self, fdp):
        self.fdp = fdp
        self.chromium = self

    async def launch(self, **kwargs):
        return DummyBrowser(self.fdp)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    url = "http://example.com/" + fdp.ConsumeUnicodeNoSurrogates(20)
    pincode = fdp.ConsumeUnicodeNoSurrogates(6)
    skip = fdp.ConsumeBool()

    scraper.async_playwright = lambda: DummyPlaywright(fdp)
    try:
        asyncio.run(scraper.check_product_availability(url, pincode, page=None, skip_pincode=skip))
    except Exception:
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
