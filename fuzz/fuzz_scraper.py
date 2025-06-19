import os
import sys
import asyncio

ROOT = os.path.dirname(os.path.dirname(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import atheris

with atheris.instrument_imports():
    from scripts import scraper


class FakeElement:
    def __init__(self, visible: bool, text: str):
        self._visible = visible
        self._text = text

    async def is_visible(self):
        return self._visible

    async def text_content(self):
        return self._text

    async def fill(self, _):
        pass


class FakePage:
    def __init__(self, fdp: atheris.FuzzedDataProvider):
        self.fdp = fdp
        self.keyboard = self

    async def goto(self, *_args, **_kwargs):
        pass

    async def wait_for_load_state(self, *_args, **_kwargs):
        pass

    async def query_selector(self, _selector: str):
        if self.fdp.ConsumeBool():
            visible = self.fdp.ConsumeBool()
            text = self.fdp.ConsumeUnicodeNoSurrogates(20)
            return FakeElement(visible, text)
        return None

    async def wait_for_selector(self, _selector: str, timeout=0):
        if self.fdp.ConsumeBool():
            return None
        raise Exception("not found")

    async def click(self, _selector: str):
        pass

    async def press(self, _key: str):
        pass

    async def screenshot(self, path: str):
        # create empty file to simulate screenshot
        try:
            open(path, "wb").close()
        except Exception:
            pass


async def run_once(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    url = fdp.ConsumeUnicodeNoSurrogates(50)
    pincode = fdp.ConsumeUnicodeNoSurrogates(6)
    page = FakePage(fdp)
    skip = fdp.ConsumeBool()
    try:
        await scraper._check_availability_on_page(page, url, pincode, skip)
    except Exception:
        pass


def TestOneInput(data: bytes) -> None:
    asyncio.run(run_once(data))


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
