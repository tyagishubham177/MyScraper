import os
import sys

ROOT = os.path.dirname(os.path.dirname(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import atheris

with atheris.instrument_imports():
    from scripts import notifications

def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    product_name = fdp.ConsumeUnicodeNoSurrogates(50)
    url = fdp.ConsumeUnicodeNoSurrogates(100)
    notifications.format_long_message(product_name, url)
    notifications.format_short_message(product_name)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
