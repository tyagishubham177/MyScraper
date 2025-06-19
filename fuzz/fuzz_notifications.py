import atheris
import sys

with atheris.instrument_imports():
    from scripts import notifications


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    product_name = fdp.ConsumeUnicodeNoSurrogates(50)
    url = fdp.ConsumeUnicodeNoSurrogates(100)
    notifications.format_long_message(product_name, url)
    notifications.format_short_message(product_name)


after_setup = atheris.Setup
atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
