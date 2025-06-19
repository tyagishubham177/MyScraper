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


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
