import os
import sys
import importlib

import atheris

with atheris.instrument_imports():
    from scripts import config


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    os.environ["EMAIL_PORT"] = fdp.ConsumeUnicodeNoSurrogates(5)
    os.environ["APP_BASE_URL"] = fdp.ConsumeUnicodeNoSurrogates(100)
    try:
        importlib.reload(config)
    except Exception:
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
