import os
import sys
import importlib

ROOT = os.path.dirname(os.path.dirname(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import atheris

with atheris.instrument_imports():
    import scripts.config as config


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)

    os.environ["PINCODE"] = fdp.ConsumeUnicodeNoSurrogates(10)
    os.environ["EMAIL_PORT"] = str(fdp.ConsumeInt(0, 65535))
    os.environ["EMAIL_HOST"] = fdp.ConsumeUnicodeNoSurrogates(20)
    os.environ["EMAIL_SENDER"] = fdp.ConsumeUnicodeNoSurrogates(20)
    importlib.reload(config)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
