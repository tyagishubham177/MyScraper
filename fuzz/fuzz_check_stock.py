import os
import sys
import datetime

ROOT = os.path.dirname(os.path.dirname(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import atheris

with atheris.instrument_imports():
    from scripts import check_stock


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)

    start = fdp.ConsumeUnicodeNoSurrogates(5)
    end = fdp.ConsumeUnicodeNoSurrogates(5)
    hour = fdp.ConsumeIntInRange(0, 23)
    minute = fdp.ConsumeIntInRange(0, 59)
    now = datetime.time(hour, minute)

    check_stock.within_time_window(start, end, now)

    subs = []
    for _ in range(fdp.ConsumeIntInRange(0, 5)):
        sub = {}
        if fdp.ConsumeBool():
            sub["paused"] = fdp.ConsumeBool()
        if fdp.ConsumeBool():
            sub["start_time"] = fdp.ConsumeUnicodeNoSurrogates(5)
        if fdp.ConsumeBool():
            sub["end_time"] = fdp.ConsumeUnicodeNoSurrogates(5)
        subs.append(sub)

    check_stock.filter_active_subs(subs, now)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
