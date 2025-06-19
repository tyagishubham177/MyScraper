import sys
from datetime import time as dt_time

import atheris

with atheris.instrument_imports():
    from scripts import check_stock


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    start = fdp.ConsumeUnicodeNoSurrogates(5)
    end = fdp.ConsumeUnicodeNoSurrogates(5)
    now = dt_time(fdp.ConsumeIntInRange(0, 23), fdp.ConsumeIntInRange(0, 59))
    check_stock.within_time_window(start, end, now)

    subs = []
    for _ in range(fdp.ConsumeIntInRange(0, 5)):
        subs.append({
            "start_time": fdp.ConsumeUnicodeNoSurrogates(5),
            "end_time": fdp.ConsumeUnicodeNoSurrogates(5),
            "paused": fdp.ConsumeBool(),
        })
    check_stock.filter_active_subs(subs, now)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
