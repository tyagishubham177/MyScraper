import asyncio
import inspect
import pytest

@pytest.hookimpl(tryfirst=True)
def pytest_pyfunc_call(pyfuncitem):
    marker = pyfuncitem.get_closest_marker("asyncio")
    if marker:
        func = pyfuncitem.obj
        if inspect.iscoroutinefunction(func):
            argnames = pyfuncitem._fixtureinfo.argnames
            args = [pyfuncitem.funcargs[name] for name in argnames]
            asyncio.run(func(*args))
            return True
    return None
