import asyncio
from datetime import time as dt_time
import pytest
import sys
import types

# Provide dummy modules for optional dependencies
sys.modules.setdefault("aiohttp", types.ModuleType("aiohttp"))
playwright_module = types.ModuleType("playwright")
playwright_async = types.ModuleType("playwright.async_api")
playwright_async.async_playwright = lambda: None
playwright_async.Page = object
playwright_module.async_api = playwright_async
sys.modules.setdefault("playwright", playwright_module)
sys.modules.setdefault("playwright.async_api", playwright_async)

import scripts.config as config_module

sys.modules.setdefault("config", config_module)
import scripts.notifications as notifications_module

sys.modules.setdefault("notifications", notifications_module)
import scripts.scraper as scraper_module

sys.modules.setdefault("scraper", scraper_module)

from scripts import check_stock, config, notifications


def test_within_time_window_simple():
    now = dt_time(12, 0)
    assert check_stock.within_time_window("10:00", "13:00", now)
    assert not check_stock.within_time_window("13:01", "14:00", now)
    assert check_stock.within_time_window("23:00", "01:00", dt_time(23, 30))


def test_filter_active_subs():
    now = dt_time(9, 0)
    subs = [
        {"paused": True},
        {"start_time": "08:00", "end_time": "10:00"},
        {"start_time": "10:00", "end_time": "12:00"},
    ]
    active = check_stock.filter_active_subs(subs, now)
    assert len(active) == 1


async def _run_notify_users(monkeypatch):
    sent_args = {}

    def dummy_send_email(*args, **kwargs):
        sent_args["called"] = True

    monkeypatch.setattr(notifications, "send_email_notification", dummy_send_email)
    monkeypatch.setattr(config, "EMAIL_HOST", "smtp")
    monkeypatch.setattr(config, "EMAIL_SENDER", "sender@example.com")
    monkeypatch.setattr(config, "EMAIL_PORT", 587)
    monkeypatch.setattr(config, "EMAIL_HOST_USER", "")
    monkeypatch.setattr(config, "EMAIL_HOST_PASSWORD", "")
    subs = [{"recipient_id": 1, "start_time": "00:00", "end_time": "23:59"}]
    recipients = {1: "user@example.com"}
    result, count = await check_stock.notify_users(
        "Prod", "url", subs, recipients, dt_time(12, 0)
    )
    return result, count, sent_args


def test_notify_users(monkeypatch):
    result, count, sent = asyncio.run(_run_notify_users(monkeypatch))
    assert count == 1
    assert sent.get("called")
    assert result[0]["status"] == "Sent"


def test_within_time_window_invalid():
    now = dt_time(12, 0)
    # Invalid time strings should default to True
    assert check_stock.within_time_window("bad", "time", now)


def test_process_product_missing_data():
    summary, sent, pin = asyncio.run(
        check_stock.process_product(
            None, None, {"name": "NoID"}, {}, dt_time(12, 0), False
        )
    )
    assert summary is None
    assert sent == 0
    assert not pin


def test_process_product_out_of_stock(monkeypatch):
    async def fake_fetch(session, pid):
        return [{"recipient_id": 1}]

    monkeypatch.setattr(check_stock, "fetch_subscriptions", fake_fetch)
    monkeypatch.setattr(check_stock, "filter_active_subs", lambda subs, ct: subs)

    async def fake_check(url, pin, page=None, skip_pincode=False):
        return False, "Scraped"

    monkeypatch.setattr(scraper_module, "check_product_availability", fake_check)
    recipients = {1: "u@example.com"}
    summary, sent, pin = asyncio.run(
        check_stock.process_product(
            None,
            object(),
            {"id": 1, "url": "http://x", "name": "Prod"},
            recipients,
            dt_time(12, 0),
            False,
        )
    )
    assert sent == 0
    assert summary["product_name"] == "Scraped"
    assert summary["subscriptions"][0]["status"] == "Not Sent - Out of Stock"
    assert pin


def test_process_product_in_stock(monkeypatch):
    async def fake_fetch(session, pid):
        return [{"recipient_id": 1}]

    monkeypatch.setattr(check_stock, "fetch_subscriptions", fake_fetch)
    monkeypatch.setattr(check_stock, "filter_active_subs", lambda subs, ct: subs)

    async def fake_notify(*a, **k):
        return ([{"user_email": "u@example.com", "status": "Sent"}], 1)

    monkeypatch.setattr(check_stock, "notify_users", fake_notify)

    async def fake_check(url, pin, page=None, skip_pincode=False):
        return True, "New"

    monkeypatch.setattr(scraper_module, "check_product_availability", fake_check)
    recipients = {1: "u@example.com"}
    summary, sent, pin = asyncio.run(
        check_stock.process_product(
            None,
            object(),
            {"id": 1, "url": "http://x", "name": "Prod"},
            recipients,
            dt_time(12, 0),
            False,
        )
    )
    assert sent == 1
    assert summary["product_name"] == "New"
    assert summary["subscriptions"][0]["status"] == "Sent"
    assert pin
