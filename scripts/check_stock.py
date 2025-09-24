import asyncio
from datetime import datetime, timezone, timedelta, time as dt_time
import inspect
import os
import sys
import time
import types
try:
    import aiohttp  # type: ignore
except Exception:  # pragma: no cover - fallback when aiohttp not installed
    aiohttp = types.SimpleNamespace()

# Allow running via `python scripts/check_stock.py`
if __package__ is None and __name__ == "__main__":
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))

try:
    from playwright.async_api import async_playwright
except Exception:  # pragma: no cover - fallback when playwright not installed
    playwright_module = types.ModuleType("playwright")
    playwright_async = types.ModuleType("playwright.async_api")

    async def async_playwright():
        raise RuntimeError("playwright not installed")

    playwright_async.async_playwright = async_playwright
    playwright_async.Page = object
    playwright_module.async_api = playwright_async
    sys.modules.setdefault("playwright", playwright_module)
    sys.modules.setdefault("playwright.async_api", playwright_async)

# Provide a minimal fallback ClientSession when aiohttp is not fully available
if not hasattr(aiohttp, "ClientSession"):
    class _DummyResponse:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            pass

        async def json(self):
            return {}

        def raise_for_status(self):
            pass

    class _DummyClientSession:
        def get(self, url, **kwargs):
            return _DummyResponse()

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            pass

    aiohttp.ClientSession = _DummyClientSession
import config
import notifications
from notifications import format_summary_email_body
import scraper
from scripts import api_utils, stock_utils
from scripts.notifications_util import notify_users
from scripts.product_checker import process_product






async def main():
    print("Starting stock check...")
    summary_email_data = []
    total_sent = 0
    timings: dict[str, float] = {}
    pincode_stats: list[dict] = []
    overall_start = time.perf_counter()

    async with aiohttp.ClientSession() as session:
        if not config.ADMIN_TOKEN:
            await stock_utils._timed("Admin login", api_utils.login_admin(session), timings)
        else:
            stock_utils._add_timing("Admin login", 0.0, timings)

        bundle = await stock_utils._timed(
            "Load configuration", api_utils.load_configuration_bundle(session), timings
        )

        if bundle:
            recipients_map, all_products, subs_map, stock_counters = bundle
        else:
            recipients_map = await stock_utils._timed(
                "Load recipients", api_utils.load_recipients(session), timings
            )
            all_products = await stock_utils._timed(
                "Load products", api_utils.load_products(session), timings
            )
            subs_map = await stock_utils._timed(
                "Load subscriptions", api_utils.load_subscriptions(session), timings
            )
            stock_counters = await stock_utils._timed(
                "Load stock counters", api_utils.load_stock_counters(session), timings
            )

        if not recipients_map:
            print("No recipients found. Notifications may not be sent.")

        if not all_products:
            print("No products fetched from API. Exiting.")
            return

        subs_by_pin = stock_utils.build_subs_by_pincode(recipients_map, subs_map)
        product_map = {p.get("id"): p for p in all_products if p.get("id")}
        subscribed_rids = {
            sub.get("recipient_id")
            for subs in subs_map.values()
            for sub in subs
            if sub.get("recipient_id") is not None
        }

        if not isinstance(stock_counters, dict):
            stock_counters = {}

        current_time = (
            datetime.now(timezone.utc) + timedelta(hours=5, minutes=30)
        ).time()

        # Only build groups for recipients that actually have active
        # subscriptions. This avoids spawning browser pages for pincodes
        # with no interested users.
        group_start = time.perf_counter()
        pincode_groups = {}
        for rid, info in recipients_map.items():
            if rid not in subscribed_rids:
                continue
            pin = info.get("pincode", config.PINCODE)
            pincode_groups.setdefault(pin, {})[rid] = info
        stock_utils._add_timing("Build pincode groups", time.perf_counter() - group_start, timings)

        async with async_playwright() as pw:
            launch_start = time.perf_counter()
            browser = await pw.chromium.launch(headless=True, args=["--no-sandbox"])
            stock_utils._add_timing("Launch browser", time.perf_counter() - launch_start, timings)

            async def process_pincode(pincode, recips_subset):
                pin_start = time.perf_counter()
                results = []
                pincode_entered = False
                pin_lock = asyncio.Lock()
                subs_subset = {
                    pid: stock_utils.filter_active_subs(subs, current_time)
                    for pid, subs in subs_by_pin.get(pincode, {}).items()
                }

                if hasattr(browser, "new_context"):
                    context = await browser.new_context()
                else:
                    context = browser
                semaphore = asyncio.Semaphore(config.MAX_PARALLEL_PAGE_CHECKS)

                async def handle_product(pid, product_subs):
                    nonlocal pincode_entered
                    product_info = product_map.get(pid)
                    if not product_info:
                        return None
                    async with semaphore:
                        page = await context.new_page()
                        try:
                            if not pincode_entered:
                                async with pin_lock:
                                    skip_pin = pincode_entered
                                    summary, sent, entered = await process_product(
                                        session,
                                        page,
                                        product_info,
                                        recips_subset,
                                        current_time,
                                        skip_pin,
                                        {pid: product_subs},
                                        pincode,
                                    )
                                    if entered and not pincode_entered:
                                        pincode_entered = True
                            else:
                                summary, sent, _ = await process_product(
                                    session,
                                    page,
                                    product_info,
                                    recips_subset,
                                    current_time,
                                    True,
                                    {pid: product_subs},
                                    pincode,
                                )
                        finally:
                            if hasattr(page, "close"):
                                close_fn = page.close
                                if inspect.iscoroutinefunction(close_fn):
                                    await close_fn()
                                else:
                                    close_fn()
                    return (product_info, summary, sent)

                try:
                    tasks = [handle_product(pid, subs) for pid, subs in subs_subset.items()]
                    gathered = await asyncio.gather(*tasks)
                    results = [r for r in gathered if r]
                finally:
                    pincode_stats.append({
                        "pincode": pincode,
                        "duration": time.perf_counter() - pin_start,
                        "products": len(results),
                    })
                    if context is not browser and hasattr(context, "close"):
                        await context.close()
                return results

            pincode_tasks = [
                process_pincode(pin, subset) for pin, subset in pincode_groups.items()
            ]

            pincode_results = await asyncio.gather(*pincode_tasks)

            for results in pincode_results:
                for product_info, summary, sent in results:
                    if summary:
                        pid = product_info.get("id")
                        pin = summary.get("pincode")
                        key = f"{pid}|{pin}"
                        if summary.get("in_stock"):
                            stock_counters[key] = stock_counters.get(key, 0) + 1
                        else:
                            stock_counters[key] = 0
                        streak = stock_counters.get(key, 0)
                        summary["consecutive_in_stock"] = streak
                        if streak > 20:
                            for sub in subs_map.get(pid, []):
                                rid = sub.get("recipient_id")
                                rec_pin = recipients_map.get(rid, {}).get(
                                    "pincode", config.PINCODE
                                )
                                if rec_pin != pin or sub.get("paused"):
                                    continue
                                await api_utils.update_subscription(
                                    session,
                                    rid,
                                    pid,
                                    sub.get("start_time", "00:00"),
                                    sub.get("end_time", "23:59"),
                                    True,
                                )
                                sub["paused"] = True
                                email = recipients_map.get(rid, {}).get("email")
                                if (
                                    email
                                    and config.EMAIL_HOST
                                    and config.EMAIL_SENDER
                                ):
                                    try:
                                        await notifications.send_email_notification(
                                            subject="Subscription Auto-Paused",
                                            body=notifications.format_auto_pause_message(
                                                product_info.get("name", "Product")
                                            ),
                                            sender=config.EMAIL_SENDER,
                                            recipients=[email],
                                            host=config.EMAIL_HOST,
                                            port=config.EMAIL_PORT,
                                            username=config.EMAIL_HOST_USER,
                                            password=config.EMAIL_HOST_PASSWORD,
                                        )
                                    except Exception as e:
                                        print(
                                            f"Error sending auto-pause email to {email}: {e}"
                                        )
                        summary_email_data.append(summary)
                    total_sent += sent

            close_start = time.perf_counter()
            await browser.close()
            stock_utils._add_timing("Close browser", time.perf_counter() - close_start, timings)

        print("\nStock check finished.")
        await api_utils.save_stock_counters(session, stock_counters)

    run_timestamp_utc = datetime.now(timezone.utc)
    ist_offset = timedelta(hours=5, minutes=30)
    run_timestamp_ist = run_timestamp_utc + ist_offset
    month_name = run_timestamp_ist.strftime("%B")
    run_timestamp_str = (
        run_timestamp_ist.strftime(f"%d-{month_name}-%Y / %I:%M%p") + ", IST"
    )
    aggregated_summary = stock_utils.aggregate_product_summaries(summary_email_data)
    subject = f"Stock Check Summary: {run_timestamp_str} - {total_sent} User Notifications Sent"
    summary_body = format_summary_email_body(
        run_timestamp_str, aggregated_summary, total_sent
    )

    if total_sent > 0:
        if (
            config.EMAIL_SENDER and config.EMAIL_HOST
        ):  # Also check EMAIL_HOST for sending
            try:
                await notifications.send_email_notification(  # Added await
                    subject=subject,
                    body=summary_body,
                    sender=config.EMAIL_SENDER,
                    recipients=[config.EMAIL_SENDER],  # Summary sent to self
                    host=config.EMAIL_HOST,
                    port=config.EMAIL_PORT,
                    username=config.EMAIL_HOST_USER,
                    password=config.EMAIL_HOST_PASSWORD,
                )
                print("✅ Summary email sent successfully.")
            except Exception as e:
                print(f"Error sending summary email: {e}")
        else:
            print("Email sender or host not configured, cannot send summary email.")
    else:
        print("No user notifications were sent. Skipping summary email.")

    stock_utils._add_timing("Total runtime", time.perf_counter() - overall_start, timings)
    stock_utils._print_summary(timings, pincode_stats)


if __name__ == "__main__":
    asyncio.run(main())
