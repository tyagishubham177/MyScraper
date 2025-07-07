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

# Limit the number of simultaneously open browser pages per pincode
MAX_CONCURRENT_PAGES = 3
import config
import notifications
from notifications import format_summary_email_body
import scraper
from scripts import api_utils, stock_utils




async def notify_users(
    effective_name,
    product_url,
    subs,
    recipients_map,
    current_time,
    pincode,
):
    current_summary = []
    valid_emails = []
    for sub in subs:
        rid = sub.get("recipient_id")
        info = recipients_map.get(rid)
        email = info.get("email") if info else None
        pincode = info.get("pincode") if info else None
        start_t = sub.get("start_time", "00:00")
        end_t = sub.get("end_time", "23:59")

        if sub.get("paused"):
            status = "Skipped - Paused"
        elif not stock_utils.within_time_window(start_t, end_t, current_time):
            status = "Skipped - Subscription Not Due"
        elif email:
            valid_emails.append(email)
            status = "Sent"
        else:
            status = "Not Sent - Recipient Email Missing"

        current_summary.append(
            {"user_email": email or "Unknown", "status": status}
        )

    sent_count = 0
    if valid_emails and config.EMAIL_HOST and config.EMAIL_SENDER:
        try:
            await notifications.send_email_notification(
                subject=f"{effective_name.strip()} In Stock Alert!",
                body=notifications.format_long_message(effective_name, product_url),
                sender=config.EMAIL_SENDER,
                recipients=valid_emails,
                host=config.EMAIL_HOST,
                port=config.EMAIL_PORT,
                username=config.EMAIL_HOST_USER,
                password=config.EMAIL_HOST_PASSWORD,
            )
            print(f"📨 Email notifications sent for '{effective_name}'.")
            sent_count = len(valid_emails)
        except Exception as e:
            print(f"Error sending email for '{effective_name}': {e}")
            for summary in current_summary:
                if summary["status"] == "Sent":
                    summary["status"] = "Not Sent - Email Send Error"
    else:
        if valid_emails:
            print(f"Email configuration missing for '{effective_name}'.")
            for summary in current_summary:
                if summary["status"] == "Sent":
                    summary["status"] = "Not Sent - Email Config Missing"
    return current_summary, sent_count


async def process_product(
    session,
    page,
    product_info,
    recipients_map,
    current_time,
    pincode_entered,
    subs_map,
    pincode,
):
    product_id = product_info.get("id")
    product_url = product_info.get("url")
    product_name = product_info.get("name", "N/A")
    effective_name = product_name

    if not product_id or not product_url:
        print(f"Skipping product due to missing data: {product_info}")
        return None, 0, pincode_entered

    subs = subs_map.get(product_id)
    if not subs or not isinstance(subs, list):
        print(f"Could not fetch subscriptions for product ID {product_id}.")
        return (
            {
                "product_id": product_id,
                "product_name": effective_name,
                "product_url": product_url,
                "subscriptions": [
                    {"user_email": "N/A", "status": "Error fetching subscriptions", "pincode": None}
                ],
            },
            0,
            pincode_entered,
        )


    try:
        log_prefix = f"{pincode}|{product_id}"
        in_stock, scraped_name = await scraper.check_product_availability(
            product_url,
            pincode,
            page=page,
            skip_pincode=pincode_entered,
            log_prefix=log_prefix,
        )
        if not pincode_entered:
            pincode_entered = True
        if scraped_name:
            effective_name = scraped_name
    except Exception as e:
        print(f"Error checking {product_url}: {e}")
        return (
            {
                "product_id": product_id,
                "product_name": effective_name,
                "product_url": product_url,
                "subscriptions": [
                    {
                        "user_email": "N/A",
                        "status": f"Error checking product: {e}",
                        "pincode": None,
                    }
                ],
            },
            0,
            pincode_entered,
        )

    if in_stock:
        print(f"✅ Product '{effective_name}' is IN STOCK.")
        current_summary, sent_count = await notify_users(
            effective_name,
            product_url,
            subs,
            recipients_map,
            current_time,
            pincode,
        )
    else:
        print(f"❌ Product '{effective_name}' is OUT OF STOCK.")
        current_summary = []
        for sub in subs:
            rid = sub.get("recipient_id")
            info = recipients_map.get(rid)
            email = info.get("email") if info else "Email not found"
            pin = info.get("pincode") if info else None
            current_summary.append(
                {"user_email": email, "status": "Not Sent - Out of Stock"}
            )
        sent_count = 0

    return (
        {
            "product_id": product_id,
            "product_name": effective_name,
            "product_url": product_url,
            "pincode": pincode,
            "subscriptions": current_summary,
            "in_stock": bool(in_stock),
        },
        sent_count,
        pincode_entered,
    )


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

        recipients_map = await stock_utils._timed(
            "Load recipients", api_utils.load_recipients(session), timings
        )
        if not recipients_map:
            print("No recipients found. Notifications may not be sent.")

        all_products = await stock_utils._timed(
            "Load products", api_utils.load_products(session), timings
        )
        if not all_products:
            print("No products fetched from API. Exiting.")
            return

        subs_map = await stock_utils._timed(
            "Load subscriptions", api_utils.load_subscriptions(session), timings
        )
        subs_by_pin = stock_utils.build_subs_by_pincode(recipients_map, subs_map)
        product_map = {p.get("id"): p for p in all_products if p.get("id")}
        subscribed_rids = {
            sub.get("recipient_id")
            for subs in subs_map.values()
            for sub in subs
            if sub.get("recipient_id") is not None
        }

        stock_counters = await stock_utils._timed(
            "Load stock counters", api_utils.load_stock_counters(session), timings
        )
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
                sem = asyncio.Semaphore(MAX_CONCURRENT_PAGES)

                async def handle_product(pid, product_subs):
                    product_info = product_map.get(pid)
                    if not product_info:
                        return None
                    async with sem:
                        page = await browser.new_page()
                        try:
                            summary, sent, _ = await process_product(
                                session,
                                page,
                                product_info,
                                recips_subset,
                                current_time,
                                False,
                                {pid: product_subs},
                                pincode,
                            )
                            return product_info, summary, sent
                        finally:
                            if hasattr(page, "close"):
                                close_fn = page.close
                                if inspect.iscoroutinefunction(close_fn):
                                    await close_fn()
                                else:
                                    close_fn()

                try:
                    subs_subset = {
                        pid: stock_utils.filter_active_subs(subs, current_time)
                        for pid, subs in subs_by_pin.get(pincode, {}).items()
                    }
                    tasks = [
                        asyncio.create_task(handle_product(pid, product_subs))
                        for pid, product_subs in subs_subset.items()
                    ]
                    for result in await asyncio.gather(*tasks):
                        if result:
                            results.append(result)
                finally:
                    pincode_stats.append({
                        "pincode": pincode,
                        "duration": time.perf_counter() - pin_start,
                        "products": len(results),
                    })
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
                        summary["consecutive_in_stock"] = stock_counters.get(key, 0)
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
