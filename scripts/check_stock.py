import asyncio
from datetime import datetime, timezone, timedelta, time as dt_time
import inspect
import aiohttp

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
from playwright.async_api import async_playwright
import config
import notifications
from notifications import format_summary_email_body
import scraper


def within_time_window(start_str: str, end_str: str, now: dt_time) -> bool:
    fmt = "%H:%M"
    try:
        start = datetime.strptime(start_str, fmt).time()
        end = datetime.strptime(end_str, fmt).time()
    except Exception:
        return True
    if start <= end:
        return start <= now <= end
    return now >= start or now <= end


async def fetch_api_data(session, url, headers=None):
    try:
        async with session.get(url, headers=headers) as response:
            response.raise_for_status()
            return await response.json()
    except Exception as e:
        print(f"API request to {url} failed: {e}")
        return None


async def load_recipients(session):
    recipients_url = f"{config.APP_BASE_URL}/api/recipients"
    data = await fetch_api_data(session, recipients_url)
    return {
        r.get("id"): {
            "email": r.get("email"),
            "pincode": r.get("pincode", config.PINCODE),
        }
        for r in data or []
        if r.get("id") and r.get("email")
    }


async def load_products(session):
    products_url = f"{config.APP_BASE_URL}/api/products"
    return await fetch_api_data(session, products_url)


async def load_subscriptions(session):
    """Fetch all subscriptions and return a dict keyed by product_id."""
    subs_url = f"{config.APP_BASE_URL}/api/subscriptions"
    data = await fetch_api_data(session, subs_url)
    if not data or not isinstance(data, list):
        return {}
    subs_by_product = {}
    for sub in data:
        pid = sub.get("product_id")
        if pid is None:
            continue
        subs_by_product.setdefault(pid, []).append(sub)
    return subs_by_product


async def fetch_subscriptions(session, product_id):
    url = f"{config.APP_BASE_URL}/api/subscriptions?product_id={product_id}"
    return await fetch_api_data(session, url)


async def login_admin(session):
    """Fetch an admin token using the login API if credentials are provided."""
    email = getattr(config, "ADMIN_EMAIL", None)
    password = getattr(config, "ADMIN_PASSWORD", None)
    if not email or not password:
        print("Admin credentials not provided; skipping login.")
        return None

    url = f"{config.APP_BASE_URL}/api/login"
    try:
        async with session.post(
            url, json={"email": email, "password": password}
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                token = data.get("token")
                if token:
                    config.ADMIN_TOKEN = token
                    print("Admin login successful.")
                    return token
                print("Admin login returned no token")
            else:
                text = await resp.text()
                print(f"Admin login failed: {resp.status} {text}")
    except Exception as e:
        print(f"Admin login failed: {e}")
    return None


async def load_stock_counters(session):
    url = f"{config.APP_BASE_URL}/api/stock-counters"
    headers = (
        {"Authorization": f"Bearer {config.ADMIN_TOKEN}"}
        if config.ADMIN_TOKEN
        else None
    )
    data = await fetch_api_data(session, url, headers=headers)
    if isinstance(data, dict):
        converted = {}
        for key, val in data.items():
            if isinstance(key, str) and key.isdigit():
                converted[int(key)] = val
            else:
                converted[key] = val
        return converted
    return {}


async def save_stock_counters(session, counters):
    url = f"{config.APP_BASE_URL}/api/stock-counters"
    headers = (
        {"Authorization": f"Bearer {config.ADMIN_TOKEN}"}
        if config.ADMIN_TOKEN
        else None
    )
    try:
        async with session.put(
            url, json={"counters": counters}, headers=headers
        ) as resp:
            if resp.status == 401:
                print("Stock counter update unauthorized. Retrying after login.")
                await login_admin(session)
                headers = (
                    {"Authorization": f"Bearer {config.ADMIN_TOKEN}"}
                    if config.ADMIN_TOKEN
                    else None
                )
                async with session.put(
                    url, json={"counters": counters}, headers=headers
                ) as resp_retry:
                    if resp_retry.status >= 400:
                        text = await resp_retry.text()
                        raise Exception(f"{resp_retry.status}: {text}")
            elif resp.status >= 400:
                text = await resp.text()
                raise Exception(f"{resp.status}: {text}")
    except Exception as e:
        print(f"Failed to update stock counters: {e}")


def filter_active_subs(subs, current_time):
    active = []
    for sub in subs:
        if sub.get("paused"):
            continue
        start_t = sub.get("start_time", "00:00")
        end_t = sub.get("end_time", "23:59")
        if within_time_window(start_t, end_t, current_time):
            active.append(sub)
    return active


def aggregate_product_summaries(summary_items):
    """Combine summary entries per product and pincode."""
    aggregated = {}
    for item in summary_items:
        pid = item.get("product_id")
        if pid is None:
            continue
        item_pin = item.get("pincode")
        subs = item.get("subscriptions", [])
        if item_pin:
            key = (pid, item_pin)
            entry = aggregated.setdefault(
                key,
                {
                    "product_id": pid,
                    "pincode": item_pin,
                    "product_name": item.get("product_name"),
                    "product_url": item.get("product_url"),
                    "consecutive_in_stock": item.get("consecutive_in_stock", 0),
                    "subscriptions": [],
                },
            )
            entry["subscriptions"].extend(subs)
        else:
            for sub in subs:
                pin = sub.get("pincode")
                key = (pid, pin)
                entry = aggregated.setdefault(
                    key,
                    {
                        "product_id": pid,
                        "pincode": pin,
                        "product_name": item.get("product_name"),
                        "product_url": item.get("product_url"),
                        "consecutive_in_stock": item.get(
                            "consecutive_in_stock", 0
                        ),
                        "subscriptions": [],
                    },
                )
                entry["subscriptions"].append(sub)
    return list(aggregated.values())


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
        elif not within_time_window(start_t, end_t, current_time):
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

    subs = filter_active_subs(subs, current_time)
    if not subs:
        print(f"Skipping product '{effective_name}' - no active subscribers.")
        return (
            {
                "product_id": product_id,
                "product_name": effective_name,
                "product_url": product_url,
                "subscriptions": [
                    {"user_email": "N/A", "status": "Skipped - No Active Subscribers", "pincode": None}
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

    async with aiohttp.ClientSession() as session:
        if not config.ADMIN_TOKEN:
            await login_admin(session)
        recipients_map = await load_recipients(session)
        if not recipients_map:
            print("No recipients found. Notifications may not be sent.")

        all_products = await load_products(session)
        if not all_products:
            print("No products fetched from API. Exiting.")
            return

        subs_map = await load_subscriptions(session)

        stock_counters = await load_stock_counters(session)
        if not isinstance(stock_counters, dict):
            stock_counters = {}

        current_time = (
            datetime.now(timezone.utc) + timedelta(hours=5, minutes=30)
        ).time()

        pincode_groups = {}
        for rid, info in recipients_map.items():
            pin = info.get("pincode", config.PINCODE)
            pincode_groups.setdefault(pin, {})[rid] = info

        async with async_playwright() as pw:

            async def process_pincode(pincode, recips_subset):
                browser = await pw.chromium.launch(headless=True, args=["--no-sandbox"])
                page = await browser.new_page()
                entered = False
                results = []
                try:
                    for product_info in all_products:
                        pid = product_info.get("id")
                        subs = subs_map.get(pid)
                        if subs is not None:
                            filtered = [
                                s for s in subs if s.get("recipient_id") in recips_subset
                            ]
                            if not filter_active_subs(filtered, current_time):
                                continue
                        summary, sent, entered = await process_product(
                            session,
                            page,
                            product_info,
                            recips_subset,
                            current_time,
                            entered,
                            {
                                pid: [
                                    s
                                    for s in subs
                                    if s.get("recipient_id") in recips_subset
                                ]
                                for pid, subs in subs_map.items()
                            },
                            pincode,
                        )
                        results.append((product_info, summary, sent))
                finally:
                    if hasattr(page, "close"):
                        close_fn = page.close
                        if inspect.iscoroutinefunction(close_fn):
                            await close_fn()
                        else:
                            close_fn()
                    await browser.close()
                return results

            pincode_tasks = [
                process_pincode(pin, subset) for pin, subset in pincode_groups.items()
            ]

            pincode_results = await asyncio.gather(*pincode_tasks)

            for results in pincode_results:
                for product_info, summary, sent in results:
                    if summary:
                        pid = product_info.get("id")
                        if summary.get("in_stock"):
                            stock_counters[pid] = stock_counters.get(pid, 0) + 1
                        else:
                            stock_counters[pid] = 0
                        summary["consecutive_in_stock"] = stock_counters.get(pid, 0)
                        summary_email_data.append(summary)
                    total_sent += sent

        print("\nStock check finished.")
        await save_stock_counters(session, stock_counters)

    run_timestamp_utc = datetime.now(timezone.utc)
    ist_offset = timedelta(hours=5, minutes=30)
    run_timestamp_ist = run_timestamp_utc + ist_offset
    month_name = run_timestamp_ist.strftime("%B")
    run_timestamp_str = (
        run_timestamp_ist.strftime(f"%d-{month_name}-%Y / %I:%M%p") + ", IST"
    )
    aggregated_summary = aggregate_product_summaries(summary_email_data)
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


if __name__ == "__main__":
    asyncio.run(main())
