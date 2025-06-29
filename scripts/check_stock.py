import asyncio
from datetime import datetime, timezone, timedelta, time as dt_time
import aiohttp
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

async def fetch_api_data(session, url):
    try:
        async with session.get(url) as response:
            response.raise_for_status()
            return await response.json()
    except Exception as e:
        print(f"API request to {url} failed: {e}")
        return None


async def load_recipients(session):
    recipients_url = f"{config.APP_BASE_URL}/api/recipients"
    data = await fetch_api_data(session, recipients_url)
    return {r.get('id'): r.get('email') for r in data or [] if r.get('id') and r.get('email')}


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


def filter_active_subs(subs, current_time):
    active = []
    for sub in subs:
        if sub.get('paused'):
            continue
        start_t = sub.get('start_time', '00:00')
        end_t = sub.get('end_time', '23:59')
        if within_time_window(start_t, end_t, current_time):
            active.append(sub)
    return active


async def notify_users(effective_name, product_url, subs, recipients_map, current_time):
    current_summary = []
    valid_emails = []
    for sub in subs:
        rid = sub.get('recipient_id')
        email = recipients_map.get(rid)
        start_t = sub.get('start_time', '00:00')
        end_t = sub.get('end_time', '23:59')

        if sub.get('paused'):
            status = 'Skipped - Paused'
        elif not within_time_window(start_t, end_t, current_time):
            status = 'Skipped - Subscription Not Due'
        elif email:
            valid_emails.append(email)
            status = 'Sent'
        else:
            status = 'Not Sent - Recipient Email Missing'

        current_summary.append({'user_email': email or 'Unknown', 'status': status})

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
                password=config.EMAIL_HOST_PASSWORD
            )
            print(f"📨 Email notifications sent for '{effective_name}'.")
            sent_count = len(valid_emails)
        except Exception as e:
            print(f"Error sending email for '{effective_name}': {e}")
            for summary in current_summary:
                if summary['status'] == 'Sent':
                    summary['status'] = 'Not Sent - Email Send Error'
    else:
        if valid_emails:
            print(f"Email configuration missing for '{effective_name}'.")
            for summary in current_summary:
                if summary['status'] == 'Sent':
                    summary['status'] = 'Not Sent - Email Config Missing'
    return current_summary, sent_count


async def process_product(session, page, product_info, recipients_map, current_time, pincode_entered, subs_map):
    product_id = product_info.get('id')
    product_url = product_info.get('url')
    product_name = product_info.get('name', 'N/A')
    effective_name = product_name

    if not product_id or not product_url:
        print(f"Skipping product due to missing data: {product_info}")
        return None, 0, pincode_entered

    subs = subs_map.get(product_id)
    if not subs or not isinstance(subs, list):
        print(f"Could not fetch subscriptions for product ID {product_id}.")
        return {
            'product_name': effective_name,
            'product_url': product_url,
            'subscriptions': [{'user_email': 'N/A', 'status': 'Error fetching subscriptions'}]
        }, 0, pincode_entered

    subs = filter_active_subs(subs, current_time)
    if not subs:
        print(f"Skipping product '{effective_name}' - no active subscribers.")
        return {
            'product_name': effective_name,
            'product_url': product_url,
            'subscriptions': [{'user_email': 'N/A', 'status': 'Skipped - No Active Subscribers'}]
        }, 0, pincode_entered

    try:
        in_stock, scraped_name = await scraper.check_product_availability(
            product_url,
            config.PINCODE,
            page=page,
            skip_pincode=pincode_entered,
        )
        if not pincode_entered:
            pincode_entered = True
        if scraped_name:
            effective_name = scraped_name
    except Exception as e:
        print(f"Error checking {product_url}: {e}")
        return {
            'product_name': effective_name,
            'product_url': product_url,
            'subscriptions': [{'user_email': 'N/A', 'status': f'Error checking product: {e}'}]
        }, 0, pincode_entered

    if in_stock:
        print(f"✅ Product '{effective_name}' is IN STOCK.")
        current_summary, sent_count = await notify_users(effective_name, product_url, subs, recipients_map, current_time)
    else:
        print(f"❌ Product '{effective_name}' is OUT OF STOCK.")
        current_summary = [
            {
                'user_email': recipients_map.get(sub.get('recipient_id'), 'Email not found'),
                'status': 'Not Sent - Out of Stock'
            } for sub in subs
        ]
        sent_count = 0

    return {
        'product_name': effective_name,
        'product_url': product_url,
        'subscriptions': current_summary
    }, sent_count, pincode_entered

async def main():
    print("Starting stock check...")
    summary_email_data = []
    total_sent = 0

    async with aiohttp.ClientSession() as session:
        recipients_map = await load_recipients(session)
        if not recipients_map:
            print("No recipients found. Notifications may not be sent.")

        all_products = await load_products(session)
        if not all_products:
            print("No products fetched from API. Exiting.")
            return

        subs_map = await load_subscriptions(session)

        current_time = (datetime.now(timezone.utc) + timedelta(hours=5, minutes=30)).time()

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True, args=["--no-sandbox"])
            page = await browser.new_page()
            pincode_entered = False

            for product_info in all_products:
                summary, sent, pincode_entered = await process_product(
                    session, page, product_info, recipients_map, current_time, pincode_entered, subs_map
                )
                if summary:
                    summary_email_data.append(summary)
                total_sent += sent

                delay = getattr(config, 'DELAY_BETWEEN_REQUESTS', 1)
                await asyncio.sleep(delay)

        await browser.close()

    print("\nStock check finished.")

    run_timestamp_utc = datetime.now(timezone.utc)
    ist_offset = timedelta(hours=5, minutes=30)
    run_timestamp_ist = run_timestamp_utc + ist_offset
    month_name = run_timestamp_ist.strftime('%B')
    run_timestamp_str = run_timestamp_ist.strftime(f'%d-{month_name}-%Y / %I:%M%p') + ", IST"
    subject = f"Stock Check Summary: {run_timestamp_str} - {total_sent} User Notifications Sent"
    sent_only_data = [
        pd for pd in summary_email_data
        if any(sub.get('status') == 'Sent' for sub in pd.get('subscriptions', []))
    ]
    summary_body = format_summary_email_body(run_timestamp_str, sent_only_data, total_sent)

    if total_sent > 0:
        if config.EMAIL_SENDER and config.EMAIL_HOST: # Also check EMAIL_HOST for sending
            try:
                await notifications.send_email_notification( # Added await
                    subject=subject,
                    body=summary_body,
                    sender=config.EMAIL_SENDER,
                    recipients=[config.EMAIL_SENDER], # Summary sent to self
                    host=config.EMAIL_HOST,
                    port=config.EMAIL_PORT,
                    username=config.EMAIL_HOST_USER,
                    password=config.EMAIL_HOST_PASSWORD
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
