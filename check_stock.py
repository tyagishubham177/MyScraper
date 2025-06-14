import asyncio
from datetime import datetime, timezone, timedelta, time as dt_time
import aiohttp
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

async def main():
    print("Starting stock check...")
    summary_email_data = []
    total_sent = 0

    async with aiohttp.ClientSession() as session:
        recipients_url = f"{config.APP_BASE_URL}/api/recipients"
        recipients_data = await fetch_api_data(session, recipients_url)
        recipients_map = {r.get('id'): r.get('email') for r in recipients_data or [] if r.get('id') and r.get('email')}

        if not recipients_map:
            print("No recipients found. Notifications may not be sent.")

        products_url = f"{config.APP_BASE_URL}/api/products"
        all_products = await fetch_api_data(session, products_url)
        if not all_products:
            print("No products fetched from API. Exiting.")
            return

        for product_info in all_products:
            product_id = product_info.get('id')
            product_url = product_info.get('url')
            product_name = product_info.get('name', 'N/A')
            effective_name = product_name

            if not product_id or not product_url:
                print(f"Skipping product due to missing data: {product_info}")
                continue

            subscriptions_url = f"{config.APP_BASE_URL}/api/subscriptions?product_id={product_id}"
            subs = await fetch_api_data(session, subscriptions_url)
            current_summary = []
            if not subs or not isinstance(subs, list):
                print(f"Could not fetch subscriptions for product ID {product_id}.")
                summary_email_data.append({
                    'product_name': effective_name,
                    'product_url': product_url,
                    'subscriptions': [{'user_email': 'N/A', 'status': 'Error fetching subscriptions'}]
                })
                continue

            try:
                in_stock, scraped_name = await scraper.check_product_availability(product_url, config.PINCODE)
                if scraped_name:
                    effective_name = scraped_name
            except Exception as e:
                print(f"Error checking {product_url}: {e}")
                for sub in subs:
                    email = recipients_map.get(sub.get('recipient_id'), 'Email not found')
                    current_summary.append({'user_email': email, 'status': 'Not Sent - Scraping Error'})
                summary_email_data.append({
                    'product_name': effective_name,
                    'product_url': product_url,
                    'subscriptions': current_summary
                })
                continue

            if in_stock:
                print(f"✅ Product '{effective_name}' is IN STOCK.")
                valid_emails = []
                current_time = (datetime.now(timezone.utc) + timedelta(hours=5, minutes=30)).time()
                for sub in subs:
                    rid = sub.get('recipient_id')
                    email = recipients_map.get(rid)
                    start_t = sub.get('start_time', '00:00')
                    end_t = sub.get('end_time', '23:59')
                    if sub.get('paused'):
                        if email:
                            current_summary.append({'user_email': email, 'status': 'Skipped - Paused'})
                        else:
                            current_summary.append({'user_email': 'Unknown', 'status': 'Skipped - Paused'})
                        continue
                    if not within_time_window(start_t, end_t, current_time):
                        if email:
                            current_summary.append({'user_email': email, 'status': 'Skipped - Subscription Not Due'})
                        else:
                            current_summary.append({'user_email': 'Unknown', 'status': 'Skipped - Subscription Not Due'})
                        continue
                    if email:
                        valid_emails.append(email)
                        current_summary.append({'user_email': email, 'status': 'Sent'})
                    else:
                        current_summary.append({'user_email': 'Unknown', 'status': 'Not Sent - Recipient Email Missing'})

                if valid_emails and config.EMAIL_HOST and config.EMAIL_SENDER:
                    try:
                        notifications.send_email_notification(
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
                        total_sent += len(valid_emails)
                    except Exception as e:
                        print(f"Error sending email for '{effective_name}': {e}")
                        for summary in current_summary:
                            if summary['status'] == 'Sent':
                                summary['status'] = 'Not Sent - Email Send Error'
                else:
                    print(f"Email configuration missing or no valid emails for '{effective_name}'.")
                    for summary in current_summary:
                        if summary['status'] == 'Sent':
                            summary['status'] = 'Not Sent - Email Config Missing'
            else:
                print(f"❌ Product '{effective_name}' is OUT OF STOCK.")
                for sub in subs:
                    email = recipients_map.get(sub.get('recipient_id'), 'Email not found')
                    current_summary.append({'user_email': email, 'status': 'Not Sent - Out of Stock'})

            summary_email_data.append({
                'product_name': effective_name,
                'product_url': product_url,
                'subscriptions': current_summary
            })

            delay = getattr(config, 'DELAY_BETWEEN_REQUESTS', 1)
            await asyncio.sleep(delay)

    print("\nStock check finished.")

    run_timestamp_utc = datetime.now(timezone.utc)
    ist_offset = timedelta(hours=5, minutes=30)
    run_timestamp_ist = run_timestamp_utc + ist_offset
    month_name = run_timestamp_ist.strftime('%B')
    run_timestamp_str = run_timestamp_ist.strftime(f'%d-{month_name}-%Y / %I:%M%p') + ", IST"
    subject = f"Stock Check Summary: {run_timestamp_str} - {total_sent} User Notifications Sent"
    summary_body = format_summary_email_body(run_timestamp_str, summary_email_data, total_sent)

    if total_sent > 0 and config.EMAIL_SENDER:
        try:
            notifications.send_email_notification(
                subject=subject,
                body=summary_body,
                sender=config.EMAIL_SENDER,
                recipients=[config.EMAIL_SENDER],
                host=config.EMAIL_HOST,
                port=config.EMAIL_PORT,
                username=config.EMAIL_HOST_USER,
                password=config.EMAIL_HOST_PASSWORD
            )
            print("✅ Summary email sent successfully.")
        except Exception as e:
            print(f"Error sending summary email: {e}")
    else:
        print("No user notifications were sent. Skipping summary email.")

if __name__ == "__main__":
    asyncio.run(main())
