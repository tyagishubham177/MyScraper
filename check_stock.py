import asyncio
from datetime import datetime, timezone, time, timedelta
from dateutil.parser import isoparse
import aiohttp
import config
import notifications
import scraper

async def fetch_api_data(session, url):
    """Fetches data from an API endpoint."""
    try:
        async with session.get(url) as response:
            response.raise_for_status()  # Raises an exception for HTTP errors 4xx/5xx
            return await response.json()
    except aiohttp.ClientError as e:
        print(f"API request to {url} failed: {e}")
        return None
    except Exception as e: # Catch other potential errors like JSON decoding issues non-aiohttp
        print(f"An unexpected error occurred during API request to {url}: {e}")
        return None

async def main():
    print("Starting dynamic stock check based on API data...")

    current_utc_time = datetime.now(timezone.utc)
    print(f"Script current UTC time: {current_utc_time.strftime('%Y-%m-%d %H:%M:%S %Z')}")

    async with aiohttp.ClientSession() as session:
        # Fetch Recipients for Mapping
        recipients_url = f"{config.APP_BASE_URL}/api/recipients"
        recipients_data = await fetch_api_data(session, recipients_url)

        recipients_map = {}
        if recipients_data and isinstance(recipients_data, list):
            recipients_map = {r.get('id'): r.get('email') for r in recipients_data if r.get('id') and r.get('email')}
        else:
            print("⚠️ Could not fetch or parse recipients data, or data is not a list. Proceeding without recipient mapping.")

        if not recipients_map:
             print("No recipients found via API or mapping failed. Notifications for in-stock items may not be sent.")

        # Fetch Products
        products_url = f"{config.APP_BASE_URL}/api/products"
        all_products = await fetch_api_data(session, products_url)

        if not all_products: # Checks for None or empty list
            print("No products fetched from API or API error. Exiting.")
            return

        for product_info in all_products:
            product_id = product_info.get('id')
            product_api_url = product_info.get('url') # Renamed to avoid conflict with 'product_url' variable name
            product_name_api = product_info.get('name', 'N/A')

            if not product_id or not product_api_url:
                print(f"⚠️ Skipping product due to missing ID or URL in API data: {product_info}")
                continue

            print(f"\nChecking product from API: '{product_name_api}' (ID: {product_id}) at URL: {product_api_url}")

            try:
                in_stock, product_name_scraper = await scraper.check_product_availability(product_api_url, config.PINCODE)
                effective_product_name = product_name_scraper if product_name_scraper else product_name_api

                if in_stock:
                    print(f"✅ Product '{effective_product_name}' (URL: {product_api_url}) is IN STOCK.")

                    # Fetch all subscriptions for this product
                    subscriptions_url = f"{config.APP_BASE_URL}/api/subscriptions?product_id={product_id}"
                    all_product_subscriptions = await fetch_api_data(session, subscriptions_url)

                    if not all_product_subscriptions or not isinstance(all_product_subscriptions, list):
                        print(f"Could not fetch subscriptions or data was invalid for product ID {product_id}. API returned: {all_product_subscriptions}")
                        continue # Skip to next product if no subscription data

                    # Filter subscriptions based on frequency BEFORE checking stock for these subscriptions
                    # It's better to get current time per product as processing can take time.
                    # However, for a single run of this script, current_utc_time from the start of main() is acceptable for now.
                    # For longer running services, this should be updated per check.
                    # For this iteration, we'll use the current_utc_time defined at the start of main().

                    active_subscriptions_for_this_product = []
                    for sub in all_product_subscriptions:
                        if not isinstance(sub, dict):
                            print(f"Skipping invalid subscription object: {sub}")
                            continue

                        # The API should provide defaults, but being defensive here.
                        frequency = sub.get('frequency', 'daily')
                        if await should_check_based_on_frequency(frequency, current_utc_time):
                            active_subscriptions_for_this_product.append(sub)

                    if not active_subscriptions_for_this_product:
                        print(f"Product '{effective_product_name}' is in stock, but no subscriptions are due for a check based on frequency at {current_utc_time.strftime('%H:%M:%S %Z')}.")
                        continue

                    # Check for active delays
                    loop_time_utc = datetime.now(timezone.utc) # Use a fresh time for delay checks
                    subscriptions_not_delayed = []
                    for sub in active_subscriptions_for_this_product:
                        delayed_until_str = sub.get('delayed_until')
                        if delayed_until_str:
                            try:
                                delayed_until_dt = isoparse(delayed_until_str)
                                # If isoparse returns naive, assume UTC (API should provide timezone)
                                if delayed_until_dt.tzinfo is None:
                                    delayed_until_dt = delayed_until_dt.replace(tzinfo=timezone.utc)

                                if delayed_until_dt > loop_time_utc:
                                    print(f"INFO: Subscription for recipient {sub.get('recipient_id')} product {product_id} is currently delayed until {delayed_until_str}. Skipping notification.")
                                    continue # Skip this subscription
                            except ValueError:
                                print(f"ERROR: Could not parse delayed_until_str: '{delayed_until_str}' for subscription {sub.get('id')}. Proceeding without delay consideration for this sub.")
                        subscriptions_not_delayed.append(sub)

                    if not subscriptions_not_delayed:
                        print(f"Product '{effective_product_name}' is in stock, frequency criteria met, but all active subscriptions are currently delayed.")
                        continue

                    # Proceed with notification logic for subscriptions that are active and not delayed
                    subscribed_recipient_ids = {s.get('recipient_id') for s in subscriptions_not_delayed if s.get('recipient_id')}

                    if not subscribed_recipient_ids:
                        print(f"Product '{effective_product_name}' is in stock, frequency/delay criteria met, but no valid recipient IDs found.")
                        continue

                    email_list_for_product = [
                        recipients_map[rid] for rid in subscribed_recipient_ids if rid in recipients_map
                    ]

                    if email_list_for_product:
                        email_subject = f"{effective_product_name.strip()} In Stock Alert!"
                        email_body = notifications.format_long_message(effective_product_name, product_api_url)

                        print(f"Attempting to send notifications to: {', '.join(email_list_for_product)}")

                        # Send actual notifications
                        if config.EMAIL_HOST and config.EMAIL_SENDER:
                            notifications.send_email_notification(
                                subject=email_subject,
                                body=email_body,
                                sender=config.EMAIL_SENDER,
                                recipients=email_list_for_product,
                                host=config.EMAIL_HOST,
                                port=config.EMAIL_PORT,
                                username=config.EMAIL_HOST_USER,
                                password=config.EMAIL_HOST_PASSWORD
                            )
                            print(f"📨 Email notifications sent for '{effective_product_name}'.")

                            # After successful notification, update timestamps for subscriptions with delay_on_stock
                            notification_time_utc = datetime.now(timezone.utc) # Fresh timestamp for updates
                            for sub_to_update in subscriptions_not_delayed:
                                if sub_to_update.get('recipient_id') in subscribed_recipient_ids and sub_to_update.get('delay_on_stock'):
                                    delay_duration_str = sub_to_update.get('delay_duration')
                                    parsed_timedelta = parse_delay_duration(delay_duration_str)

                                    if parsed_timedelta:
                                        last_in_stock_at_iso = notification_time_utc.isoformat()
                                        delayed_until_calculated_dt = notification_time_utc + parsed_timedelta
                                        delayed_until_iso = delayed_until_calculated_dt.isoformat()

                                        update_payload = {
                                            "recipient_id": sub_to_update.get('recipient_id'),
                                            "product_id": product_id, # product_id is from the outer loop
                                            "last_in_stock_at": last_in_stock_at_iso,
                                            "delayed_until": delayed_until_iso
                                        }
                                        update_url = f"{config.APP_BASE_URL}/api/subscriptions"
                                        try:
                                            async with session.post(update_url, json=update_payload) as response:
                                                if response.status == 200 or response.status == 201:
                                                    print(f"INFO: Successfully updated subscription for {sub_to_update.get('recipient_id')} product {product_id} with delay until {delayed_until_iso}.")
                                                else:
                                                    error_text = await response.text()
                                                    print(f"ERROR: Failed to update subscription with delay for {sub_to_update.get('recipient_id')} product {product_id}: {response.status} - {error_text}")
                                        except Exception as e_update:
                                            print(f"ERROR: Exception during subscription update for {sub_to_update.get('recipient_id')} product {product_id}: {e_update}")
                                    else:
                                        print(f"ERROR: Could not parse delay_duration '{delay_duration_str}' for subscription {sub_to_update.get('id')}. Not updating timestamps.")
                        else:
                            print("⚠️ Email configuration missing or invalid (EMAIL_HOST, EMAIL_SENDER), cannot send email.")
                    else:
                        print(f"Product '{effective_product_name}' is in stock, but no valid & subscribed recipients found via API after mapping IDs to emails for notification.")
                else:
                    print(f"❌ Product '{effective_product_name}' (URL: {product_api_url}) is OUT OF STOCK or information is unavailable.")

            except Exception as e:
                print(f"🚨 An error occurred while processing product {product_name_api} (URL: {product_api_url}): {e}")

            # Respectful delay, ensure DELAY_BETWEEN_REQUESTS is defined in config
            delay = getattr(config, 'DELAY_BETWEEN_REQUESTS', 1) # Default to 1s if not defined
            await asyncio.sleep(delay)

    print("\nStock check finished.")

def parse_delay_duration(duration_str: str) -> timedelta | None:
    """
    Parses a delay duration string (e.g., "1_day", "3_hours") into a timedelta object.
    Returns None if parsing fails.
    """
    if not duration_str or not isinstance(duration_str, str):
        return None

    parts = duration_str.lower().split('_')
    if len(parts) != 2:
        return None

    try:
        value = int(parts[0])
        unit = parts[1]
        if unit == "day" or unit == "days":
            return timedelta(days=value)
        elif unit == "hour" or unit == "hours":
            return timedelta(hours=value)
        else:
            return None
    except ValueError:
        return None

async def should_check_based_on_frequency(subscription_frequency: str, current_time_utc: datetime) -> bool:
    """
    Determines if a stock check should be performed based on the subscription frequency and current UTC time.
    Baseline for checks is midnight UTC.
    """
    # Ensure current_time_utc is offset-aware (which it should be if datetime.now(timezone.utc) was used)
    if current_time_utc.tzinfo is None or current_time_utc.tzinfo.utcoffset(current_time_utc) is None:
        print(f"Warning: current_time_utc is naive. Assuming UTC for frequency check: {current_time_utc}")
        # Potentially, make it aware: current_time_utc = current_time_utc.replace(tzinfo=timezone.utc)

    hour = current_time_utc.hour
    minute = current_time_utc.minute # Check if it's close to the hour mark
    weekday = current_time_utc.weekday() # Monday is 0, Sunday is 6

    # Allow a small window for the check (e.g., first 5 minutes of the hour)
    # This helps if the script doesn't run exactly at 00 minutes.
    is_at_hour_mark = (minute < 5)

    if subscription_frequency == "hourly":
        return is_at_hour_mark
    elif subscription_frequency == "every_2_hours":
        return hour % 2 == 0 and is_at_hour_mark
    elif subscription_frequency == "daily":
        return hour == 0 and is_at_hour_mark # Midnight
    elif subscription_frequency == "weekly":
        # Check on Monday (weekday == 0) at midnight UTC
        return weekday == 0 and hour == 0 and is_at_hour_mark
    else:
        print(f"Warning: Unknown frequency '{subscription_frequency}'. Defaulting to no check.")
        return False

if __name__ == "__main__":
    asyncio.run(main())
