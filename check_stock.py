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

                    # New frequency check logic
                    active_subscriptions_for_this_product = []
                    for sub in all_product_subscriptions:
                        if not isinstance(sub, dict):
                            print(f"Skipping invalid subscription object: {sub}")
                            continue

                        # API should provide these with defaults. If missing, treat as 0.
                        freq_days = sub.get('frequency_days', 0)
                        freq_hours = sub.get('frequency_hours', 0)
                        freq_minutes = sub.get('frequency_minutes', 0)
                        last_checked_at_str = sub.get('last_checked_at')
                        sub_id = sub.get('id', 'Unknown_ID')

                        is_due = False
                        if last_checked_at_str is None:
                            is_due = True
                            print(f"INFO: Subscription {sub_id} for product {product_id} has no last_checked_at, due for check.")
                        else:
                            try:
                                last_checked_at_dt = isoparse(last_checked_at_str)
                                if last_checked_at_dt.tzinfo is None:
                                    last_checked_at_dt = last_checked_at_dt.replace(tzinfo=timezone.utc)

                                if freq_days == 0 and freq_hours == 0 and freq_minutes == 0:
                                    is_due = True
                                    print(f"INFO: Subscription {sub_id} for product {product_id} has zero frequency, due for check on every run.")
                                else:
                                    next_due_dt = calculate_next_check_due(last_checked_at_dt, freq_days, freq_hours, freq_minutes)
                                    if current_utc_time >= next_due_dt:
                                        is_due = True
                                        print(f"INFO: Subscription {sub_id} for product {product_id} is due. Next due: {next_due_dt.isoformat()}, Last checked: {last_checked_at_str}.")
                                    # else: # Optional: log when not due
                                        # print(f"DEBUG: Subscription {sub_id} for product {product_id} not due. Next due: {next_due_dt.isoformat()}, Last checked: {last_checked_at_str}.")
                            except ValueError:
                                print(f"ERROR: Could not parse last_checked_at_str: '{last_checked_at_str}' for subscription {sub_id}. Considering it due.")
                                is_due = True

                        if is_due:
                            sub['_effective_check_time'] = current_utc_time
                            active_subscriptions_for_this_product.append(sub)

                    if not active_subscriptions_for_this_product:
                        print(f"Product '{effective_product_name}' is in stock, but no subscriptions are due for a check based on new frequency logic at {current_utc_time.strftime('%H:%M:%S %Z')}.")
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
                                    # Retrieve granular delay fields
                                    d_days = sub_to_update.get('delay_days', 0)
                                    d_hours = sub_to_update.get('delay_hours', 0)
                                    d_minutes = sub_to_update.get('delay_minutes', 0)

                                    if d_days == 0 and d_hours == 0 and d_minutes == 0:
                                        print(f"INFO: Subscription {sub_to_update.get('id')} for product {product_id} has zero delay (D/H/M all zero). No delay will be applied.")
                                        # Optionally, update last_in_stock_at without delayed_until if that's desired
                                        # For now, just skip delay update.
                                        continue

                                    delay_timedelta = timedelta(days=d_days, hours=d_hours, minutes=d_minutes)
                                    last_in_stock_at_iso = notification_time_utc.isoformat()
                                    delayed_until_calculated_dt = notification_time_utc + delay_timedelta
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
                            print("⚠️ Email configuration missing or invalid (EMAIL_HOST, EMAIL_SENDER), cannot send email.")
                    else:
                        print(f"Product '{effective_product_name}' is in stock, but no valid & subscribed recipients found via API after mapping IDs to emails for notification.")
                else:
                    print(f"❌ Product '{effective_product_name}' (URL: {product_api_url}) is OUT OF STOCK or information is unavailable.")

            except Exception as e:
                print(f"🚨 An error occurred while processing product {product_name_api} (URL: {product_api_url}): {e}")

            # Placeholder for updating last_checked_at for all subscriptions that were due for this product
            # This happens regardless of whether the product was in stock or if notifications were sent,
            # as a check was performed for these active subscriptions.
            # Ensure 'active_subscriptions_for_this_product' was defined (it would be unless an early continue happened)
            if 'active_subscriptions_for_this_product' in locals() and active_subscriptions_for_this_product:
                print(f"INFO: Placeholder for updating last_checked_at for product {product_id}:")
                for sub_to_log_check in active_subscriptions_for_this_product:
                    sub_id_log = sub_to_log_check.get('id', 'Unknown_ID')
                    # Ensure _effective_check_time was set
                    if '_effective_check_time' in sub_to_log_check:
                         effective_check_time_iso = sub_to_log_check.get('_effective_check_time').isoformat()
                         print(f"  - Sub ID: {sub_id_log}, Would update last_checked_at to: {effective_check_time_iso}")
                    else:
                        # This case should ideally not happen if logic is correct
                        print(f"  - Sub ID: {sub_id_log}, _effective_check_time not set, cannot log last_checked_at update.")

            # Respectful delay, ensure DELAY_BETWEEN_REQUESTS is defined in config
            delay = getattr(config, 'DELAY_BETWEEN_REQUESTS', 1) # Default to 1s if not defined
            await asyncio.sleep(delay)

    print("\nStock check finished.")

def calculate_next_check_due(last_checked_at_dt: datetime, freq_days: int, freq_hours: int, freq_minutes: int) -> datetime:
    """Calculates the next due time based on the last checked time and frequency components."""
    if last_checked_at_dt.tzinfo is None: # Ensure last_checked_at_dt is offset-aware
        print(f"Warning: last_checked_at_dt is naive: {last_checked_at_dt}. Assuming UTC.")
        last_checked_at_dt = last_checked_at_dt.replace(tzinfo=timezone.utc)

    return last_checked_at_dt + timedelta(days=freq_days, hours=freq_hours, minutes=freq_minutes)

if __name__ == "__main__":
    asyncio.run(main())
