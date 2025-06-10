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

            # print(f"\nChecking product from API: '{product_name_api}' (ID: {product_id}) at URL: {product_api_url}")

            # --- BEGIN MODIFIED SECTION ---

            # 1. Fetch all subscriptions for this product FIRST
            subscriptions_url = f"{config.APP_BASE_URL}/api/subscriptions?product_id={product_id}"
            all_product_subscriptions = await fetch_api_data(session, subscriptions_url)

            if not all_product_subscriptions or not isinstance(all_product_subscriptions, list):
                print(f"Could not fetch subscriptions or data was invalid for product ID {product_id}. API returned: {all_product_subscriptions}. Skipping product.")
                # Respectful delay before continuing to the next product
                delay = getattr(config, 'DELAY_BETWEEN_REQUESTS', 1)
                await asyncio.sleep(delay)
                continue

            # 2. Determine active/due subscriptions (based on frequency and last_checked_at)
            # This list will be used for deciding to scrape and for updating last_checked_at later.
            active_subscriptions_due_check = []
            # Use current_utc_time from the start of main() for this entire run's consistency in "due" calculation
            # Alternatively, a fresh current_utc_time = datetime.now(timezone.utc) could be used here per product.
            # For now, using the script's start time for this check.

            for sub in all_product_subscriptions:
                if not isinstance(sub, dict):
                    print(f"Skipping invalid subscription object: {sub}")
                    continue

                freq_days = sub.get('frequency_days', 0)
                freq_hours = sub.get('frequency_hours', 0)
                freq_minutes = sub.get('frequency_minutes', 0)
                last_checked_at_str = sub.get('last_checked_at')
                sub_id = sub.get('id', 'Unknown_ID')

                is_due = False
                if last_checked_at_str is None:
                    is_due = True
                    # print(f"DEBUG: Subscription {sub_id} for product {product_id} has no last_checked_at, due for check.")
                else:
                    try:
                        last_checked_at_dt = isoparse(last_checked_at_str)
                        if last_checked_at_dt.tzinfo is None:
                            last_checked_at_dt = last_checked_at_dt.replace(tzinfo=timezone.utc)

                        if freq_days == 0 and freq_hours == 0 and freq_minutes == 0:
                            is_due = True # Always check if frequency is zero (or not set)
                            # print(f"DEBUG: Subscription {sub_id} for product {product_id} has zero frequency, due for check.")
                        else:
                            next_due_dt = calculate_next_check_due(last_checked_at_dt, freq_days, freq_hours, freq_minutes)
                            if current_utc_time >= next_due_dt:
                                is_due = True
                                # print(f"DEBUG: Subscription {sub_id} for product {product_id} is due. Next due: {next_due_dt.isoformat()}, Last checked: {last_checked_at_str}.")
                    except ValueError:
                        print(f"ERROR: Could not parse last_checked_at_str: '{last_checked_at_str}' for subscription {sub_id}. Considering it due.")
                        is_due = True

                if is_due:
                    sub['_effective_check_time'] = current_utc_time # Store the time this check was deemed "due"
                    active_subscriptions_due_check.append(sub)

            # 3. If no active/due subscriptions, print message and skip scraping
            if not active_subscriptions_due_check:
                print(f"ℹ️ No active or due subscriptions for product '{product_name_api}' (ID: {product_id}) at {current_utc_time.strftime('%Y-%m-%d %H:%M:%S %Z')}. Skipping scrape.")
                # Update last_checked_at for subscriptions that might have been fetched but weren't due (if any were due, they are in active_subscriptions_due_check)
                # This part is tricky: the original code updates LCA for 'active_subscriptions_for_this_product'.
                # If we skip scraping, we still need to update LCA for those that *were* due.
                # The current logic at the end of the loop handles 'active_subscriptions_due_check' (renamed from 'active_subscriptions_for_this_product').
                # So, if active_subscriptions_due_check is empty here, the LCA update loop at the end won't run for this product, which is correct.
            else:
                print(f"Found {len(active_subscriptions_due_check)} active/due subscriptions for '{product_name_api}' (ID: {product_id}). Proceeding with scrape.")
                try:
                    in_stock, product_name_scraper = await scraper.check_product_availability(product_api_url, config.PINCODE)
                    effective_product_name = product_name_scraper if product_name_scraper else product_name_api

                    if in_stock:
                        print(f"✅ Product '{effective_product_name}' (URL: {product_api_url}) is IN STOCK.")

                        # Filter the previously fetched active/due subscriptions for 'delayed_until'
                        loop_time_utc = datetime.now(timezone.utc) # Fresh time for delay checks
                        subscriptions_to_notify = []
                        for sub in active_subscriptions_due_check: # Use the already filtered list
                            delayed_until_str = sub.get('delayed_until')
                            if delayed_until_str:
                                try:
                                    delayed_until_dt = isoparse(delayed_until_str)
                                    if delayed_until_dt.tzinfo is None:
                                        delayed_until_dt = delayed_until_dt.replace(tzinfo=timezone.utc)
                                    if delayed_until_dt > loop_time_utc:
                                        print(f"INFO: Subscription for recipient {sub.get('recipient_id')} product {product_id} is currently delayed until {delayed_until_str}. Skipping notification.")
                                        continue
                                except ValueError:
                                    print(f"ERROR: Could not parse delayed_until_str: '{delayed_until_str}' for subscription {sub.get('id')}. Considering not delayed.")
                            subscriptions_to_notify.append(sub)

                        if not subscriptions_to_notify:
                            print(f"Product '{effective_product_name}' is in stock, but all {len(active_subscriptions_due_check)} active/due subscriptions are currently delayed.")
                        else:
                            subscribed_recipient_ids = {s.get('recipient_id') for s in subscriptions_to_notify if s.get('recipient_id')}
                            if not subscribed_recipient_ids:
                                print(f"Product '{effective_product_name}' is in stock, but no valid recipient IDs in non-delayed subscriptions.")
                            else:
                                email_list_for_product = [recipients_map[rid] for rid in subscribed_recipient_ids if rid in recipients_map]
                                if email_list_for_product:
                                    email_subject = f"{effective_product_name.strip()} In Stock Alert!"
                                    email_body = notifications.format_long_message(effective_product_name, product_api_url)
                                    print(f"Attempting to send notifications to: {', '.join(email_list_for_product)}")

                                    if config.EMAIL_HOST and config.EMAIL_SENDER:
                                        notifications.send_email_notification(
                                            subject=email_subject, body=email_body, sender=config.EMAIL_SENDER,
                                            recipients=email_list_for_product, host=config.EMAIL_HOST, port=config.EMAIL_PORT,
                                            username=config.EMAIL_HOST_USER, password=config.EMAIL_HOST_PASSWORD
                                        )
                                        print(f"📨 Email notifications sent for '{effective_product_name}'.")

                                        notification_time_utc = datetime.now(timezone.utc)
                                        for sub_to_update in subscriptions_to_notify: # Only update those who were to be notified
                                            if sub_to_update.get('recipient_id') in subscribed_recipient_ids and sub_to_update.get('delay_on_stock'):
                                                d_days = sub_to_update.get('delay_days', 0)
                                                d_hours = sub_to_update.get('delay_hours', 0)
                                                d_minutes = sub_to_update.get('delay_minutes', 0)

                                                if d_days == 0 and d_hours == 0 and d_minutes == 0:
                                                    print(f"INFO: Subscription {sub_to_update.get('id')} for product {product_id} has zero delay_on_stock duration. No delay applied.")
                                                    continue

                                                delay_timedelta = timedelta(days=d_days, hours=d_hours, minutes=d_minutes)
                                                last_in_stock_at_iso = notification_time_utc.isoformat()
                                                delayed_until_calculated_dt = notification_time_utc + delay_timedelta
                                                delayed_until_iso = delayed_until_calculated_dt.isoformat()
                                                update_payload = {
                                                    "recipient_id": sub_to_update.get('recipient_id'), "product_id": product_id,
                                                    "last_in_stock_at": last_in_stock_at_iso, "delayed_until": delayed_until_iso
                                                }
                                                update_url_delay = f"{config.APP_BASE_URL}/api/subscriptions" # Renamed variable
                                                try:
                                                    async with session.post(update_url_delay, json=update_payload) as resp_delay: # Renamed variable
                                                        if resp_delay.status == 200 or resp_delay.status == 201:
                                                            print(f"INFO: Successfully updated subscription for {sub_to_update.get('recipient_id')} product {product_id} with delay until {delayed_until_iso}.")
                                                        else:
                                                            error_text = await resp_delay.text()
                                                            print(f"ERROR: Failed to update subscription with delay for {sub_to_update.get('recipient_id')} product {product_id}: {resp_delay.status} - {error_text}")
                                                except Exception as e_delay_update: # Renamed variable
                                                    print(f"ERROR: Exception during subscription delay update for {sub_to_update.get('recipient_id')} product {product_id}: {e_delay_update}")
                                    else:
                                        print("⚠️ Email configuration missing, cannot send email.")
                                else:
                                    print(f"Product '{effective_product_name}' is in stock, but no valid email addresses for subscribed recipients.")
                    else: # Product out of stock
                        print(f"❌ Product '{effective_product_name}' (URL: {product_api_url}) is OUT OF STOCK.")
                        # No notification or delay logic needed here, but last_checked_at for active_subscriptions_due_check will be updated below.

                except Exception as e:
                    print(f"🚨 An error occurred while scraping or processing product {product_name_api} (URL: {product_api_url}): {e}")

            # --- END MODIFIED SECTION ---

            # Update last_checked_at for all subscriptions that were determined to be active/due for this product run
            # This list is 'active_subscriptions_due_check'. If it's empty (e.g. no subs, or none were due), this loop won't run.
            if active_subscriptions_due_check: # Check if the list is not empty
                update_lca_url = f"{config.APP_BASE_URL}/api/subscriptions" # Renamed variable
                for sub_to_update_lca in active_subscriptions_due_check:
                    recipient_id_lca = sub_to_update_lca.get('recipient_id')
                    sub_id_lca = sub_to_update_lca.get('id', 'Unknown_ID')

                    if '_effective_check_time' in sub_to_update_lca and recipient_id_lca and product_id:
                        new_last_checked_at_iso = sub_to_update_lca['_effective_check_time'].isoformat()
                        update_payload_lca = {
                            "recipient_id": recipient_id_lca,
                            "product_id": product_id,
                            "last_checked_at": new_last_checked_at_iso
                        }
                        try:
                            async with session.post(update_lca_url, json=update_payload_lca) as resp_lca: # Renamed variable
                                if resp_lca.status == 200 or resp_lca.status == 201:
                                    print(f"INFO: Successfully updated last_checked_at for subscription {sub_id_lca} (Recipient {recipient_id_lca}, Product {product_id}) to {new_last_checked_at_iso}.")
                                else:
                                    error_text = await resp_lca.text()
                                    print(f"ERROR: Failed to update last_checked_at for subscription {sub_id_lca}. Status: {resp_lca.status} - {error_text}")
                        except aiohttp.ClientError as e_lca_client: # Renamed variable
                            print(f"ERROR: ClientError while updating last_checked_at for subscription {sub_id_lca}: {e_lca_client}")
                        except Exception as e_lca_general:
                             print(f"ERROR: Unexpected error while updating last_checked_at for subscription {sub_id_lca}: {e_lca_general}")
                    else:
                        print(f"WARN: Missing data to update last_checked_at for sub ID {sub_id_lca} (recipient_id: {recipient_id_lca}, product_id: {product_id}, _effective_check_time set: {'_effective_check_time' in sub_to_update_lca})")

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
