import asyncio
from datetime import datetime, timezone, time, timedelta
try:
    import pytz
except ImportError:
    pytz = None
from dateutil.parser import isoparse
import aiohttp
import config
from config import RUN_OFFSET_MINUTES # Import the new variable
import notifications
from notifications import format_summary_email_body
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

    summary_email_data = []
    total_actual_notifications_sent = 0

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
            # Capture product_api_url and product_name_api for the current product.
            product_api_url = product_info.get('url')
            product_name_api = product_info.get('name', 'N/A')
            effective_product_name = product_name_api # Initialize with API name, update if scraper provides a better one

            if not product_id or not product_api_url:
                print(f"⚠️ Skipping product due to missing ID or URL in API data: {product_info}")
                continue

            # print(f"\nChecking product from API: '{product_name_api}' (ID: {product_id}) at URL: {product_api_url}")

            # --- BEGIN MODIFIED SECTION ---

            # 1. Fetch all subscriptions for this product FIRST
            subscriptions_url = f"{config.APP_BASE_URL}/api/subscriptions?product_id={product_id}"
            all_product_subscriptions = await fetch_api_data(session, subscriptions_url)

            current_product_subscription_summary = []

            if not all_product_subscriptions or not isinstance(all_product_subscriptions, list):
                print(f"Could not fetch subscriptions or data was invalid for product ID {product_id}. API returned: {all_product_subscriptions}. Skipping product.")
                # Append data for summary email even if subscriptions couldn't be fetched
                summary_email_data.append({
                    'product_name': effective_product_name,
                    'product_url': product_api_url,
                    'subscriptions': [{'user_email': 'N/A', 'status': 'Error fetching subscriptions'}]
                })
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
                    sub['notification_status'] = "Skipped - Invalid Subscription Object" # Ensure status for summary
                    continue

                # Default notification_status for every subscription
                sub['notification_status'] = "Skipped - Subscription Not Due"
                # Determine user_email (will be re-checked when populating summary, but good to have early if needed)
                # user_email = recipients_map.get(sub.get('recipient_id'), "Email not found")
                # Actually, user_email is only needed when current_product_subscription_summary is populated.

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
                            if current_utc_time >= (next_due_dt - timedelta(minutes=RUN_OFFSET_MINUTES)): # Use RUN_OFFSET_MINUTES
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
                # No specific status change needed here for summary email, default "Skipped - Subscription Not Due" is correct.
            else:
                print(f"Found {len(active_subscriptions_due_check)} active/due subscriptions for '{product_name_api}' (ID: {product_id}). Proceeding with scrape.")
                try:
                    in_stock, product_name_scraper = await scraper.check_product_availability(product_api_url, config.PINCODE)
                    effective_product_name = product_name_scraper if product_name_scraper else product_name_api # Update effective name

                    if in_stock:
                        print(f"✅ Product '{effective_product_name}' (URL: {product_api_url}) is IN STOCK.")
                        loop_time_utc = datetime.now(timezone.utc)
                        subscriptions_to_notify = []
                        active_due_sub_ids = {s['id'] for s in active_subscriptions_due_check} # For quick lookup

                        for sub_ad in active_subscriptions_due_check: # Iterate active/due subs
                            delayed_until_str = sub_ad.get('delayed_until')
                            is_delayed = False
                            if delayed_until_str:
                                try:
                                    delayed_until_dt = isoparse(delayed_until_str)
                                    if delayed_until_dt.tzinfo is None:
                                        delayed_until_dt = delayed_until_dt.replace(tzinfo=timezone.utc)
                                    if delayed_until_dt > loop_time_utc:
                                        is_delayed = True
                                        print(f"INFO: Subscription for recipient {sub_ad.get('recipient_id')} product {product_id} is currently delayed until {delayed_until_str}. Skipping notification.")
                                        sub_ad['notification_status'] = "Not Sent - Delayed" # Update status for summary
                                except ValueError:
                                    print(f"ERROR: Could not parse delayed_until_str: '{delayed_until_str}' for subscription {sub_ad.get('id')}. Considering not delayed.")

                            if not is_delayed:
                                subscriptions_to_notify.append(sub_ad)
                                sub_ad['notification_status'] = "Sent" # Tentative, actual send determines final "Sent"
                                # total_actual_notifications_sent will be incremented after successful send

                        if not subscriptions_to_notify:
                            print(f"Product '{effective_product_name}' is in stock, but all {len(active_subscriptions_due_check)} active/due subscriptions are currently delayed.")
                        else:
                            subscribed_recipient_ids = {s.get('recipient_id') for s in subscriptions_to_notify if s.get('recipient_id')}
                            if not subscribed_recipient_ids:
                                print(f"Product '{effective_product_name}' is in stock, but no valid recipient IDs in non-delayed subscriptions.")
                                for sub_ntn in subscriptions_to_notify: # Mark as not sent if no valid recipient
                                    sub_ntn['notification_status'] = "Not Sent - Missing Recipient ID"
                            else:
                                email_list_for_product = [recipients_map[rid] for rid in subscribed_recipient_ids if rid in recipients_map]
                                if email_list_for_product:
                                    email_subject = f"{effective_product_name.strip()} In Stock Alert!"
                                    email_body = notifications.format_long_message(effective_product_name, product_api_url)
                                    print(f"Attempting to send notifications to: {', '.join(email_list_for_product)}")

                                    if config.EMAIL_HOST and config.EMAIL_SENDER:
                                        # Store current count in case send_email_notification raises an exception
                                        initial_sent_count_for_product = total_actual_notifications_sent
                                        try:
                                            notifications.send_email_notification(
                                                subject=email_subject, body=email_body, sender=config.EMAIL_SENDER,
                                                recipients=email_list_for_product, host=config.EMAIL_HOST, port=config.EMAIL_PORT,
                                                username=config.EMAIL_HOST_USER, password=config.EMAIL_HOST_PASSWORD
                                            )
                                            print(f"📨 Email notifications sent for '{effective_product_name}'.")

                                            # Increment total_actual_notifications_sent for each recipient successfully emailed
                                            # This assumes send_email_notification sends to all in email_list_for_product or throws an error
                                            # For a more granular status, one would need to know which specific emails failed from send_email_notification

                                            # Update status for subscriptions that were actually part of this email batch
                                            for sub_notified in subscriptions_to_notify:
                                                if sub_notified.get('recipient_id') in subscribed_recipient_ids:
                                                    sub_notified['notification_status'] = "Sent"
                                                    total_actual_notifications_sent += 1

                                            notification_time_utc = datetime.now(timezone.utc)
                                            for sub_to_update in subscriptions_to_notify:
                                                if sub_to_update.get('recipient_id') in subscribed_recipient_ids and sub_to_update.get('delay_on_stock'):
                                                    # ... (delay logic remains the same)
                                                    d_days = sub_to_update.get('delay_days')
                                                    d_days = d_days if d_days is not None else 0
                                                    d_hours = sub_to_update.get('delay_hours')
                                                    d_hours = d_hours if d_hours is not None else 0
                                                    d_minutes = sub_to_update.get('delay_minutes')
                                                    d_minutes = d_minutes if d_minutes is not None else 0

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
                                                    update_url_delay = f"{config.APP_BASE_URL}/api/subscriptions"
                                                    try:
                                                        async with session.post(update_url_delay, json=update_payload) as resp_delay:
                                                            if resp_delay.status == 200 or resp_delay.status == 201:
                                                                print(f"INFO: Successfully updated subscription for {sub_to_update.get('recipient_id')} product {product_id} with delay until {delayed_until_iso}.")
                                                            else:
                                                                error_text = await resp_delay.text()
                                                                print(f"ERROR: Failed to update subscription with delay for {sub_to_update.get('recipient_id')} product {product_id}: {resp_delay.status} - {error_text}")
                                                    except Exception as e_delay_update:
                                                        print(f"ERROR: Exception during subscription delay update for {sub_to_update.get('recipient_id')} product {product_id}: {e_delay_update}")

                                        except Exception as e_send_email:
                                            print(f"ERROR: Failed to send email notifications for '{effective_product_name}': {e_send_email}")
                                            # Revert count and update status for these subscriptions
                                            total_actual_notifications_sent = initial_sent_count_for_product
                                            for sub_failed_send in subscriptions_to_notify:
                                                 if sub_failed_send.get('recipient_id') in subscribed_recipient_ids:
                                                    sub_failed_send['notification_status'] = "Not Sent - Email Send Error"
                                    else: # Email config missing
                                        print("⚠️ Email configuration missing, cannot send email.")
                                        for sub_no_config in subscriptions_to_notify:
                                            if sub_no_config.get('recipient_id') in subscribed_recipient_ids:
                                                sub_no_config['notification_status'] = "Not Sent - Email Config Missing"
                                else: # No valid email addresses
                                    print(f"Product '{effective_product_name}' is in stock, but no valid email addresses for subscribed recipients.")
                                    for sub_no_email in subscriptions_to_notify:
                                         if sub_no_email.get('recipient_id') in subscribed_recipient_ids:
                                            sub_no_email['notification_status'] = "Not Sent - Recipient Email Missing"
                    else: # Product out of stock
                        print(f"❌ Product '{effective_product_name}' (URL: {product_api_url}) is OUT OF STOCK.")
                        for sub_oos in active_subscriptions_due_check:
                            sub_oos['notification_status'] = "Not Sent - Out of Stock"

                except Exception as e:
                    print(f"🚨 An error occurred while scraping or processing product {product_name_api} (URL: {product_api_url}): {e}")
                    effective_product_name = product_name_api # Ensure effective_product_name is set if scraping fails early
                    for sub_err in active_subscriptions_due_check:
                        sub_err['notification_status'] = "Not Sent - Scraping Error"

            # --- END MODIFIED SECTION --- (This comment might be slightly off due to other changes, but marks the logical end of scraping block)

            # Populate current_product_subscription_summary for the summary email
            for sub in all_product_subscriptions:
                user_email = recipients_map.get(sub.get('recipient_id'), "Email not found")
                # notification_status should have been set in the logic above or defaulted
                status = sub.get('notification_status', "Skipped - Status Unknown") # Fallback if not set
                current_product_subscription_summary.append({
                    'user_email': user_email,
                    'status': status
                })

            summary_email_data.append({
                'product_name': effective_product_name, # Use potentially updated name
                'product_url': product_api_url,
                'subscriptions': current_product_subscription_summary
            })

            # Update last_checked_at for all subscriptions that were determined to be active/due for this product run
            # This list is 'active_subscriptions_due_check'. If it's empty (e.g. no subs, or none were due), this loop won't run.
            if active_subscriptions_due_check: # Check if the list is not empty
                update_lca_url = f"{config.APP_BASE_URL}/api/subscriptions"
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

    # Send summary email
    run_timestamp_utc = datetime.now(timezone.utc) # Ensure it's UTC

    # Convert to IST
    ist_timezone_offset = timedelta(hours=5, minutes=30)
    if pytz:
        try:
            ist_tz = pytz.timezone('Asia/Kolkata')
            run_timestamp_ist = run_timestamp_utc.astimezone(ist_tz)
        except pytz.UnknownTimeZoneError:
            print("Warning: pytz could not find 'Asia/Kolkata'. Falling back to fixed offset for IST.")
            fixed_ist_tz = timezone(ist_timezone_offset)
            run_timestamp_ist = run_timestamp_utc.replace(tzinfo=timezone.utc).astimezone(fixed_ist_tz)
    else: # pytz is not available
        print("Warning: pytz library not available. Using fixed offset for IST.")
        fixed_ist_tz = timezone(ist_timezone_offset)
        run_timestamp_ist = run_timestamp_utc.replace(tzinfo=timezone.utc).astimezone(fixed_ist_tz)

    # Format the IST timestamp
    # Desired format: "DD-Month-YYYY / HH:MM AM/PM, IST"
    month_name = run_timestamp_ist.strftime('%B')
    run_timestamp_str = run_timestamp_ist.strftime(f'%d-{month_name}-%Y / %I:%M %p') + ", IST"

    summary_subject = f"Stock Check Summary: {run_timestamp_str} - {total_actual_notifications_sent} User Notifications Sent"
    summary_body = format_summary_email_body(run_timestamp_str, summary_email_data, total_actual_notifications_sent)

    if config.EMAIL_SENDER: # Check if a sender email is configured (used as recipient for summary)
        summary_recipient_list = [config.EMAIL_SENDER]
        print(f"\nAttempting to send summary email to: {config.EMAIL_SENDER}")
        try:
            notifications.send_email_notification(
                subject=summary_subject,
                body=summary_body,
                sender=config.EMAIL_SENDER, # Assuming summary is sent from the primary sender identity
                recipients=summary_recipient_list,
                host=config.EMAIL_HOST,
                port=config.EMAIL_PORT,
                username=config.EMAIL_HOST_USER,
                password=config.EMAIL_HOST_PASSWORD
            )
            print("✅ Summary email sent successfully.")
        except Exception as e:
            print(f"🚨 Error sending summary email: {e}")
    else:
        print("\n⚠️ EMAIL_SENDER not configured in config.py. Skipping summary email.")
        # Optionally, print the summary body to console if not sending email
        # print("\n--- Summary Email Body (Not Sent) ---")
        # print(summary_body)
        # print("--- End of Summary Email Body ---")

def calculate_next_check_due(last_checked_at_dt: datetime, freq_days: int, freq_hours: int, freq_minutes: int) -> datetime:
    """Calculates the next due time based on the last checked time and frequency components."""
    if last_checked_at_dt.tzinfo is None: # Ensure last_checked_at_dt is offset-aware
        print(f"Warning: last_checked_at_dt is naive: {last_checked_at_dt}. Assuming UTC.")
        last_checked_at_dt = last_checked_at_dt.replace(tzinfo=timezone.utc)

    return last_checked_at_dt + timedelta(days=freq_days, hours=freq_hours, minutes=freq_minutes)

if __name__ == "__main__":
    asyncio.run(main())
