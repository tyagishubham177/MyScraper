import asyncio
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

                    subscriptions_url = f"{config.APP_BASE_URL}/api/subscriptions?product_id={product_id}"
                    product_subscriptions = await fetch_api_data(session, subscriptions_url)

                    if product_subscriptions and isinstance(product_subscriptions, list):
                        subscribed_recipient_ids = {
                            s.get('recipient_id') for s in product_subscriptions
                            if isinstance(s, dict) and s.get('recipient_id')
                        }

                        if not subscribed_recipient_ids:
                            print(f"Product '{effective_product_name}' is in stock, but no recipient IDs found in its subscriptions via API.")
                            continue

                        email_list_for_product = [
                            recipients_map[rid] for rid in subscribed_recipient_ids if rid in recipients_map
                        ]

                        if email_list_for_product:
                            email_subject = f"{effective_product_name.strip()} In Stock Alert!"
                            email_body = notifications.format_long_message(effective_product_name, product_api_url)

                            print(f"Attempting to send notifications to: {', '.join(email_list_for_product)}")
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
                            else:
                                print("⚠️ Email configuration missing or invalid (EMAIL_HOST, EMAIL_SENDER), cannot send email.")
                        else:
                            print(f"Product '{effective_product_name}' is in stock, but no valid & subscribed recipients found via API after mapping IDs to emails.")
                    else:
                        print(f"Could not fetch subscriptions or data was invalid for product ID {product_id} (Name: '{effective_product_name}'). API returned: {product_subscriptions}")
                else:
                    print(f"❌ Product '{effective_product_name}' (URL: {product_api_url}) is OUT OF STOCK or information is unavailable.")

            except Exception as e:
                print(f"🚨 An error occurred while processing product {product_name_api} (URL: {product_api_url}): {e}")

            # Respectful delay, ensure DELAY_BETWEEN_REQUESTS is defined in config
            delay = getattr(config, 'DELAY_BETWEEN_REQUESTS', 1) # Default to 1s if not defined
            await asyncio.sleep(delay)

    print("\nStock check finished.")

if __name__ == "__main__":
    asyncio.run(main())
