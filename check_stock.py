import asyncio
import json
import os
import config
import notifications
import scraper

# Define the path to the db.json file
# Assuming check_stock.py is in the root directory along with the 'web' folder
DB_PATH = os.path.join(os.path.dirname(__file__), 'web', 'data', 'db.json')
if not os.path.exists(os.path.dirname(DB_PATH)): # Ensure web/data exists for initial setup
    try:
        os.makedirs(os.path.dirname(DB_PATH))
        print(f"Created directory {os.path.dirname(DB_PATH)} as it did not exist.")
    except OSError as e:
        print(f"Error creating directory {os.path.dirname(DB_PATH)}: {e}")


def load_db(db_path):
    """Loads the database from a JSON file."""
    default_data = {"products": [], "recipients": [], "subscriptions": []}
    try:
        if not os.path.exists(db_path):
            print(f"Warning: Database file not found at {db_path}. Returning default empty structure.")
            # Create an empty db.json if it doesn't exist so UI doesn't break on first run
            with open(db_path, 'w') as f:
                json.dump(default_data, f, indent=2)
            print(f"Created an empty database file at {db_path}.")
            return default_data

        with open(db_path, 'r') as f:
            data = json.load(f)
            # Validate basic structure
            if not all(key in data for key in ["products", "recipients", "subscriptions"]):
                print(f"Warning: Database file {db_path} is missing one or more root keys (products, recipients, subscriptions). Returning default structure.")
                return default_data
            return data
    except FileNotFoundError:
        print(f"Warning: Database file not found at {db_path}. This should have been handled by os.path.exists, but catching anyway.")
        return default_data
    except json.JSONDecodeError:
        print(f"Warning: Error decoding JSON from {db_path}. File might be corrupted. Returning default structure.")
        return default_data
    except Exception as e:
        print(f"An unexpected error occurred loading the database: {e}. Returning default structure.")
        return default_data


async def main():
    print("Starting dynamic stock check based on db.json...")
    db_data = load_db(DB_PATH)

    recipients_map = {r['id']: r['email'] for r in db_data.get('recipients', []) if r.get('id') and r.get('email')}
    all_products = db_data.get('products', [])

    if not all_products:
        print("No products found in the database (db.json). Exiting.")
        return

    if not recipients_map:
        print("No recipients found in the database. Notifications for in-stock items may not be sent unless subscriptions are empty.")

    for product_info in all_products:
        product_id = product_info.get('id')
        product_url = product_info.get('url')
        product_name_db = product_info.get('name', 'N/A') # Name from DB for logging

        if not product_id or not product_url:
            print(f"⚠️ Skipping product due to missing ID or URL: {product_info}")
            continue

        print(f"\nChecking product: '{product_name_db}' (ID: {product_id}) at URL: {product_url}")

        try:
            in_stock, product_name_scraper = await scraper.check_product_availability(product_url, config.PINCODE)
            # Use DB name if scraper returns empty, otherwise prefer scraper's potentially updated name
            effective_product_name = product_name_scraper if product_name_scraper else product_name_db


            if in_stock:
                print(f"✅ Product '{effective_product_name}' (URL: {product_url}) is IN STOCK.")

                product_subscriptions = [s for s in db_data.get('subscriptions', []) if s.get('product_id') == product_id]

                if product_subscriptions:
                    subscribed_recipient_ids = {s['recipient_id'] for s in product_subscriptions if s.get('recipient_id')}

                    if not subscribed_recipient_ids:
                        print("Product is in stock, but no recipient IDs found in its subscriptions.")
                        continue

                    email_list_for_product = [recipients_map[rid] for rid in subscribed_recipient_ids if rid in recipients_map]

                    if email_list_for_product:
                        email_subject = f"{effective_product_name.strip()} In Stock Alert!"
                        email_body = notifications.format_long_message(effective_product_name, product_url)

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
                        print("Product is in stock, but no valid & subscribed recipients found after mapping IDs to emails.")
                else:
                    print("Product is in stock, but no subscriptions found for it in db.json.")
            else:
                print(f"❌ Product '{effective_product_name}' (URL: {product_url}) is OUT OF STOCK or information is unavailable.")

        except Exception as e:
            print(f"🚨 An error occurred while checking product {product_name_db} (URL: {product_url}): {e}")
            # Optionally, decide if you want to continue to the next product or stop
            # For now, we'll continue

        await asyncio.sleep(config.DELAY_BETWEEN_REQUESTS) # Respectful delay

    print("\nStock check finished.")

if __name__ == "__main__":
    # Ensure DB_PATH is correct if __file__ is not where you expect (e.g. when bundled)
    # For most direct script runs, os.path.dirname(__file__) is reliable.
    # print(f"Database path configured to: {DB_PATH}")
    asyncio.run(main())
