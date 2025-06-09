import asyncio
# import os # No longer needed in this file directly
import config
import notifications
import scraper


async def main():
    print("Starting stock check...")

    # Get product availability status and name from scraper
    # Uses URL and PINCODE from the config module
    in_stock, product_name = await scraper.check_product_availability(config.URL, config.PINCODE)

    if in_stock:
        print(f"Product '{product_name}' is IN STOCK.")
        # Format messages
        email_subject = f"{product_name.strip()} In Stock Alert!"
        email_body = notifications.format_long_message(product_name, config.URL)
        # short_message = notifications.format_short_message(product_name) # For SMS if used

        # Send email notification
        # Ensure EMAIL_RECIPIENTS is split into a list if it's a comma-separated string
        recipients_list = []
        if config.EMAIL_RECIPIENTS:
            recipients_list = [r.strip() for r in config.EMAIL_RECIPIENTS.split(',') if r.strip()]

        if config.EMAIL_HOST and config.EMAIL_SENDER and recipients_list:
            notifications.send_email_notification(
                subject=email_subject,
                body=email_body,
                sender=config.EMAIL_SENDER,
                recipients=recipients_list,
                host=config.EMAIL_HOST,
                port=config.EMAIL_PORT, # This is already an int from config.py
                username=config.EMAIL_HOST_USER,
                password=config.EMAIL_HOST_PASSWORD
            )
        else:
            print("⚠️ Email configuration missing or invalid (EMAIL_HOST, EMAIL_SENDER, EMAIL_RECIPIENTS), cannot send email.")

        # Call SMS notification if it were to be used
        # notifications.send_fast2sms(short_message) # Example
    else:
        print(f"Product '{product_name}' is OUT OF STOCK or information is unavailable.")

    print("Stock check finished.")

if __name__ == "__main__":
    asyncio.run(main())
