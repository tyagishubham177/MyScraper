import inspect
import scraper
from scripts.notifications_util import notify_users
from scripts import stock_utils

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
            current_summary.append({"user_email": email, "status": "Not Sent - Out of Stock"})
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
