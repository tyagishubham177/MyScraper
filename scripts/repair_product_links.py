"""Apply the approved legacy link corrections without exporting configuration.

Run before the stock checker. Once the old entries are corrected this only reads
and validates the product list; it does not repeat browser checks or writes.
"""
import asyncio
import argparse
from contextlib import redirect_stdout
import io
import os
import sys
from urllib.parse import urlsplit

if __package__ is None and __name__ == "__main__":
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import aiohttp
from playwright.async_api import async_playwright
from scripts import config, scraper
from scripts.validation import configured_product_url, product_url

BLUEBERRY_ID = "1758622977117"
OLD_BLUEBERRY_URL = "https://shop.amul.com/en/product/amul-high-protein-blueberry-shake-200-ml-or-pack-of-8"
BLUEBERRY_URL = "https://shop.amul.com/en/product/amul-high-protein-blueberry-shake-200-ml-or-pack-of-30"
BLUEBERRY_NAME = "Amul High Protein Blueberry Shake, 200 mL | Pack of 30"


def plan_repairs(products):
    """Return exact before/after records; never substitute an unrelated item."""
    if not isinstance(products, list):
        raise RuntimeError("Invalid product configuration")
    repairs = []
    ids = set()
    for product in products:
        if not isinstance(product, dict) or not product.get("id"):
            raise RuntimeError("Invalid product configuration")
        pid = str(product["id"])
        if pid in ids:
            raise RuntimeError("Duplicate product identifier")
        ids.add(pid)
        before = dict(product)
        after = dict(product)
        url = product.get("url")
        name = product.get("name")
        if not isinstance(name, str) or not name.strip():
            raise RuntimeError("Product label requires review")
        if pid == BLUEBERRY_ID and url == OLD_BLUEBERRY_URL:
            after.update(url=BLUEBERRY_URL, name=BLUEBERRY_NAME)
        else:
            try:
                canonical = configured_product_url(url)
            except ValueError:
                parsed = urlsplit(url) if isinstance(url, str) else None
                # Describe structure only; never print configuration values.
                shape = {
                    "https": bool(parsed and parsed.scheme == 'https'),
                    "http": bool(parsed and parsed.scheme == 'http'),
                    "amul_host": bool(parsed and parsed.hostname == 'shop.amul.com'),
                    "product_path": bool(parsed and parsed.path.startswith('/en/product/')),
                    "query": bool(parsed and parsed.query),
                    "fragment": bool(parsed and parsed.fragment),
                    "embedded_url": bool(parsed and 'https://' in parsed.path),
                }
                raise RuntimeError(f"An unrecognized product URL requires review; shape={shape}") from None
            # Only repair the demonstrated duplicated-path corruption. Ordinary
            # canonical links and custom labels are left exactly as stored.
            if "https://shop.amul.com/enhttps://" in url:
                after["url"] = canonical
        if after != before:
            repairs.append((before, after))
    return repairs


async def read_products(session):
    async with session.get(f"{config.APP_BASE_URL}/api/products") as response:
        if response.status != 200:
            raise RuntimeError("Could not read product configuration for repair")
        return await response.json()


async def verify_product_pages(products, repairs):
    replacements = {str(after["id"]): after for _, after in repairs}
    # The existing scraper logs public-page details. Keep these transient
    # diagnostics in memory so this repair does not export selected products.
    with redirect_stdout(io.StringIO()):
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True, args=["--no-sandbox"])
            try:
                context = await browser.new_context()
                for product in products:
                    candidate = replacements.get(str(product["id"]), product)
                    url = product_url(candidate["url"])
                    page = await context.new_page()
                    try:
                        _, name = await scraper.check_product_availability(
                            url, config.PINCODE, page=page, skip_pincode=False
                        )
                        if url == BLUEBERRY_URL and " ".join(name.split()) != BLUEBERRY_NAME:
                            raise RuntimeError("Replacement product identity did not match")
                    except Exception:
                        raise RuntimeError("A product link could not be reliably verified; no repairs applied") from None
                    finally:
                        await page.close()
            finally:
                await browser.close()


async def admin_token(session):
    if config.ADMIN_TOKEN:
        return config.ADMIN_TOKEN
    if not config.ADMIN_EMAIL or not config.ADMIN_PASSWORD:
        raise RuntimeError("Admin authentication is required for approved link repairs")
    async with session.post(
        f"{config.APP_BASE_URL}/api/login",
        json={"email": config.ADMIN_EMAIL, "password": config.ADMIN_PASSWORD},
    ) as response:
        if response.status != 200:
            raise RuntimeError("Admin authentication failed during link repair")
        token = (await response.json()).get("token")
    if not isinstance(token, str) or not token:
        raise RuntimeError("Admin authentication returned no token")
    return token


async def apply_repair(session, token, before, after):
    # Reconcile a previous uncertain write and check for concurrent changes
    # before retrying. A different record is never overwritten automatically.
    current = next((p for p in await read_products(session) if p.get("id") == before["id"]), None)
    if current == after:
        return
    if current != before:
        raise RuntimeError("Product changed since repair planning; review required")
    async with session.put(
        f"{config.APP_BASE_URL}/api/products",
        params={"id": before["id"]},
        headers={"Authorization": f"Bearer {token}"},
        json={"url": after["url"], "name": after["name"]},
    ) as response:
        if response.status != 200:
            raise RuntimeError("Product update failed; reconcile configuration before retrying")
    observed = next((p for p in await read_products(session) if p.get("id") == after["id"]), None)
    if observed != after:
        raise RuntimeError("Product update outcome is uncertain; reconcile before retrying")


async def main(check_only=False):
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
        products = await read_products(session)
        repairs = plan_repairs(products)
        if check_only:
            await verify_product_pages(products, repairs)
            print(f"Verified {len(products)} product links; {len(repairs)} approved corrections planned; no writes performed.")
            return
        if not repairs:
            print("Product link migration already applied; no configuration writes needed.")
            return
        # Complete validation of every configured link before the first write.
        await verify_product_pages(products, repairs)
        token = await admin_token(session)
        for before, after in repairs:
            await apply_repair(session, token, before, after)
        print(f"Verified {len(products)} product links; applied {len(repairs)} approved corrections.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-only", action="store_true", help="Verify the repair plan without authentication or writes")
    asyncio.run(main(check_only=parser.parse_args().check_only))
