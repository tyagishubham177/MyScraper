"""Apply the approved legacy link corrections without exporting configuration.

Run before the stock checker. Once the old entries are corrected this only reads
and validates the product list; it does not repeat browser checks or writes.
"""
import asyncio
import argparse
from contextlib import redirect_stdout
import io
import json
import os
import re
import sys
from urllib.parse import urlsplit

if __package__ is None and __name__ == "__main__":
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import aiohttp
from playwright.async_api import async_playwright
from scripts import config
from scripts.validation import configured_product_url, product_url

BLUEBERRY_ID = "1758622977117"
OLD_BLUEBERRY_URL = "https://shop.amul.com/en/product/amul-high-protein-blueberry-shake-200-ml-or-pack-of-8"
BLUEBERRY_URL = "https://shop.amul.com/en/product/amul-high-protein-blueberry-shake-200-ml-or-pack-of-30"
BLUEBERRY_NAME = "Amul High Protein Blueberry Shake, 200 mL | Pack of 30"
# Public corporate address published at https://shop.amul.com/en/contact.
# This catalogue browsing location is unrelated to any user's configuration.
PUBLIC_CATALOG_POSTAL_CODE = "388001"


class UnrecognizedProductURL(RuntimeError):
    def __init__(self, product):
        super().__init__("An unrecognized product URL requires review")
        self.product = product


def copied_url_candidates(value):
    """Enumerate only canonical Amul identities in same-origin copied URLs."""
    origin = 'https://shop.amul.com'
    if not isinstance(value, str):
        raise RuntimeError('Copied URL cannot be safely resolved')
    value = value.strip()
    parts = value.split(origin)
    parsed = urlsplit(value)
    if (parts[0] or len(parts) < 3 or len(parts) - 1 != value.count('https://')
            or 'http://' in value or parsed.query or parsed.fragment):
        raise RuntimeError('Copied URL cannot be safely resolved')
    slugs = {slug for part in parts[1:]
             for slug in re.findall(r'/product/([a-z0-9-]+)(?=/|$)', part)}
    tokens = [token for part in parts[1:] for token in part.split('/') if token]
    if not slugs or len(slugs) > 5 or any(token not in slugs | {'en', 'product'} for token in tokens):
        raise RuntimeError('Copied URL cannot be safely resolved')
    return sorted(product_url(origin + '/en/product/' + slug) for slug in slugs)


def match_product_label(names_by_url, expected_name):
    expected = ' '.join(expected_name.split()).casefold()
    matches = [url for url, name in names_by_url.items()
               if ' '.join(name.split()).casefold() == expected]
    if len(matches) != 1:
        raise RuntimeError('Copied link identity is ambiguous; no repairs applied')
    return matches[0]


def public_identity(url, headings, documents):
    headings = {" ".join(name.split()) for name in headings if name.strip()}
    if len(headings) == 1:
        return next(iter(headings))
    names = set()
    def visit(value):
        if isinstance(value, list):
            for item in value: visit(item)
        elif isinstance(value, dict):
            types = value.get('@type', [])
            types = [types] if isinstance(types, str) else types
            if 'Product' in types and isinstance(value.get('name'), str):
                link = value.get('url')
                try:
                    matches_url = not link or product_url(link) == url
                except ValueError:
                    matches_url = False
                if matches_url and value['name'].strip():
                    names.add(" ".join(value['name'].split()))
            for item in value.values(): visit(item)
    for document in documents: visit(document)
    if len(names) != 1:
        raise RuntimeError('Public product identity is unavailable or ambiguous')
    return next(iter(names))


async def public_product_name(page, url):
    response = await page.goto(url, timeout=30000)
    if response is not None and response.status >= 400:
        raise RuntimeError('Public product page is unavailable')
    if product_url(page.url) != url:
        raise RuntimeError('Public product page changed identity')
    for attempt in range(2):
        headings = await page.locator('h1.product-name').all_text_contents()
        documents = []
        for raw in await page.locator('script[type="application/ld+json"]').all_text_contents():
            try: documents.append(json.loads(raw))
            except (ValueError, TypeError): pass
        try:
            return public_identity(url, headings, documents)
        except RuntimeError:
            if attempt: raise
            await page.wait_for_timeout(1000)


async def initialize_public_catalog(context):
    """Unlock the anonymous catalogue using only Amul's public office address."""
    page = await context.new_page()
    try:
        await page.goto('https://shop.amul.com/', timeout=30000)
        await page.wait_for_load_state('networkidle')
        await page.wait_for_timeout(500)
        modal = await page.query_selector('#locationWidgetModal')
        if modal and await modal.is_visible():
            await page.locator('#search:visible').fill(PUBLIC_CATALOG_POSTAL_CODE)
            suggestion = page.locator(f"#automatic a.searchitem-name:has-text('{PUBLIC_CATALOG_POSTAL_CODE}')")
            await suggestion.wait_for(timeout=10000)
            await suggestion.click()
            await page.locator('#locationWidgetModal').wait_for(state='hidden', timeout=15000)
            await page.wait_for_load_state('networkidle')
    finally:
        await page.close()


async def resolve_copied_url(product):
    candidates = copied_url_candidates(product['url'])
    names = {}
    with redirect_stdout(io.StringIO()):
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True, args=['--no-sandbox'])
            try:
                context = await browser.new_context()
                await initialize_public_catalog(context)
                for url in candidates:
                    page = await context.new_page()
                    try:
                        names[url] = await public_product_name(page, url)
                    except Exception:
                        continue
                    finally:
                        await page.close()
            finally:
                await browser.close()
    return match_product_label(names, product['name'])


def plan_repairs(products, resolved_urls=None):
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
                canonical = (product_url(resolved_urls[pid]) if resolved_urls and pid in resolved_urls
                             else configured_product_url(url))
            except ValueError:
                raise UnrecognizedProductURL(product) from None
            # Only repair the demonstrated duplicated-path corruption. Ordinary
            # canonical links and custom labels are left exactly as stored.
            if url.count("https://") > 1:
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
    """Verify public identity only; no recipient data or private locations."""
    replacements = {str(after['id']): after for _, after in repairs}
    unverified = set()
    with redirect_stdout(io.StringIO()):
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True, args=['--no-sandbox'])
            try:
                context = await browser.new_context()
                await initialize_public_catalog(context)
                semaphore = asyncio.Semaphore(3)
                async def verify(product):
                    async with semaphore:
                        candidate = replacements.get(str(product['id']), product)
                        page = await context.new_page()
                        try:
                            url = product_url(candidate['url'])
                            name = await public_product_name(page, url)
                            if url == BLUEBERRY_URL and name != BLUEBERRY_NAME:
                                raise RuntimeError('Replacement product identity did not match')
                        except Exception:
                            unverified.add(str(product['id']))
                        finally:
                            await page.close()
                async with asyncio.TaskGroup() as group:
                    for product in products:
                        group.create_task(verify(product))
            finally:
                await browser.close()
    return unverified


def collect_repairs(products):
    if not isinstance(products, list):
        raise RuntimeError('Invalid product configuration')
    repairs, unknown, ids = [], [], set()
    for product in products:
        if not isinstance(product, dict) or not product.get('id'):
            raise RuntimeError('Invalid product configuration')
        pid = str(product['id'])
        if pid in ids:
            raise RuntimeError('Duplicate product identifier')
        ids.add(pid)
        try:
            repairs.extend(plan_repairs([product]))
        except UnrecognizedProductURL:
            unknown.append(product)
    return repairs, unknown


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
        repairs, unknown = collect_repairs(products)
        if not repairs and not check_only:
            print(f"Product link migration already applied; no configuration writes needed. {len(unknown)} unresolved links preserved for review.")
            return
        print(f"Product link audit: {len(products)} entries; {len(repairs)} deterministic corrections; {len(unknown)} copied links require identity checks.")
        unresolved = set()
        for product in unknown:
            try:
                # If copied fragments name different products, retain only a
                # unique live page matching the existing full label and pack.
                url = await resolve_copied_url(product)
                repairs.extend(plan_repairs([product], {str(product['id']): url}))
            except RuntimeError:
                unresolved.add(str(product['id']))
        candidates = [p for p in products if str(p['id']) not in unresolved]
        unverified = await verify_product_pages(candidates, repairs) or set()
        if (BLUEBERRY_ID in unverified and any(str(before['id']) == BLUEBERRY_ID
                                             for before, _ in repairs)):
            raise RuntimeError('Approved blueberry replacement could not be verified; no repairs applied')
        unresolved.update(unverified)
        repairs = [(before, after) for before, after in repairs if str(before['id']) not in unresolved]
        verified_count = len(products) - len(unresolved)
        if check_only:
            print(f"Verified {verified_count} product links; {len(repairs)} approved corrections planned; {len(unresolved)} unresolved links unchanged; no writes performed.")
            return
        if not repairs:
            print(f"No verified corrections to apply; {len(unresolved)} unresolved links unchanged.")
            return
        # Validate every planned correction before the first write. Unrelated
        # ambiguous/unavailable items stay unchanged and are never stock results.
        token = await admin_token(session)
        for before, after in repairs:
            await apply_repair(session, token, before, after)
        print(f"Verified {verified_count} product links; applied {len(repairs)} approved corrections; {len(unresolved)} unresolved links unchanged for review.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-only", action="store_true", help="Verify the repair plan without authentication or writes")
    asyncio.run(main(check_only=parser.parse_args().check_only))
