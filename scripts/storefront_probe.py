"""Read-only live regression checks; no notifications or account code."""
import asyncio
from playwright.async_api import async_playwright
from scripts.scraper import check_product_availability

SLUGS = [
    "amul-high-protein-rose-lassi-200-ml-or-pack-of-30",
    "amul-high-protein-plain-lassi-200-ml-or-pack-of-30",
    "amul-whey-protein-32-g-or-pack-of-30-sachets",
    "amul-high-protein-buttermilk-200-ml-or-pack-of-30",
]

async def main():
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        try:
            for pin in ["201305", "247001", "410206"]:
                context = await browser.new_context()
                try:
                    for index, slug in enumerate(SLUGS):
                        page = await context.new_page()
                        try:
                            result = await check_product_availability(
                                "https://shop.amul.com/en/product/" + slug,
                                pin, page=page, skip_pincode=bool(index), log_prefix=pin
                            )
                            print("LIVE CHECK PASSED", pin, slug, result)
                        except Exception:
                            print("FAILED PAGE", page.url, (await page.locator("body").inner_text())[:1500])
                            raise
                        finally:
                            await page.close()
                finally:
                    await context.close()
        finally:
            await browser.close()

if __name__ == "__main__":
    asyncio.run(main())
