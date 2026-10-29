"""Read-only investigation of the one remaining configured product failure."""
import asyncio
from playwright.async_api import async_playwright
from scripts.scraper import check_product_availability
from scripts.repair_product_links import BLUEBERRY_NAME, BLUEBERRY_URL

async def main():
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        try:
            page = await browser.new_page()
            await page.goto('https://shop.amul.com/en/product/amul-high-protein-rose-lassi-200-ml-or-pack-of-30')
            await page.locator('input#search:visible').wait_for()
            await page.locator('input#search:visible').fill('302021')
            await page.locator("#automatic a.searchitem-name:has-text('302021')").click()
            await page.locator('h1.product-name').wait_for()
            await page.goto('https://shop.amul.com/en/product/amul-high-protein-blueberry-shake-200-ml-or-pack-of-8')
            await page.wait_for_timeout(15000)
            print('BLUEBERRY URL', page.url)
            print('BLUEBERRY BODY', (await page.locator('body').inner_text())[:6000])
            print('BLUEBERRY STRUCTURE', await page.evaluate("""() => Array.from(document.querySelectorAll('h1,.alert,.modal,[class*=loader], [class*=loading], [class*=error]')).map(e=>({tag:e.tagName,id:e.id,class:e.className,text:e.textContent.trim().slice(0,300),visible:!!(e.offsetWidth||e.offsetHeight||e.getClientRects().length)}))"""))
            result = await check_product_availability(BLUEBERRY_URL, '302021', page=page, skip_pincode=True)
            assert result[1] == BLUEBERRY_NAME
            print('APPROVED THIRTY-PACK VERIFIED', result)
        finally:
            await browser.close()

if __name__ == '__main__':
    asyncio.run(main())
