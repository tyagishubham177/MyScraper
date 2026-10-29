"""Inspect only the approved public product page, without location or account data."""
import asyncio
import json
from playwright.async_api import async_playwright
from scripts.repair_product_links import initialize_public_catalog

URL = 'https://shop.amul.com/en/product/amul-high-protein-blueberry-shake-200-ml-or-pack-of-30'

async def main():
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        try:
            context = await browser.new_context()
            await initialize_public_catalog(context)
            page = await context.new_page()
            response = await page.goto(URL)
            await page.wait_for_timeout(2000)
            result = await page.evaluate("""() => ({
                title: document.title,
                headings: Array.from(document.querySelectorAll('h1.product-name')).map(e=>e.textContent),
                meta: Array.from(document.querySelectorAll('meta[property="og:title"],meta[name="title"]')).map(e=>({key:e.getAttribute('property')||e.name,value:e.content})),
                microdata: Array.from(document.querySelectorAll('[itemtype*="schema.org/Product"]')).map(e=>({tag:e.tagName,name:e.querySelector('[itemprop="name"]')?.getAttribute('content')||e.querySelector('[itemprop="name"]')?.textContent,url:e.querySelector('[itemprop="url"]')?.getAttribute('content')})),
                scripts: Array.from(document.querySelectorAll('script[type="application/ld+json"]')).map(e=>{try {const x=JSON.parse(e.textContent); return {type:x['@type'],name:x.name,url:x.url,keys:Object.keys(x)}} catch {return {parseError:true}}})
            })""")
            print('PUBLIC PRODUCT IDENTITY', response.status, page.url, json.dumps(result))
        finally:
            await browser.close()

if __name__ == '__main__':
    asyncio.run(main())
