"""Read-only storefront diagnostics; never imports notification or account code."""
import asyncio
import json
from playwright.async_api import async_playwright

URL = "https://shop.amul.com/en/product/amul-high-protein-rose-lassi-200-ml-or-pack-of-30"

async def main():
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        page = await browser.new_page()
        await page.goto(URL)
        await page.wait_for_load_state("networkidle")
        async def snapshot(label):
            print(label, page.url, json.dumps(await page.evaluate("""() => Array.from(document.querySelectorAll('h1, input, .modal, button, a, [class*=product], [class*=pincode]')).filter(e => e.matches('h1,input,.modal') || /add.to.cart|notify me|sold out|pincode/i.test(e.textContent) && e.textContent.length < 120).map(e=>({tag:e.tagName,id:e.id,class:e.className,text:e.textContent.trim().slice(0,120),placeholder:e.getAttribute('placeholder'),visible:!!(e.offsetWidth||e.offsetHeight||e.getClientRects().length)})).slice(0,100)""")))
        await snapshot("BEFORE PIN")
        pin = page.locator('input#search:visible')
        await pin.wait_for(timeout=10000)
        if await pin.count():
            await pin.fill("201305")
            suggestion = page.locator("#automatic a.searchitem-name:has-text('201305')")
            await suggestion.wait_for(timeout=10000)
            await suggestion.click()
            await page.wait_for_load_state("networkidle")
            await page.wait_for_timeout(5000)
        await snapshot("AFTER PIN")
        print("BODY", (await page.locator("body").inner_text())[:6000])
        print("MODAL HTML", (await page.locator("#locationWidgetModal").inner_html())[:12000])
        await browser.close()

if __name__ == "__main__":
    asyncio.run(main())
