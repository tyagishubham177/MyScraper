"""Regressions for real checker boundaries. No SMTP, HTTP or browser network I/O."""
import asyncio
from datetime import time
from types import SimpleNamespace

import pytest
from scripts.validation import CheckError, product_url, pincode
from tests.test_scraper import MockPage, MockElementHandle
from tests import test_check_stock as stock_tests
from scripts import scraper

URL = 'https://shop.amul.com/en/product/test-product'
PIN_SELECTOR = 'div.d-flex.flex-column.loc_area.overflow-hidden.text-turncate span'
NAME_SELECTOR = 'h1.product-name.mb-2.fw-bold.lh-sm.text-dark.h3.mb-4'


@pytest.mark.parametrize('url', [
    'http://shop.amul.com/en/product/demo',
    'https://shop.amul.com.evil.invalid/en/product/demo',
    'https://user:secret@shop.amul.com/en/product/demo',
    'https://shop.amul.com:443/en/product/demo',
    'https://shop.amul.com/enhttps://shop.amul.com/en/product/demo',
    'https://shop.amul.com/en/product/demo?x=1',
    'https://shop.amul.com/en/product/demo#fragment',
    'https://shop.amul.com/en/product/../admin', None,
])
def test_reject_invalid_product_urls(url):
    with pytest.raises(ValueError): product_url(url)


def test_url_normalization_preserves_product_identity():
    assert product_url('  '+URL+'/  ') == URL


@pytest.mark.parametrize('pin', ['12345', '1234567', ' 123456', 'abcdef', '１２３４５６', None, 123456])
def test_reject_invalid_pincodes(pin):
    with pytest.raises(ValueError): pincode(pin)


def page_for(pin='123456'):
    return MockPage(selectors_config={
        PIN_SELECTOR: {'text_content': 'Delivery '+pin},
        NAME_SELECTOR: {'text_content': 'Example product'},
        'a.btn.btn-primary.add-to-cart:not(.disabled)': {'visible': True, 'enabled': True},
    })


@pytest.mark.asyncio
async def test_reused_context_still_verifies_pincode():
    page = page_for('654321')
    with pytest.raises(CheckError, match='Pincode verification failed'):
        await scraper._check_availability_on_page(page, URL, '123456', True)
    assert page.screenshot_path  # Retain evidence for a failed confirmation.


@pytest.mark.asyncio
async def test_http_error_and_cross_product_redirect_are_not_out_of_stock():
    page = page_for()
    async def http_error(*args, **kwargs): return SimpleNamespace(status=404)
    page.goto = http_error
    with pytest.raises(CheckError, match='HTTP 404'):
        await scraper._check_availability_on_page(page, URL, '123456', False)
    async def redirect(*args, **kwargs):
        page.url = 'https://shop.amul.com/en/product/another-product'
        return SimpleNamespace(status=200)
    page.goto = redirect
    with pytest.raises(CheckError, match='Unexpected product redirect'):
        await scraper._check_availability_on_page(page, URL, '123456', False)


@pytest.mark.asyncio
async def test_screenshots_do_not_overwrite_other_checks():
    page = page_for()
    await scraper._check_availability_on_page(page, URL, '123456', True)
    first = page.screenshot_path
    await scraper._check_availability_on_page(page, URL, '123456', True)
    assert first != page.screenshot_path
    assert '123456_' in first


@pytest.mark.asyncio
@pytest.mark.parametrize('outcome', ['refuse-one', 'fail', 'no-result'])
async def test_notify_users_never_counts_failed_or_unknown_delivery(monkeypatch, outcome):
    mod = stock_tests.notifications_util
    monkeypatch.setattr(mod.config, 'EMAIL_HOST', 'smtp.example.invalid')
    monkeypatch.setattr(mod.config, 'EMAIL_SENDER', 'sender@example.invalid')
    async def transport(**kwargs):
        if outcome == 'fail': raise TimeoutError('simulated')
        if outcome == 'no-result': return None
        return {'a@example.invalid': True, 'b@example.invalid': False}
    monkeypatch.setattr(mod.notifications, 'send_email_notification', transport)
    summaries, count = await mod.notify_users('Example', URL,
        [{'recipient_id':'a'}, {'recipient_id':'b'}, {'recipient_id':'a'}],
        {'a':{'email':'a@example.invalid'}, 'b':{'email':'b@example.invalid'}}, time(12), '123456')
    assert count == (1 if outcome == 'refuse-one' else 0)
    assert all(s['status'] != 'Sent' for s in summaries if s['user_email'] == 'b@example.invalid')
    if outcome != 'refuse-one': assert all(s['status'] != 'Sent' for s in summaries)


@pytest.fixture
def orchestrator(monkeypatch):
    mod = stock_tests.check_stock
    events = dict(pages=0, peak_pages=0, contexts=0, peak_contexts=0, calls=0, closed=False, saved=None)
    recipients = {str(n):{'email':f'{n}@example.invalid','pincode':str(100000+n)} for n in range(8)}
    products = [{'id':'one','url':URL}, {'id':'two','url':URL}]
    subs = {p['id']:[{'recipient_id':rid} for rid in recipients] for p in products}
    counters = {'one|100000':7}
    events['counters'] = counters
    async def bundle(session): return recipients, products, subs, counters
    async def save(session, data): events['saved'] = dict(data)
    monkeypatch.setattr(mod.api_utils, 'load_configuration_bundle', bundle)
    monkeypatch.setattr(mod.api_utils, 'save_stock_counters', save)
    monkeypatch.setattr(mod.config, 'ADMIN_TOKEN', 'fake-test-token')
    monkeypatch.setattr(mod.config, 'MAX_PARALLEL_PAGE_CHECKS', 2)
    monkeypatch.setattr(mod.config, 'EMAIL_SENDER', None)
    class Session:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
    monkeypatch.setattr(mod.aiohttp, 'ClientSession', Session)
    class Page:
        async def close(self): events['pages'] -= 1
    class Context:
        async def new_page(self):
            events['pages'] += 1
            events['peak_pages'] = max(events['peak_pages'], events['pages'])
            return Page()
        async def close(self): events['contexts'] -= 1
    class Browser:
        async def new_context(self):
            if events.get('init_error'): raise RuntimeError('context initialization failed')
            events['contexts'] += 1
            events['peak_contexts'] = max(events['peak_contexts'], events['contexts'])
            return Context()
        async def close(self): events['closed'] = True
    class Playwright:
        chromium = SimpleNamespace(launch=lambda **kwargs: launch())
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
    async def launch(): return Browser()
    async def process(session, page, info, recips, now, skip, mapping, pin):
        events['calls'] += 1
        await asyncio.sleep(.001)
        if events.get('worker_error'): raise RuntimeError('worker failed')
        if events.get('unknown') and info['id'] == 'one':
            return {'product_id':'one','pincode':pin,'state':'ERROR'}, 0, False
        return {'product_id':info['id'],'pincode':pin,'in_stock':events.get('in_stock', False),'subscriptions':[]}, events.get('sent', 0), True
    monkeypatch.setattr(mod, 'async_playwright', Playwright)
    monkeypatch.setattr(mod, 'process_product', process)
    return mod, events, subs


@pytest.mark.asyncio
async def test_global_limit_applies_across_all_pincodes(orchestrator):
    mod, events, _ = orchestrator
    await mod.main()
    assert events['calls'] == 16
    assert events['peak_pages'] <= 2 and events['peak_contexts'] <= 3
    assert events['pages'] == events['contexts'] == 0 and events['closed']


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ['init_error','worker_error'])
async def test_worker_failure_drains_children_and_closes_browser(orchestrator, kind):
    mod, events, _ = orchestrator
    events[kind] = True
    with pytest.raises(ExceptionGroup): await mod.main()
    assert events['closed']
    assert events['pages'] == events['contexts'] == 0


@pytest.mark.asyncio
async def test_cancellation_drains_children_and_closes_browser(orchestrator):
    mod, events, _ = orchestrator
    task = asyncio.create_task(mod.main())
    while events['calls'] == 0: await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError): await task
    assert events['closed']
    assert events['pages'] == events['contexts'] == 0


@pytest.mark.asyncio
async def test_unknown_results_preserve_streak_and_save_other_results(orchestrator):
    mod, events, _ = orchestrator
    events['unknown'] = True
    with pytest.raises(RuntimeError, match='Unreliable stock result'): await mod.main()
    assert events['saved']['one|100000'] == 7
    assert events['saved']['two|100000'] == 0
    assert events['closed']


@pytest.mark.asyncio
async def test_paused_groups_do_not_create_pages_or_reset_counters(orchestrator):
    mod, events, subs = orchestrator
    for entries in subs.values():
        for sub in entries: sub['paused'] = True
    await mod.main()
    assert events['calls'] == events['peak_pages'] == events['peak_contexts'] == 0
    assert events['saved'] == {'one|100000':7}


@pytest.mark.asyncio
@pytest.mark.parametrize('response', [None, {'paused':False}])
async def test_failed_auto_pause_never_changes_local_state_or_sends_notice(orchestrator, monkeypatch, response):
    mod, events, subs = orchestrator
    events['in_stock'] = True
    events['counters']['one|100000'] = 20
    async def fail_update(*args): return response
    async def unexpected_mail(**kwargs): pytest.fail('Unconfirmed pause sent a notice')
    monkeypatch.setattr(mod.api_utils, 'update_subscription', fail_update)
    monkeypatch.setattr(mod.notifications, 'send_email_notification', unexpected_mail)
    with pytest.raises(RuntimeError, match='Auto-pause was not persisted'): await mod.main()
    assert all(not sub.get('paused') for entries in subs.values() for sub in entries)
    assert events['saved']['one|100000'] == 21


@pytest.mark.asyncio
async def test_summary_refusal_is_not_logged_as_delivery(orchestrator, monkeypatch, capsys):
    mod, events, _ = orchestrator
    events['sent'] = 1
    monkeypatch.setattr(mod.config, 'EMAIL_SENDER', 'sender@example.invalid')
    monkeypatch.setattr(mod.config, 'EMAIL_HOST', 'smtp.example.invalid')
    async def refuse(**kwargs): return {'sender@example.invalid':False}
    monkeypatch.setattr(mod.notifications, 'send_email_notification', refuse)
    with pytest.raises(RuntimeError, match='Summary notification failed'): await mod.main()
    output = capsys.readouterr().out
    assert 'Summary email accepted' not in output
    assert 'Summary email was not accepted' in output
