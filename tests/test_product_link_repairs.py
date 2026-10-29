"""Approved link migrations preserve identifiers and reject concurrent edits."""
import copy
import pytest
from scripts import repair_product_links as repair


def blueberry():
    return {"id": repair.BLUEBERRY_ID, "url": repair.OLD_BLUEBERRY_URL,
            "name": "Blueberry eight-pack", "metadata": {"keep": True}}


def test_plan_repairs_only_approved_links_and_preserves_metadata():
    other = {"id": "other", "url": "https://shop.amul.com/en/product/other", "name": "Custom label"}
    butter_url = "https://shop.amul.com/en/product/buttermilk"
    butter = {"id": "butter", "name": "Keep this label",
              "url": "https://shop.amul.com/en" + butter_url + "/product/buttermilk"}
    products = [blueberry(), butter, other]
    original = copy.deepcopy(products)
    planned = repair.plan_repairs(products)
    assert products == original
    assert len(planned) == 2
    migrated = {after['id']: after for _, after in planned}
    assert migrated[repair.BLUEBERRY_ID] == dict(blueberry(), url=repair.BLUEBERRY_URL, name=repair.BLUEBERRY_NAME)
    assert migrated['butter'] == dict(butter, url=butter_url)
    assert repair.plan_repairs([migrated[repair.BLUEBERRY_ID], migrated['butter'], other]) == []


def test_other_identifiers_and_custom_labels_are_not_substituted():
    other = dict(blueberry(), id="unrelated")
    current = dict(blueberry(), url=repair.BLUEBERRY_URL, name="My custom blueberry label")
    assert repair.plan_repairs([other, current]) == []


def test_unknown_corruption_requires_review_without_mutating_source():
    products = [blueberry(), {"id": "bad", "url": "https://other.invalid/product", "name": "Other"}]
    original = copy.deepcopy(products)
    with pytest.raises(RuntimeError, match="requires review"):
        repair.plan_repairs(products)
    assert products == original


@pytest.mark.parametrize('broken', [
    'https://shop.amul.com/enhttps://shop.amul.com/en/product/demo/product/demo',
    'https://shop.amul.com/en/product/https://shop.amul.com/en/product/demo',
    'https://shop.amul.com/en/product/https://shop.amul.com/en/product/demo/product/demo',
    'https://shop.amul.com/en/product/demohttps://shop.amul.com/en/product/demo',
    'https://shop.amul.com/en/product/https://shop.amul.com/en/product/demo/en/product/demo',
    'https://shop.amul.com/en/product/https://shop.amul.com/enhttps://shop.amul.com/en/product/demo',
    'https://shop.amul.com/en/product/demo/enhttps://shop.amul.com/en/product/demo',
])
def test_embedded_url_correction_requires_one_unambiguous_product(broken):
    item = {'id': 'example', 'name': 'Original label', 'url': broken}
    before, after = repair.plan_repairs([item])[0]
    assert before == item
    assert after == dict(item, url='https://shop.amul.com/en/product/demo')


@pytest.mark.parametrize('broken', [
    'https://shop.amul.com/en/product/otherhttps://shop.amul.com/en/product/demo',
    'https://shop.amul.com/en/product/https://evil.invalid/en/product/demo',
    'https://evil.invalid/en/product/https://shop.amul.com/en/product/demo',
    'https://shop.amul.com/en/product/https://shop.amul.com/en/product/demo/product/other',
    'https://shop.amul.com/en/product/enhttps://shop.amul.com/en/product/demo',
    'https://shop.amul.com/en/product/https://shop.amul.com.evil.invalid/en/product/demo',
])
def test_conflicting_or_foreign_embedded_links_remain_errors(broken):
    with pytest.raises(RuntimeError, match='requires review') as exc:
        repair.plan_repairs([{'id': 'example', 'name': 'Original label', 'url': broken}])
    assert broken not in str(exc.value)


def test_copied_candidates_are_same_origin_and_public_label_selects_exact_identity():
    value = 'https://shop.amul.com/en/product/outerhttps://shop.amul.com/en/product/inner'
    candidates = repair.copied_url_candidates(value)
    assert candidates == ['https://shop.amul.com/en/product/inner', 'https://shop.amul.com/en/product/outer']
    assert repair.match_product_label({candidates[0]: 'Actual product | Pack of 30', candidates[1]: 'Other product | Pack of 8'}, 'Actual product | Pack of 30') == candidates[0]
    with pytest.raises(RuntimeError, match='ambiguous'):
        repair.match_product_label({candidates[0]: 'Actual product | Pack of 8'}, 'Actual product | Pack of 30')
    with pytest.raises(RuntimeError, match='ambiguous'):
        repair.match_product_label({candidates[0]: 'Same name', candidates[1]: 'Same name'}, 'Same name')


@pytest.mark.parametrize('value', [
    'https://evil.invalid/en/product/outerhttps://shop.amul.com/en/product/inner',
    'https://shop.amul.com/en/product/outerhttps://shop.amul.com.evil.invalid/en/product/inner',
    'https://shop.amul.com/en/product/outerhttps://shop.amul.com/en/product/inner?variant=other',
])
def test_copied_candidates_never_follow_foreign_origins_or_variant_parameters(value):
    with pytest.raises(RuntimeError, match='safely resolved'):
        repair.copied_url_candidates(value)


def test_public_identity_uses_product_metadata_without_delivery_location():
    url = repair.BLUEBERRY_URL
    assert repair.public_identity(url, [], [{'@graph': [
        {'@type': 'Product', 'url': url, 'name': repair.BLUEBERRY_NAME},
        {'@type': 'Product', 'url': 'https://shop.amul.com/en/product/other', 'name': 'Other'},
    ]}]) == repair.BLUEBERRY_NAME
    with pytest.raises(RuntimeError, match='unavailable or ambiguous'):
        repair.public_identity(url, [], [{'@type': 'WebSite', 'name': 'Amul'}])
    with pytest.raises(RuntimeError, match='unavailable or ambiguous'):
        repair.public_identity(url, [], [
            {'@type': 'Product', 'name': 'One'}, {'@type': 'Product', 'name': 'Two'}])


class Response:
    def __init__(self, data, status=200):
        self.data, self.status = data, status
    async def __aenter__(self): return self
    async def __aexit__(self, *args): pass
    async def json(self): return copy.deepcopy(self.data)


class Session:
    def __init__(self, products, apply=True):
        self.products, self.puts, self.apply = copy.deepcopy(products), [], apply
    async def __aenter__(self): return self
    async def __aexit__(self, *args): pass
    def get(self, url): return Response(self.products)

    def put(self, url, *, params, headers, json):
        self.puts.append((params, json))
        if self.apply:
            self.products = [dict(p, **json) if p['id'] == params['id'] else p for p in self.products]
        return Response({})


@pytest.mark.asyncio
async def test_update_preserves_identifier_and_verifies_persisted_record():
    before, after = repair.plan_repairs([blueberry()])[0]
    session = Session([before])
    await repair.apply_repair(session, "test-token", before, after)
    assert session.products == [after]
    assert session.puts == [({'id': repair.BLUEBERRY_ID}, {'url': repair.BLUEBERRY_URL, 'name': repair.BLUEBERRY_NAME})]
    await repair.apply_repair(session, "test-token", before, after)
    assert len(session.puts) == 1  # Reconcile an already-completed write.


@pytest.mark.asyncio
async def test_concurrent_product_edit_aborts_before_writing():
    before, after = repair.plan_repairs([blueberry()])[0]
    session = Session([dict(before, name="Edited elsewhere")])
    with pytest.raises(RuntimeError, match="changed since"):
        await repair.apply_repair(session, "test-token", before, after)
    assert not session.puts


@pytest.mark.asyncio
async def test_unconfirmed_write_is_reported_and_not_retried():
    before, after = repair.plan_repairs([blueberry()])[0]
    session = Session([before], apply=False)
    with pytest.raises(RuntimeError, match="outcome is uncertain"):
        await repair.apply_repair(session, "test-token", before, after)
    assert len(session.puts) == 1


@pytest.mark.asyncio
async def test_all_page_validation_completes_before_authentication_or_writes(monkeypatch):
    session = Session([blueberry()])
    monkeypatch.setattr(repair.aiohttp, 'ClientSession', lambda **kwargs: session)
    async def invalid(*args): raise RuntimeError("Unverified page")
    async def unexpected_auth(*args): raise AssertionError("Authentication before validation")
    monkeypatch.setattr(repair, 'verify_product_pages', invalid)
    monkeypatch.setattr(repair, 'admin_token', unexpected_auth)
    with pytest.raises(RuntimeError, match="Unverified page"):
        await repair.main()
    assert not session.puts


@pytest.mark.asyncio
async def test_check_only_verifies_plan_without_authentication_or_writes(monkeypatch, capsys):
    session = Session([blueberry()])
    monkeypatch.setattr(repair.aiohttp, 'ClientSession', lambda **kwargs: session)
    verified = []
    async def verify(products, planned): verified.append((products, planned))
    async def unexpected_auth(*args): raise AssertionError('Read-only verification requested authentication')
    monkeypatch.setattr(repair, 'verify_product_pages', verify)
    monkeypatch.setattr(repair, 'admin_token', unexpected_auth)
    await repair.main(check_only=True)
    assert len(verified) == 1
    assert len(verified[0][1]) == 1
    assert not session.puts
    assert repair.OLD_BLUEBERRY_URL not in capsys.readouterr().out


@pytest.mark.asyncio
async def test_ambiguous_unrelated_item_is_preserved_while_approved_repair_completes(monkeypatch, capsys):
    unknown = {'id': 'unrelated', 'name': 'Custom label', 'url': 'https://shop.amul.com/en/product/outerhttps://shop.amul.com/en/product/inner'}
    session = Session([blueberry(), unknown])
    monkeypatch.setattr(repair.aiohttp, 'ClientSession', lambda **kwargs: session)
    async def ambiguous(*args): raise RuntimeError('Ambiguous identity')
    async def verified(*args): return set()
    async def token(*args): return 'test-token'
    monkeypatch.setattr(repair, 'resolve_copied_url', ambiguous)
    monkeypatch.setattr(repair, 'verify_product_pages', verified)
    monkeypatch.setattr(repair, 'admin_token', token)
    await repair.main()
    assert session.products[1] == unknown
    assert session.products[0]['url'] == repair.BLUEBERRY_URL
    assert session.products[0]['name'] == repair.BLUEBERRY_NAME
    assert len(session.puts) == 1
    output = capsys.readouterr().out
    assert '1 unresolved links unchanged' in output
    assert unknown['url'] not in output


@pytest.mark.asyncio
async def test_unverified_blueberry_candidate_aborts_all_writes(monkeypatch):
    session = Session([blueberry()])
    monkeypatch.setattr(repair.aiohttp, 'ClientSession', lambda **kwargs: session)
    async def unverified(*args): return {repair.BLUEBERRY_ID}
    async def unexpected_auth(*args): raise AssertionError('Authentication before validation')
    monkeypatch.setattr(repair, 'verify_product_pages', unverified)
    monkeypatch.setattr(repair, 'admin_token', unexpected_auth)
    with pytest.raises(RuntimeError, match='could not be verified'):
        await repair.main()
    assert not session.puts
