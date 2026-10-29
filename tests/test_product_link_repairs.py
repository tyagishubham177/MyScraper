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
