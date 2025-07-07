# Utilities for interacting with the API layer.
import aiohttp
import config

# Provide a minimal fallback ClientSession when aiohttp is not fully available
if not hasattr(aiohttp, "ClientSession"):
    class _DummyResponse:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            pass

        async def json(self):
            return {}

        def raise_for_status(self):
            pass

    class _DummyClientSession:
        def get(self, url, **kwargs):
            return _DummyResponse()

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            pass

    aiohttp.ClientSession = _DummyClientSession


async def fetch_api_data(session, url, headers=None):
    try:
        async with session.get(url, headers=headers) as response:
            response.raise_for_status()
            return await response.json()
    except Exception as e:
        print(f"API request to {url} failed: {e}")
        return None


async def load_recipients(session):
    recipients_url = f"{config.APP_BASE_URL}/api/recipients"
    data = await fetch_api_data(session, recipients_url)
    return {
        r.get("id"): {
            "email": r.get("email"),
            "pincode": r.get("pincode", config.PINCODE),
        }
        for r in data or []
        if r.get("id") and r.get("email")
    }


async def load_products(session):
    products_url = f"{config.APP_BASE_URL}/api/products"
    return await fetch_api_data(session, products_url)


async def load_subscriptions(session):
    """Fetch all subscriptions and return a dict keyed by product_id."""
    subs_url = f"{config.APP_BASE_URL}/api/subscriptions"
    data = await fetch_api_data(session, subs_url)
    if not data or not isinstance(data, list):
        return {}
    subs_by_product = {}
    for sub in data:
        pid = sub.get("product_id")
        if pid is None:
            continue
        subs_by_product.setdefault(pid, []).append(sub)
    return subs_by_product


async def fetch_subscriptions(session, product_id):
    url = f"{config.APP_BASE_URL}/api/subscriptions?product_id={product_id}"
    return await fetch_api_data(session, url)


async def login_admin(session):
    """Fetch an admin token using the login API if credentials are provided."""
    email = getattr(config, "ADMIN_EMAIL", None)
    password = getattr(config, "ADMIN_PASSWORD", None)
    if not email or not password:
        print("Admin credentials not provided; skipping login.")
        return None

    url = f"{config.APP_BASE_URL}/api/login"
    try:
        async with session.post(
            url, json={"email": email, "password": password}
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                token = data.get("token")
                if token:
                    config.ADMIN_TOKEN = token
                    print("Admin login successful.")
                    return token
                print("Admin login returned no token")
            else:
                text = await resp.text()
                print(f"Admin login failed: {resp.status} {text}")
    except Exception as e:
        print(f"Admin login failed: {e}")
    return None


async def load_stock_counters(session):
    url = f"{config.APP_BASE_URL}/api/stock-counters"
    headers = (
        {"Authorization": f"Bearer {config.ADMIN_TOKEN}"}
        if config.ADMIN_TOKEN
        else None
    )
    data = await fetch_api_data(session, url, headers=headers)
    if isinstance(data, dict):
        converted = {}
        for key, val in data.items():
            converted[str(key)] = val
        return converted
    return {}


async def save_stock_counters(session, counters):
    url = f"{config.APP_BASE_URL}/api/stock-counters"
    headers = (
        {"Authorization": f"Bearer {config.ADMIN_TOKEN}"}
        if config.ADMIN_TOKEN
        else None
    )
    try:
        payload = {"counters": {str(k): v for k, v in counters.items()}}
        async with session.put(
            url, json=payload, headers=headers
        ) as resp:
            if resp.status == 401:
                print("Stock counter update unauthorized. Retrying after login.")
                await login_admin(session)
                headers = (
                    {"Authorization": f"Bearer {config.ADMIN_TOKEN}"}
                    if config.ADMIN_TOKEN
                    else None
                )
                async with session.put(
                    url, json=payload, headers=headers
                ) as resp_retry:
                    if resp_retry.status >= 400:
                        text = await resp_retry.text()
                        raise Exception(f"{resp_retry.status}: {text}")
            elif resp.status >= 400:
                text = await resp.text()
                raise Exception(f"{resp.status}: {text}")
    except Exception as e:
        print(f"Failed to update stock counters: {e}")

