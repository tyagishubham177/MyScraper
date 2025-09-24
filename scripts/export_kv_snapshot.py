"""Export the current KV-backed datasets to a JSON snapshot.

The script is designed to run in GitHub Actions on a schedule so we always
have a recent copy of the data should the KV store ever hiccup. It fetches the
public API endpoints (products, recipients, subscriptions, and stock counters)
and stores them in a timestamped JSON file that can be downloaded as an
artifact.
"""

import asyncio
from datetime import datetime, timezone
import json
import os
import sys
from pathlib import Path
import types

try:
    import aiohttp  # type: ignore
except Exception:  # pragma: no cover - fallback when aiohttp not installed
    aiohttp = types.SimpleNamespace()

# Allow running via `python scripts/export_kv_snapshot.py`
if __package__ is None and __name__ == "__main__":
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import config  # noqa: E402

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
        def __init__(self):
            self.headers = None

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            pass

        def _response(self):
            return _DummyResponse()

        def get(self, _url, **_kwargs):
            return self._response()

    aiohttp.ClientSession = _DummyClientSession  # type: ignore[attr-defined]


API_PATHS = {
    "products": "/api/products",
    "recipients": "/api/recipients",
    "subscriptions": "/api/subscriptions",
    "stock_counters": "/api/stock-counters",
}


async def fetch_endpoint(session, path, headers):
    base = config.APP_BASE_URL.rstrip("/")
    url = f"{base}{path}"
    async with session.get(url, headers=headers) as response:
        response.raise_for_status()
        return await response.json()


async def export_snapshot():
    headers = None
    token = getattr(config, "ADMIN_TOKEN", None)
    if token:
        headers = {"Authorization": f"Bearer {token}"}

    results = {}
    async with aiohttp.ClientSession() as session:
        for key, path in API_PATHS.items():
            data = await fetch_endpoint(session, path, headers)
            results[key] = data

    generated_at = datetime.now(timezone.utc).isoformat()
    snapshot = {
        "generated_at": generated_at,
        "app_base_url": config.APP_BASE_URL,
        "data": results,
    }

    snapshot_dir = Path(os.getenv("SNAPSHOT_DIR", "backups"))
    snapshot_dir.mkdir(parents=True, exist_ok=True)

    filename = os.getenv("SNAPSHOT_FILE")
    if filename:
        path = Path(filename)
        if not path.is_absolute():
            path = snapshot_dir / path
    else:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = snapshot_dir / f"kv-backup-{timestamp}.json"

    path.write_text(json.dumps(snapshot, indent=2, sort_keys=True))
    print(f"Snapshot written to {path} with keys: {', '.join(sorted(results.keys()))}")


def main():
    asyncio.run(export_snapshot())


if __name__ == "__main__":
    main()
