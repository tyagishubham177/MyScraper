"""Utility helpers for stock checking."""
import os
import time
from datetime import datetime, timezone, timedelta, time as dt_time
import config


def _add_timing(label: str, duration: float, timings: dict[str, float]) -> None:
    """Store the elapsed duration for a step."""
    timings[label] = duration


async def _timed(label: str, coro, timings: dict[str, float]):
    """Await *coro* and record how long it took."""
    start = time.perf_counter()
    result = await coro
    _add_timing(label, time.perf_counter() - start, timings)
    return result


def _print_summary(timings: dict[str, float], pincode_stats: list[dict]):
    """Print a markdown table of timings and pincode processing info."""
    lines = ["### Workflow Timing Summary", "| Step | Duration (s) |", "| --- | --- |"]
    for step, dur in timings.items():
        lines.append(f"| {step} | {dur:.2f} |")

    if pincode_stats:
        lines.extend([
            "",
            "### Pincode Groups",
            "| Pincode | Duration (s) | Products Checked |",
            "| --- | --- | --- |",
        ])
        for info in pincode_stats:
            lines.append(
                f"| {info['pincode']} | {info['duration']:.2f} | {info['products']} |"
            )

    summary = "\n".join(lines)
    print(summary)
    summary_file = os.getenv("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a", encoding="utf-8") as fh:
            fh.write(summary + "\n")


def within_time_window(start_str: str, end_str: str, now: dt_time) -> bool:
    fmt = "%H:%M"
    try:
        start = datetime.strptime(start_str, fmt).time()
        end = datetime.strptime(end_str, fmt).time()
    except Exception:
        return True
    if start <= end:
        return start <= now <= end
    return now >= start or now <= end


def filter_active_subs(subs, current_time):
    active = []
    for sub in subs:
        if sub.get("paused"):
            continue
        start_t = sub.get("start_time", "00:00")
        end_t = sub.get("end_time", "23:59")
        if within_time_window(start_t, end_t, current_time):
            active.append(sub)
    return active


def build_subs_by_pincode(recipients_map, subs_map):
    """Return {pincode: {product_id: [subscription, ...]}}."""
    result = {}
    for pid, subs in subs_map.items():
        for sub in subs:
            rid = sub.get("recipient_id")
            if rid is None:
                continue
            rec = recipients_map.get(rid)
            if not rec:
                continue
            pin = rec.get("pincode", config.PINCODE)
            result.setdefault(pin, {}).setdefault(pid, []).append(sub)
    return result


def aggregate_product_summaries(summary_items):
    """Combine summary entries per product and pincode."""
    aggregated = {}
    for item in summary_items:
        pid = item.get("product_id")
        if pid is None:
            continue
        item_pin = item.get("pincode")
        subs = item.get("subscriptions", [])
        if item_pin:
            key = (pid, item_pin)
            entry = aggregated.setdefault(
                key,
                {
                    "product_id": pid,
                    "pincode": item_pin,
                    "product_name": item.get("product_name"),
                    "product_url": item.get("product_url"),
                    "consecutive_in_stock": item.get("consecutive_in_stock", 0),
                    "subscriptions": [],
                },
            )
            entry["subscriptions"].extend(subs)
            entry["consecutive_in_stock"] = item.get(
                "consecutive_in_stock", entry.get("consecutive_in_stock", 0)
            )
        else:
            for sub in subs:
                pin = sub.get("pincode")
                key = (pid, pin)
                entry = aggregated.setdefault(
                    key,
                    {
                        "product_id": pid,
                        "pincode": pin,
                        "product_name": item.get("product_name"),
                        "product_url": item.get("product_url"),
                        "consecutive_in_stock": item.get(
                            "consecutive_in_stock", 0
                        ),
                        "subscriptions": [],
                    },
                )
                entry["subscriptions"].append(sub)
                entry["consecutive_in_stock"] = item.get(
                    "consecutive_in_stock", entry.get("consecutive_in_stock", 0)
                )
    return list(aggregated.values())

