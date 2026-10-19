"""Plasma notify: alert delivery for drift/health findings.

Channels are configured in <root>/notify.json:
    {"channels": [
        {"type": "telegram", "token_env": "PLASMA_TG_TOKEN", "chat_id": "123"},
        {"type": "webhook",  "url": "https://hooks.example/plasma"}
     ],
     "min_score": 7}

Secrets are NEVER stored in the config file — tokens arrive through the
environment variable named by `token_env` (same discipline as actuate
inventory). Delivery failures are returned as data, never raised.
"""

from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path

DEFAULT_CONFIG = "notify.json"


def load_config(root) -> dict:
    path = Path(root) / DEFAULT_CONFIG
    if not path.exists():
        return {"channels": [], "min_score": 7}
    blob = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(blob.get("channels", []), list):
        raise ValueError("notify config: 'channels' must be a list")
    for ch in blob["channels"]:
        if ch.get("type") == "telegram" and "token_env" not in ch:
            raise ValueError("telegram channel needs token_env (secrets never live in config)")
        if ch.get("type") == "webhook" and not ch.get("url"):
            raise ValueError("webhook channel needs url")
        for field in ch:
            if "token" in field.lower() and field != "token_env":
                raise ValueError(f"inline secret field '{field}' is forbidden — use token_env")
    blob.setdefault("min_score", 7)
    return blob


def _post(url: str, payload: dict, timeout: int = 15) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return {"ok": 200 <= resp.status < 300, "status": resp.status}


def deliver(channel: dict, title: str, body: str) -> dict:
    """Send one message through one channel. Failures are data."""
    ctype = channel.get("type")
    try:
        if ctype == "telegram":
            token = os.environ.get(channel["token_env"], "")
            if not token:
                return {"channel": "telegram", "ok": False,
                        "error": f"env {channel['token_env']} not set"}
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            res = _post(url, {"chat_id": channel["chat_id"],
                              "text": f"{title}\n{body}"[:4000]})
        elif ctype == "webhook":
            res = _post(channel["url"], {"title": title, "body": body})
        else:
            return {"channel": ctype, "ok": False, "error": f"unknown type {ctype}"}
        res["channel"] = ctype
        return res
    except Exception as exc:  # noqa: BLE001 — delivery failures are data
        return {"channel": ctype, "ok": False, "error": str(exc)[:200]}


def notify_all(root, title: str, body: str, score: float | None = None,
               min_score: float | None = None) -> dict:
    """Deliver to every configured channel, gated by min_score.

    `score` is the finding's own score; the effective threshold comes from
    the config's `min_score` (default 7) unless `min_score` overrides it.
    A finding below the threshold is suppressed (reported as data, never
    raised). No config → nothing sent (data).
    """
    cfg = load_config(root)
    threshold = min_score if min_score is not None else cfg.get("min_score", 7)
    suppressed = score is not None and score < threshold
    if suppressed:
        return {"sent": 0, "channels": [], "min_score": threshold,
                "configured": len(cfg["channels"]), "suppressed": True}
    results = [deliver(ch, title, body) for ch in cfg["channels"]]
    return {"sent": sum(1 for r in results if r.get("ok")),
            "channels": results,
            "min_score": threshold,
            "configured": len(cfg["channels"])}
