#!/usr/bin/env python3
"""
notify.py - out-of-band alerts (ntfy, Telegram, generic/Slack webhook).

Config (config.json -> "alerts"):
    {
      "ntfy":     {"server": "https://ntfy.sh", "topic": "<long random>", "token": null},
      "telegram": {"bot_token": "123:ABC", "chat_id": "123456"},
      "webhook_url": "https://hooks.slack.com/services/..."
    }

Alerts never block or break authentication: every failure is swallowed and
logged. Only https:// endpoints are used.
"""
import asyncio
import json
import logging
import urllib.request

log = logging.getLogger("remote-unlock.notify")
TIMEOUT = 5


def _post(url: str, body: bytes, headers: dict):
    if not url.startswith("https://"):
        raise ValueError("alert endpoints must use https")
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # noqa: S310 (https enforced)
        resp.read(1024)


def _ascii(s: str) -> str:
    return s.encode("ascii", "replace").decode()


class Notifier:
    def __init__(self, alerts_cfg: dict | None):
        self.cfg = alerts_cfg or {}

    def send_sync(self, title: str, message: str, priority: str = "default", tags=()):
        n = self.cfg.get("ntfy")
        if n and n.get("topic"):
            try:
                headers = {"Title": _ascii(title), "Priority": priority,
                           "Tags": ",".join(tags)}
                if n.get("token"):
                    headers["Authorization"] = f"Bearer {n['token']}"
                _post(f"{n.get('server', 'https://ntfy.sh').rstrip('/')}/{n['topic']}",
                      message.encode(), headers)
            except Exception as e:  # noqa: BLE001
                log.warning("ntfy alert failed: %s", e)
        t = self.cfg.get("telegram")
        if t and t.get("bot_token") and t.get("chat_id"):
            try:
                body = json.dumps({"chat_id": t["chat_id"], "text": f"{title}\n{message}"}).encode()
                _post(f"https://api.telegram.org/bot{t['bot_token']}/sendMessage",
                      body, {"Content-Type": "application/json"})
            except Exception as e:  # noqa: BLE001
                log.warning("telegram alert failed: %s", e)
        w = self.cfg.get("webhook_url")
        if w:
            try:
                body = json.dumps({"text": f"*{title}*\n{message}"}).encode()
                _post(w, body, {"Content-Type": "application/json"})
            except Exception as e:  # noqa: BLE001
                log.warning("webhook alert failed: %s", e)

    async def send(self, title: str, message: str, priority: str = "default", tags=()):
        try:
            await asyncio.to_thread(self.send_sync, title, message, priority, tags)
        except Exception as e:  # noqa: BLE001
            log.warning("alert failed: %s", e)
