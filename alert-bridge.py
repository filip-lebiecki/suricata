#!/usr/bin/env python3
"""Suricata eve.json -> Telegram alert + MikroTik auto-block bridge.

Follows eve.json like `tail -F` (survives logrotate), and for every alert
with severity <= MAX_SEVERITY:
  - adds the attacker IP to a MikroTik address-list with a timeout
  - sends one Telegram message (rate-limited per attacker+signature) —
    except pure reputation-list hits (QUIET_PREFIXES), which are blocked
    silently and rolled up into a one-line daily digest

Config via environment (see alert-bridge.service):
  TG_TOKEN   Telegram bot token
  TG_CHAT    Telegram chat id
   MT_HOST    MikroTik address, e.g. 192.168.12.200
   MT_USER    REST API user (default: suricata)
   MT_PASS    REST API password
   WAN_IP            own WAN public IP (CIDR, e.g. 203.0.113.5/32)
   WAN_IPV6_PREFIX   own IPv6 prefix (CIDR, e.g. 2001:db8::/64)
"""

import ipaddress
import json
import os
import time

import requests
import urllib3

urllib3.disable_warnings()  # self-signed cert on the router's www-ssl

EVE_LOG = "/var/log/suricata/eve.json"
MAX_SEVERITY = 2          # 1=high, 2=medium; 3=informational is ignored
BLOCK_TIMEOUT = "1h"      # address-list entry lifetime on the router
COOLDOWN = 300            # seconds before re-alerting same ip+signature
BLOCK_LIST = "suricata-block"

# Reputation-list hits: real enough to block, too common to page about
# (~270/day of background internet scanning on this WAN). Still blocked,
# just not messaged — counted into the daily digest instead.
QUIET_PREFIXES = ("ET DROP", "ET CINS", "ET TOR", "ET 3CORESec")

TG_TOKEN = os.environ.get("TG_TOKEN", "")  # empty = skip Telegram, log only
TG_CHAT = os.environ.get("TG_CHAT", "")
MT_HOST = os.environ.get("MT_HOST", "")
MT_USER = os.environ.get("MT_USER", "")
MT_PASS = os.environ["MT_PASS"]
WAN_IP = os.environ.get("WAN_IP", "")            # own WAN public IP (CIDR)
WAN_IPV6_PREFIX = os.environ.get("WAN_IPV6_PREFIX", "")  # own IPv6 prefix

# Never block these, no matter what Suricata says: RFC1918 / CGNAT / loopback
# and well-known public DNS resolvers. Own public IPs come from WAN_IP /
# WAN_IPV6_PREFIX in the env so this file stays deployment-agnostic.
WHITELIST = [
    ipaddress.ip_network(n)
    for n in (
        "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12",
        "127.0.0.0/8", "100.64.0.0/10",
        "1.1.1.1/32", "8.8.8.8/32", "9.9.9.9/32",
    )
] + [ipaddress.ip_network(n) for n in (WAN_IP, WAN_IPV6_PREFIX) if n]

# Match suricata.yaml HOME_NET — used to decide which side is the attacker.
HOME_NETS = [ipaddress.ip_network("192.168.0.0/16")] + [
    ipaddress.ip_network(n) for n in (WAN_IP, WAN_IPV6_PREFIX) if n
]

_recent: dict[str, float] = {}
_quiet_blocks = 0
_digest_day = time.strftime("%Y-%m-%d")


def whitelisted(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in WHITELIST)


def pick_attacker(ev: dict) -> str:
    """The side of the flow that is NOT ours."""
    src = ev.get("src_ip", "")
    try:
        if any(ipaddress.ip_address(src) in n for n in HOME_NETS):
            return ev.get("dest_ip", "")
    except ValueError:
        pass
    return src


def cooled_down(key: str) -> bool:
    now = time.time()
    if now - _recent.get(key, 0) < COOLDOWN:
        return False
    _recent[key] = now
    # keep the dedup table from growing forever
    for k in [k for k, t in _recent.items() if now - t > COOLDOWN * 4]:
        del _recent[k]
    return True


def telegram_send(text: str) -> None:
    if not TG_TOKEN or not TG_CHAT:
        return  # Telegram not configured yet — alerts still logged + blocked
    try:
        requests.post(
            f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
            json={"chat_id": TG_CHAT, "text": text},
            timeout=10,
        )
    except requests.RequestException as e:
        print(f"telegram failed: {e}", flush=True)


def mikrotik_block(ip: str, signature: str) -> bool:
    family = "ipv6" if ipaddress.ip_address(ip).version == 6 else "ip"
    try:
        r = requests.put(
            f"https://{MT_HOST}/rest/{family}/firewall/address-list",
            json={
                "list": BLOCK_LIST,
                "address": ip,
                "timeout": BLOCK_TIMEOUT,
                "comment": signature[:60],
            },
            auth=(MT_USER, MT_PASS),
            verify=False,
            timeout=(5, 30),
        )
        # 400 "already have such entry" is fine — it's already blocked
        return r.status_code in (200, 201) or "already" in r.text
    except requests.RequestException as e:
        print(f"mikrotik block failed for {ip}: {e}", flush=True)
        return False


def maybe_send_digest() -> None:
    """First alert of a new day flushes yesterday's quiet-block count."""
    global _quiet_blocks, _digest_day
    today = time.strftime("%Y-%m-%d")
    if today == _digest_day:
        return
    if _quiet_blocks:
        telegram_send(f"🌦 {_digest_day}: silently blocked {_quiet_blocks} "
                      "reputation-listed IPs (ET DROP/CINS/TOR)")
    _digest_day = today
    _quiet_blocks = 0


def follow(path: str):
    """tail -F: follow the file across logrotate, truncation, and re-create."""
    f = None
    inode = None
    pos = None
    while True:
        try:
            st = os.stat(path)
            # (Re)open when: first run, inode changed (rotation/recreate),
            # or the file shrank below our read position (truncation, same inode).
            if f is None or st.st_ino != inode or st.st_size < pos:
                if f:
                    f.close()
                f = open(path, "r")
                inode = st.st_ino
                f.seek(0, os.SEEK_END)  # only new events
                pos = f.tell()
            line = f.readline()
            if line:
                pos = f.tell()
                yield line
            else:
                time.sleep(0.5)
        except FileNotFoundError:
            time.sleep(1)


def main() -> None:
    global _quiet_blocks
    print(f"following {EVE_LOG}, blocking via {MT_HOST}", flush=True)
    for line in follow(EVE_LOG):
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("event_type") != "alert":
            continue
        alert = ev.get("alert", {})
        if alert.get("severity", 3) > MAX_SEVERITY:
            continue

        attacker = pick_attacker(ev)
        if not attacker or whitelisted(attacker):
            continue
        if not cooled_down(f"{attacker}|{alert.get('signature_id')}"):
            continue

        maybe_send_digest()
        sig = alert.get("signature", "")
        blocked = mikrotik_block(attacker, sig)
        quiet = sig.startswith(QUIET_PREFIXES)
        if quiet:
            _quiet_blocks += 1
        else:
            telegram_send(
                "🚨 Suricata alert\n"
                f"{sig}\n"
                f"{ev.get('src_ip')}:{ev.get('src_port', '')} → "
                f"{ev.get('dest_ip')}:{ev.get('dest_port', '')}\n"
                f"severity {alert.get('severity')} · "
                + (f"⛔ blocked {BLOCK_TIMEOUT}" if blocked else "⚠️ block FAILED")
            )
        print(f"alert {sig} attacker={attacker} "
              f"blocked={blocked} paged={not quiet}", flush=True)


if __name__ == "__main__":
    main()
