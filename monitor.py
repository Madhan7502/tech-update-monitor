#!/usr/bin/env python3
"""
Tech Update Monitor -> Google Chat

Watches release / security feeds (PHP, Node.js, Python, AWS, Apple, Android,
R8, policy pages ...) defined in sources.yaml and posts anything NEW to a
Google Chat space via an incoming webhook.

Source types:
  feed   - RSS / Atom feed (new entries are reported)
  page   - plain web page (reported when the watched text changes)
  maven  - Maven metadata XML (reported when a new version is published)

Usage:
  python monitor.py              # normal run (post to Google Chat)
  python monitor.py --dry-run    # print messages instead of posting
  python monitor.py --notify-first  # also post items on a source's first run
  python monitor.py --status     # also post a "current status" summary
"""
import argparse
import difflib
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
import xml.etree.ElementTree as ET
from pathlib import Path

import feedparser
import requests
import yaml
from bs4 import BeautifulSoup

BASE = Path(__file__).resolve().parent
STATE_FILE = Path(os.environ.get("STATE_FILE", BASE / "state.json"))
SOURCES_FILE = Path(os.environ.get("SOURCES_FILE", BASE / "sources.yaml"))
WEBHOOK = os.environ.get("GCHAT_WEBHOOK_URL", "")
HEADERS = {"User-Agent": "Mozilla/5.0 (tech-update-monitor/1.0)"}
MAX_SEEN_IDS = 300          # per source, to keep state.json small
MAX_ITEMS_PER_MESSAGE = 10
FAIL_ALERT_AFTER = 6        # consecutive failures before we warn in chat


# ---------------------------------------------------------------- helpers
def load_json(path, default):
    try:
        return json.loads(Path(path).read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def strip_html(text, limit=220):
    text = BeautifulSoup(text or "", "html.parser").get_text(" ", strip=True)
    text = re.sub(r"\s+", " ", text)
    return text[:limit] + ("…" if len(text) > limit else "")


def fetch(url):
    r = requests.get(url, headers=HEADERS, timeout=30)
    r.raise_for_status()
    return r


def label(src):
    """Display name, with 'In Android' / 'In iOS' when a platform is set."""
    plat = src.get("platform")
    return f"*In {plat}* · *{src['name']}*" if plat else f"*{src['name']}*"


def today():
    return datetime.now(timezone.utc).strftime("%d %b %Y")


def matches(text, keywords):
    text = text.lower()
    return any(k.lower() in text for k in keywords)


# ---------------------------------------------------------------- checkers
def check_feed(src, st):
    feed = feedparser.parse(fetch(src["url"]).content)
    if feed.bozo and not feed.entries:
        raise ValueError(f"could not parse feed: {feed.bozo_exception}")
    seen = set(st.get("seen", []))
    include = src.get("include_keywords")
    new, all_ids, latest, recent = [], [], None, []
    for e in feed.entries[:60]:
        uid = e.get("id") or e.get("link") or e.get("title")
        all_ids.append(uid)
        title = (e.get("title") or "(no title)").strip()
        summary = strip_html(e.get("summary", ""))
        if include and not matches(f"{title} {summary}", include):
            continue
        if src.get("title_regex") and not re.search(src["title_regex"], title):
            continue                        # e.g. skip alpha/beta releases
        when = e.get("published_parsed") or e.get("updated_parsed")
        recent.append({"title": title, "link": e.get("link", src["url"]), "_when": when or (),
                       "date": time.strftime("%d %b %Y", when) if when else ""})
        if latest is None or (when and latest["_when"] and when > latest["_when"]):
            latest = {"title": title, "link": e.get("link", src["url"]), "_when": when,
                      "date": time.strftime("%d %b %Y", when) if when else ""}
        if uid in seen:
            continue
        new.append({"title": title, "link": e.get("link", src["url"]), "summary": summary})
    st["seen"] = (all_ids + [i for i in st.get("seen", []) if i not in all_ids])[:MAX_SEEN_IDS]
    if latest:
        latest.pop("_when", None)
    recent.sort(key=lambda r: tuple(r["_when"]), reverse=True)
    st["recent"] = [{k: v for k, v in r.items() if k != "_when"}
                    for r in recent[:src.get("status_items", 1)]]
    st["latest"] = latest or {"title": "No matching items right now", "link": src["url"], "date": ""}
    return new


def check_page(src, st):
    soup = BeautifulSoup(fetch(src["url"]).text, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    node = soup.select_one(src["selector"]) if src.get("selector") else soup.body or soup
    if node is None:
        raise ValueError(f"selector {src['selector']!r} not found on page")
    lines = [l.strip() for l in node.get_text("\n").splitlines() if l.strip()]
    text = "\n".join(lines)[:40000]
    digest = hashlib.sha256(text.encode()).hexdigest()
    old_digest, old_text = st.get("hash"), st.get("text", "")
    st["hash"], st["text"] = digest, text
    if old_digest != digest:
        st["changed_at"] = today()
    st["latest"] = {"title": "Watching page — last change detected " + st.get("changed_at", today()),
                    "link": src["url"], "date": ""}
    if old_digest is None or digest == old_digest:
        return []
    added = [l[2:] for l in difflib.ndiff(old_text.splitlines(), lines) if l.startswith("+ ")]
    snippet = " | ".join(added[:6])[:400] or "content changed"
    return [{"title": f"Page updated: {src['name']}", "link": src["url"], "summary": f"New/changed: {snippet}"}]


def check_maven(src, st):
    root = ET.fromstring(fetch(src["url"]).content)
    versions = [v.text for v in root.iter("version") if v.text]
    if src.get("stable_only", True):
        versions = [v for v in versions if re.fullmatch(r"[\d.]+", v)]
    if not versions:
        return []
    seen = set(st.get("seen", []))
    new = [v for v in versions if v not in seen]
    st["seen"] = versions[-MAX_SEEN_IDS:]
    link = src.get("link", src["url"])
    st["latest"] = {"title": f"Latest stable version: {versions[-1]}", "link": link, "date": ""}
    return [{"title": f"{src['name']} {v} released", "link": link, "summary": ""} for v in new[-5:]]


CHECKERS = {"feed": check_feed, "page": check_page, "maven": check_maven}


# ---------------------------------------------------------------- google chat
def post_chat(text, dry_run, limit=3500):
    if len(text) > limit:                   # Chat has a message size limit
        chunk = ""
        for line in text.split("\n"):
            if len(chunk) + len(line) + 1 > limit:
                post_chat(chunk, dry_run, limit)
                chunk = ""
            chunk += line + "\n"
        if chunk.strip():
            post_chat(chunk.rstrip(), dry_run, limit)
        return
    if dry_run or not WEBHOOK:
        print("\n----- message -----\n" + text)
        return
    for attempt in range(4):
        r = requests.post(WEBHOOK, json={"text": text}, timeout=30,
                          headers={"Content-Type": "application/json; charset=UTF-8"})
        if r.status_code == 429:            # Chat webhooks allow ~1 msg/sec
            time.sleep(2 ** attempt * 2)
            continue
        r.raise_for_status()
        time.sleep(1.2)
        return
    print("WARN: gave up posting after rate limiting", file=sys.stderr)


def format_message(src, items, security_kw, heading=None):
    critical = any(matches(f"{i['title']} {i['summary']}", security_kw) for i in items)
    icon = "🚨" if critical else src.get("icon", "📢")
    limit = src.get("max_items", MAX_ITEMS_PER_MESSAGE)
    heading = heading or f"{len(items)} new update(s)"
    lines = [f"{icon} {label(src)} — {heading}"]
    for i in items[:limit]:
        flag = " ⚠️" if matches(f"{i['title']} {i['summary']}", security_kw) else ""
        lines.append(f"• <{i['link']}|{i['title']}>{flag}")
        if i["summary"] and src.get("show_summary", True):
            lines.append(f"   _{i['summary']}_")
    if len(items) > limit:
        lines.append(f"…and {len(items) - limit} more: {src.get('link', src['url'])}")
    if critical and src.get("mention"):
        lines.insert(0, src["mention"])     # e.g. "<users/all>"
    return "\n".join(lines)


def post_status(cfg, state, failed, security_kw, dry_run):
    now = datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M UTC")
    blocks = [f"📊 *Tech Update Monitor — Current Status*\n_{now}_"]
    for src in cfg["sources"]:
        if not src.get("enabled", True):
            continue
        sid, icon = src["id"], src.get("icon", "📢")
        if sid in failed:
            blocks.append(f"{icon} {label(src)}\n   ❗ Could not check right now")
            continue
        recent = state.get(sid, {}).get("recent", [])
        if src.get("status_items", 1) > 1 and recent:
            rows = [f"{icon} {label(src)} — latest {len(recent)}"]
            for r in recent:
                d = f" · {r['date']}" if r["date"] else ""
                rows.append(f"   • <{r['link']}|{r['title']}>{d}")
            blocks.append("\n".join(rows))
            continue
        latest = state.get(sid, {}).get("latest")
        if not latest:
            continue
        flag = " 🚨" if matches(latest["title"], security_kw) else ""
        date = f" · {latest['date']}" if latest["date"] else ""
        blocks.append(f"{icon} {label(src)}\n   <{latest['link']}|{latest['title']}>{flag}{date}")
    blocks.append("_I'll post here automatically whenever something new is released._")
    # Google Chat messages have a size limit, so split long reports
    msg = ""
    for b in blocks:
        if len(msg) + len(b) > 3500:
            post_chat(msg, dry_run)
            msg = ""
        msg += b + "\n\n"
    if msg.strip():
        post_chat(msg.strip(), dry_run)


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--notify-first", action="store_true")
    ap.add_argument("--status", action="store_true", help="post a current-status summary")
    ap.add_argument("--only", help="comma-separated source ids to run")
    args = ap.parse_args()

    if not WEBHOOK and not args.dry_run:
        sys.exit("Set GCHAT_WEBHOOK_URL (or use --dry-run).")

    cfg = yaml.safe_load(SOURCES_FILE.read_text())
    security_kw = cfg.get("security_keywords", [])
    state = load_json(STATE_FILE, {})
    only = set(args.only.split(",")) if args.only else None
    total_new = 0
    failed = set()

    for src in cfg["sources"]:
        sid = src["id"]
        if not src.get("enabled", True) or (only and sid not in only):
            continue
        first_run = sid not in state
        st = state.setdefault(sid, {})
        try:
            items = CHECKERS[src["type"]](src, st)
            st["fails"] = 0
        except Exception as exc:  # keep going with other sources
            st["fails"] = st.get("fails", 0) + 1
            failed.add(sid)
            print(f"ERROR [{sid}] {exc}", file=sys.stderr)
            if st["fails"] == FAIL_ALERT_AFTER:
                post_chat(f"⚙️ Update monitor: source *{src['name']}* has failed "
                          f"{FAIL_ALERT_AFTER} runs in a row ({exc}). Check its URL.", args.dry_run)
            continue

        if first_run and not args.notify_first:
            print(f"[{sid}] first run: baseline saved ({len(items)} items), not posting")
            continue
        print(f"[{sid}] {len(items)} new")
        total_new += len(items)
        if src.get("digest"):               # collect, then post once a day
            st.setdefault("pending", []).extend(items)
            hour = datetime.now(timezone.utc).hour
            if (st["pending"] and hour >= src.get("digest_hour_utc", 3)
                    and st.get("digest_date") != today()):
                post_chat(format_message(src, st["pending"], security_kw,
                                         heading=f"daily digest ({len(st['pending'])} updates)"),
                          args.dry_run)
                st["pending"], st["digest_date"] = [], today()
            else:
                print(f"[{sid}] {len(st['pending'])} waiting for daily digest")
        elif items:
            post_chat(format_message(src, items, security_kw), args.dry_run)

    if args.status:
        post_status(cfg, state, failed, security_kw, args.dry_run)

    STATE_FILE.write_text(json.dumps(state, indent=1, ensure_ascii=False))
    print(f"Done. {total_new} new update(s).")


if __name__ == "__main__":
    main()
