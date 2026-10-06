"""Messaging-domain tool implementations (read-only).

list_messenger_chats / read_messenger_chat / search_messenger_messages read
the local Signal / WhatsApp index (src/messaging/store.py). They never send,
never touch Signal's or WhatsApp's servers, and are admin-only
(NON_ADMIN_BLOCKED_TOOLS). Results are classified EXTERNAL_UNTRUSTED in
src/tool_capabilities.py: message text is written by other people, so it arms
the post-untrusted approval gate exactly like email does.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.tools._common import _parse_tool_args

logger = logging.getLogger(__name__)

_MAX_BODY_CHARS = 1500
_MAX_OUTPUT_CHARS = 24000
_SOURCE_LABELS = {"signal_desktop": "Signal", "whatsapp_backup": "WhatsApp"}


def _tz():
    try:
        from src.user_time import user_timezone
        return user_timezone()
    except Exception:
        return timezone.utc


def _fmt_ts(ms: Optional[int]) -> str:
    if not ms:
        return "-"
    dt = datetime.fromtimestamp(int(ms) / 1000, timezone.utc).astimezone(_tz())
    return dt.strftime("%Y-%m-%d %H:%M %Z").strip()


def _bound(value: Any) -> Optional[int]:
    from src.messaging.store import parse_time_bound
    return parse_time_bound(value, _tz())


def _int_arg(args: Dict[str, Any], key: str, default: int) -> int:
    try:
        return int(args.get(key) or default)
    except (TypeError, ValueError):
        return default


def _clip(text: str, limit: int = _MAX_BODY_CHARS) -> str:
    text = (text or "").replace("\r\n", "\n")
    return text if len(text) <= limit else text[:limit] + " …[truncated]"


def _cap_output(lines: List[str]) -> str:
    out, total = [], 0
    for line in lines:
        total += len(line) + 1
        if total > _MAX_OUTPUT_CHARS:
            out.append("…[more results omitted; narrow with chat_id, since/until or a smaller limit]")
            break
        out.append(line)
    return "\n".join(out)


def _no_sources_message() -> Dict[str, Any]:
    return {
        "output": (
            "No messaging sources are set up yet. The user can add Signal Desktop or a "
            "WhatsApp backup under Settings > Messaging."
        ),
        "exit_code": 0,
    }


async def do_list_messenger_chats(content: str, owner: Optional[str] = None) -> Dict:
    from src.messaging import store

    try:
        args = _parse_tool_args(content)
    except ValueError:
        return {"error": "Invalid JSON arguments", "exit_code": 1}
    if not await asyncio.to_thread(store.list_sources, owner, include_disabled=False):
        return _no_sources_message()
    chats = await asyncio.to_thread(
        store.list_chats, owner,
        source=args.get("source"), query=args.get("query"),
        limit=_int_arg(args, "limit", 30),
    )
    if not chats:
        return {"output": "No chats matched.", "exit_code": 0}
    lines = [f"{len(chats)} chat(s), most recent first. Use chat_id with read_messenger_chat."]
    for c in chats:
        kind = "group" if c["is_group"] else "1:1"
        lines.append(
            f"- chat_id={c['id']} | {_SOURCE_LABELS.get(c['source_kind'], c['source_kind'])} {kind} | "
            f"{c['title']} | {c['message_count']} msgs | last {_fmt_ts(c['last_message_at'])}"
        )
    return {"output": _cap_output(lines), "exit_code": 0}


async def do_read_messenger_chat(content: str, owner: Optional[str] = None) -> Dict:
    from src.messaging import store

    try:
        args = _parse_tool_args(content)
    except ValueError:
        return {"error": "Invalid JSON arguments", "exit_code": 1}
    try:
        chat_id = int(args.get("chat_id"))
    except (TypeError, ValueError):
        return {"error": "chat_id is required (an integer from list_messenger_chats or search results)",
                "exit_code": 1}
    chat = await asyncio.to_thread(store.get_chat, owner, chat_id)
    if not chat or chat.get("excluded"):
        return {"error": f"No chat with chat_id={chat_id}", "exit_code": 1}
    rows = await asyncio.to_thread(
        store.read_chat, owner, chat_id,
        before=_bound(args.get("before")), after=_bound(args.get("after")),
        limit=_int_arg(args, "limit", 50),
    )
    source = _SOURCE_LABELS.get(chat["source_kind"], chat["source_kind"])
    header = f"{source} chat '{chat['title']}' (chat_id={chat_id}), {len(rows)} message(s), oldest first."
    if not rows:
        return {"output": header + "\nNo messages in that range.", "exit_code": 0}
    lines = [header]
    for r in rows:
        lines.append(f"[{_fmt_ts(r['sent_at'])}] {r['sender_name'] or r['sender_id']}: {_clip(r['body'])}")
    if len(rows) >= _int_arg(args, "limit", 50):
        lines.append(f"(Older messages: call again with before=\"{_iso(rows[0]['sent_at'])}\".)")
    return {"output": _cap_output(lines), "exit_code": 0}


def _iso(ms: int) -> str:
    return datetime.fromtimestamp(int(ms) / 1000, timezone.utc).isoformat(timespec="seconds")


async def do_search_messenger_messages(content: str, owner: Optional[str] = None) -> Dict:
    from src.messaging import store

    try:
        args = _parse_tool_args(content)
    except ValueError:
        return {"error": "Invalid JSON arguments", "exit_code": 1}
    query = str(args.get("query") or "").strip()
    sender = str(args.get("sender") or "").strip() or None
    since, until = _bound(args.get("since")), _bound(args.get("until"))
    chat_id = args.get("chat_id")
    if not (query or sender or since or until or chat_id):
        return {"error": "Give a query, or at least one of sender/since/until/chat_id", "exit_code": 1}
    if not await asyncio.to_thread(store.list_sources, owner, include_disabled=False):
        return _no_sources_message()
    try:
        rows = await asyncio.to_thread(
            store.search_messages, owner, query,
            source=args.get("source"), chat_id=chat_id, sender=sender,
            since=since, until=until, limit=_int_arg(args, "limit", 20),
        )
    except (TypeError, ValueError):
        return {"error": "chat_id must be an integer", "exit_code": 1}
    if not rows:
        return {"output": "No messages matched.", "exit_code": 0}
    lines = [f"{len(rows)} match(es). Open the surrounding conversation with read_messenger_chat."]
    for r in rows:
        source = _SOURCE_LABELS.get(r["source_kind"], r["source_kind"])
        text = r.get("snippet") or r["body"]
        lines.append(
            f"- [{_fmt_ts(r['sent_at'])}] {source} '{r['chat_title']}' (chat_id={r['chat_id']}) "
            f"{r['sender_name'] or r['sender_id']}: {_clip(text, 600)}"
        )
    return {"output": _cap_output(lines), "exit_code": 0}
