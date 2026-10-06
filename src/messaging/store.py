"""Owner-scoped SQLite + FTS5 index for messages from Signal / WhatsApp.

Raw sqlite3 (not SQLAlchemy) because FTS5 virtual tables and their sync
triggers do not fit the ORM models in core/database.py; the pattern mirrors
``routes/email_helpers.py:_init_scheduled_db``.

Every query is filtered by an exact owner match. The owner bucket is the
authenticated username, or "" in single-user / auth-disabled mode (routes
resolve that case to "" and agent tools to None — both normalise to "").
"""
from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Iterator, List, Optional

from src.constants import MESSAGING_DB

logger = logging.getLogger(__name__)

# Tests monkeypatch this to a tmp_path database.
DB_PATH = MESSAGING_DB

_init_lock = threading.Lock()
_initialised_paths: set = set()

MESSAGE_KINDS = ("text", "media", "other")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS msg_sources (
    id TEXT PRIMARY KEY,
    owner TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    config TEXT NOT NULL DEFAULT '{}',
    secret_enc TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    last_sync_at TEXT,
    last_source_mtime REAL,
    last_error TEXT,
    stats TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_msg_sources_owner ON msg_sources(owner);

CREATE TABLE IF NOT EXISTS msg_chats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner TEXT NOT NULL DEFAULT '',
    source_id TEXT NOT NULL,
    external_id TEXT NOT NULL,
    title TEXT NOT NULL DEFAULT '',
    is_group INTEGER NOT NULL DEFAULT 0,
    excluded INTEGER NOT NULL DEFAULT 0,
    last_message_at INTEGER,
    message_count INTEGER NOT NULL DEFAULT 0,
    UNIQUE(source_id, external_id)
);
CREATE INDEX IF NOT EXISTS idx_msg_chats_owner ON msg_chats(owner, last_message_at);

CREATE TABLE IF NOT EXISTS msg_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner TEXT NOT NULL DEFAULT '',
    source_id TEXT NOT NULL,
    chat_id INTEGER NOT NULL,
    external_id TEXT NOT NULL,
    sender_id TEXT NOT NULL DEFAULT '',
    sender_name TEXT NOT NULL DEFAULT '',
    is_from_me INTEGER NOT NULL DEFAULT 0,
    sent_at INTEGER NOT NULL,
    body TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL DEFAULT 'text',
    UNIQUE(source_id, external_id)
);
CREATE INDEX IF NOT EXISTS idx_msg_messages_chat ON msg_messages(chat_id, sent_at);
CREATE INDEX IF NOT EXISTS idx_msg_messages_owner ON msg_messages(owner, sent_at);

CREATE VIRTUAL TABLE IF NOT EXISTS msg_messages_fts USING fts5(
    body, sender_name,
    content='msg_messages', content_rowid='id',
    tokenize='unicode61 remove_diacritics 2'
);
CREATE TRIGGER IF NOT EXISTS msg_messages_ai AFTER INSERT ON msg_messages BEGIN
    INSERT INTO msg_messages_fts(rowid, body, sender_name)
    VALUES (new.id, new.body, new.sender_name);
END;
CREATE TRIGGER IF NOT EXISTS msg_messages_ad AFTER DELETE ON msg_messages BEGIN
    INSERT INTO msg_messages_fts(msg_messages_fts, rowid, body, sender_name)
    VALUES ('delete', old.id, old.body, old.sender_name);
END;
CREATE TRIGGER IF NOT EXISTS msg_messages_au AFTER UPDATE OF body, sender_name ON msg_messages BEGIN
    INSERT INTO msg_messages_fts(msg_messages_fts, rowid, body, sender_name)
    VALUES ('delete', old.id, old.body, old.sender_name);
    INSERT INTO msg_messages_fts(rowid, body, sender_name)
    VALUES (new.id, new.body, new.sender_name);
END;
"""


def owner_bucket(owner: Optional[str]) -> str:
    """Normalise the caller's owner to the storage bucket ("" = single-user)."""
    return str(owner or "").strip()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _secure_file(path: str) -> None:
    for suffix in ("", "-wal", "-shm"):
        try:
            if os.path.exists(path + suffix):
                os.chmod(path + suffix, 0o600)
        except OSError:
            pass


def init_db(path: Optional[str] = None) -> str:
    path = path or DB_PATH
    with _init_lock:
        if path in _initialised_paths and os.path.exists(path):
            return path
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        conn = sqlite3.connect(path)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_SCHEMA)
            conn.commit()
        finally:
            conn.close()
        _secure_file(path)
        _initialised_paths.add(path)
    return path


@contextmanager
def connect(path: Optional[str] = None) -> Iterator[sqlite3.Connection]:
    path = init_db(path)
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ── Sources ──────────────────────────────────────────────────────────────

def _source_row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    d["config"] = json.loads(d.get("config") or "{}")
    d["stats"] = json.loads(d.get("stats") or "{}")
    d["enabled"] = bool(d.get("enabled"))
    return d


def list_sources(owner: Optional[str], *, include_disabled: bool = True) -> List[Dict[str, Any]]:
    sql = "SELECT * FROM msg_sources WHERE owner = ?"
    if not include_disabled:
        sql += " AND enabled = 1"
    with connect() as conn:
        rows = conn.execute(sql + " ORDER BY created_at", (owner_bucket(owner),)).fetchall()
    return [_source_row_to_dict(r) for r in rows]


def get_source(owner: Optional[str], source_id: str) -> Optional[Dict[str, Any]]:
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM msg_sources WHERE id = ? AND owner = ?",
            (source_id, owner_bucket(owner)),
        ).fetchone()
    return _source_row_to_dict(row) if row else None


def create_source(owner: Optional[str], *, kind: str, name: str,
                  config: Optional[Dict[str, Any]] = None, secret_enc: str = "",
                  enabled: bool = True) -> Dict[str, Any]:
    source_id = uuid.uuid4().hex
    with connect() as conn:
        conn.execute(
            "INSERT INTO msg_sources (id, owner, kind, name, config, secret_enc, enabled, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (source_id, owner_bucket(owner), kind, name, json.dumps(config or {}),
             secret_enc or "", 1 if enabled else 0, _now_iso()),
        )
    return get_source(owner, source_id)


def update_source(owner: Optional[str], source_id: str, **fields: Any) -> Optional[Dict[str, Any]]:
    allowed = {"name", "config", "secret_enc", "enabled", "last_sync_at",
               "last_source_mtime", "last_error", "stats"}
    sets, params = [], []
    for key, value in fields.items():
        if key not in allowed:
            raise ValueError(f"unknown source field: {key}")
        if key in ("config", "stats"):
            value = json.dumps(value or {})
        elif key == "enabled":
            value = 1 if value else 0
        sets.append(f"{key} = ?")
        params.append(value)
    if not sets:
        return get_source(owner, source_id)
    with connect() as conn:
        cur = conn.execute(
            f"UPDATE msg_sources SET {', '.join(sets)} WHERE id = ? AND owner = ?",
            (*params, source_id, owner_bucket(owner)),
        )
        if cur.rowcount == 0:
            return None
    return get_source(owner, source_id)


def delete_source(owner: Optional[str], source_id: str) -> bool:
    """Delete a source and everything indexed from it."""
    bucket = owner_bucket(owner)
    with connect() as conn:
        row = conn.execute(
            "SELECT id FROM msg_sources WHERE id = ? AND owner = ?", (source_id, bucket)
        ).fetchone()
        if not row:
            return False
        conn.execute("DELETE FROM msg_messages WHERE source_id = ?", (source_id,))
        conn.execute("DELETE FROM msg_chats WHERE source_id = ?", (source_id,))
        conn.execute("DELETE FROM msg_sources WHERE id = ?", (source_id,))
    return True


# ── Snapshot reconcile ───────────────────────────────────────────────────

@dataclass
class ChatRecord:
    external_id: str
    title: str
    is_group: bool = False


@dataclass
class MessageRecord:
    external_id: str
    chat_external_id: str
    sent_at: int  # epoch milliseconds, UTC
    body: str
    sender_id: str = ""
    sender_name: str = ""
    is_from_me: bool = False
    kind: str = "text"


@dataclass
class ReconcileStats:
    chats: int = 0
    messages: int = 0
    added: int = 0
    updated: int = 0
    removed: int = 0
    skipped_excluded: int = 0
    extra: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        d = {k: v for k, v in self.__dict__.items() if k != "extra"}
        d.update(self.extra)
        return d


def reconcile_snapshot(owner: Optional[str], source_id: str,
                       chats: Iterable[ChatRecord],
                       messages: Iterable[MessageRecord]) -> ReconcileStats:
    """Make the index for ``source_id`` match one full snapshot of the source.

    Upserts every chat and message in the snapshot, then deletes anything the
    snapshot no longer contains. That is how deletions (delete-for-everyone,
    expired disappearing messages, a chat deleted on the phone) propagate.
    Messages in chats the user has excluded are never stored.
    """
    bucket = owner_bucket(owner)
    stats = ReconcileStats()
    with connect() as conn:
        if not conn.execute(
            "SELECT 1 FROM msg_sources WHERE id = ? AND owner = ?", (source_id, bucket)
        ).fetchone():
            raise LookupError("source not found")

        conn.execute("CREATE TEMP TABLE IF NOT EXISTS seen_chats (external_id TEXT PRIMARY KEY)")
        conn.execute("CREATE TEMP TABLE IF NOT EXISTS seen_messages (external_id TEXT PRIMARY KEY)")
        conn.execute("DELETE FROM temp.seen_chats")
        conn.execute("DELETE FROM temp.seen_messages")

        for chat in chats:
            conn.execute(
                "INSERT INTO msg_chats (owner, source_id, external_id, title, is_group)"
                " VALUES (?, ?, ?, ?, ?)"
                " ON CONFLICT(source_id, external_id) DO UPDATE SET"
                "   title = excluded.title, is_group = excluded.is_group",
                (bucket, source_id, chat.external_id, chat.title or "", 1 if chat.is_group else 0),
            )
            conn.execute("INSERT OR IGNORE INTO temp.seen_chats VALUES (?)", (chat.external_id,))
            stats.chats += 1

        chat_ids: Dict[str, tuple] = {
            r["external_id"]: (r["id"], bool(r["excluded"]))
            for r in conn.execute(
                "SELECT id, external_id, excluded FROM msg_chats WHERE source_id = ?", (source_id,)
            )
        }

        for msg in messages:
            chat = chat_ids.get(msg.chat_external_id)
            if chat is None:
                continue
            chat_id, excluded = chat
            if excluded:
                stats.skipped_excluded += 1
                continue
            existing = conn.execute(
                "SELECT id, body, sender_name, sent_at, kind, is_from_me, sender_id FROM msg_messages"
                " WHERE source_id = ? AND external_id = ?",
                (source_id, msg.external_id),
            ).fetchone()
            values = (msg.sender_id or "", msg.sender_name or "", 1 if msg.is_from_me else 0,
                      int(msg.sent_at), msg.body or "", msg.kind or "text")
            if existing is None:
                conn.execute(
                    "INSERT INTO msg_messages (owner, source_id, chat_id, external_id, sender_id,"
                    " sender_name, is_from_me, sent_at, body, kind) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (bucket, source_id, chat_id, msg.external_id, *values),
                )
                stats.added += 1
            elif (existing["sender_id"], existing["sender_name"], existing["is_from_me"],
                  existing["sent_at"], existing["body"], existing["kind"]) != values:
                # Edited messages and refreshed contact names land here.
                conn.execute(
                    "UPDATE msg_messages SET sender_id = ?, sender_name = ?, is_from_me = ?,"
                    " sent_at = ?, body = ?, kind = ?, chat_id = ? WHERE id = ?",
                    (*values, chat_id, existing["id"]),
                )
                stats.updated += 1
            conn.execute("INSERT OR IGNORE INTO temp.seen_messages VALUES (?)", (msg.external_id,))
            stats.messages += 1

        cur = conn.execute(
            "DELETE FROM msg_messages WHERE source_id = ?"
            " AND external_id NOT IN (SELECT external_id FROM temp.seen_messages)",
            (source_id,),
        )
        stats.removed = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
        conn.execute(
            "DELETE FROM msg_chats WHERE source_id = ? AND excluded = 0"
            " AND external_id NOT IN (SELECT external_id FROM temp.seen_chats)",
            (source_id,),
        )
        _refresh_chat_counts(conn, source_id)
        conn.execute("DROP TABLE IF EXISTS temp.seen_chats")
        conn.execute("DROP TABLE IF EXISTS temp.seen_messages")
    return stats


def _refresh_chat_counts(conn: sqlite3.Connection, source_id: str) -> None:
    conn.execute(
        "UPDATE msg_chats SET"
        " message_count = (SELECT COUNT(*) FROM msg_messages m WHERE m.chat_id = msg_chats.id),"
        " last_message_at = (SELECT MAX(sent_at) FROM msg_messages m WHERE m.chat_id = msg_chats.id)"
        " WHERE source_id = ?",
        (source_id,),
    )


# ── Chats ────────────────────────────────────────────────────────────────

def _source_filter_sql(source: Optional[str]) -> tuple:
    """Filter by source kind ('signal'/'whatsapp'), full kind, or source id."""
    if not source:
        return "", ()
    s = str(source).strip().lower()
    if s in ("signal", "signal_desktop"):
        return " AND s.kind = ?", ("signal_desktop",)
    if s in ("whatsapp", "whatsapp_backup", "wa"):
        return " AND s.kind = ?", ("whatsapp_backup",)
    return " AND s.id = ?", (str(source).strip(),)


def list_chats(owner: Optional[str], *, source: Optional[str] = None, query: Optional[str] = None,
               limit: int = 30, include_excluded: bool = False) -> List[Dict[str, Any]]:
    src_sql, src_params = _source_filter_sql(source)
    sql = (
        "SELECT c.id, c.title, c.is_group, c.excluded, c.last_message_at, c.message_count,"
        " s.kind AS source_kind, s.name AS source_name, s.id AS source_id"
        " FROM msg_chats c JOIN msg_sources s ON s.id = c.source_id"
        " WHERE c.owner = ? AND s.owner = ? AND s.enabled = 1" + src_sql
    )
    params: List[Any] = [owner_bucket(owner), owner_bucket(owner), *src_params]
    if not include_excluded:
        sql += " AND c.excluded = 0"
    if query:
        sql += " AND c.title LIKE ? ESCAPE '\\'"
        params.append("%" + _like_escape(query) + "%")
    sql += " ORDER BY c.last_message_at IS NULL, c.last_message_at DESC LIMIT ?"
    params.append(max(1, min(int(limit or 30), 500)))
    with connect() as conn:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]


def get_chat(owner: Optional[str], chat_id: int) -> Optional[Dict[str, Any]]:
    with connect() as conn:
        row = conn.execute(
            "SELECT c.*, s.kind AS source_kind, s.name AS source_name"
            " FROM msg_chats c JOIN msg_sources s ON s.id = c.source_id"
            " WHERE c.id = ? AND c.owner = ? AND s.owner = ?",
            (int(chat_id), owner_bucket(owner), owner_bucket(owner)),
        ).fetchone()
    return dict(row) if row else None


def set_chat_excluded(owner: Optional[str], chat_id: int, excluded: bool) -> bool:
    """Exclude (and purge) or re-include a chat. Re-included chats refill on next sync."""
    bucket = owner_bucket(owner)
    with connect() as conn:
        row = conn.execute(
            "SELECT id, source_id FROM msg_chats WHERE id = ? AND owner = ?", (int(chat_id), bucket)
        ).fetchone()
        if not row:
            return False
        conn.execute("UPDATE msg_chats SET excluded = ? WHERE id = ?", (1 if excluded else 0, row["id"]))
        if excluded:
            conn.execute("DELETE FROM msg_messages WHERE chat_id = ?", (row["id"],))
            _refresh_chat_counts(conn, row["source_id"])
    return True


# ── Messages ─────────────────────────────────────────────────────────────

def _like_escape(text: str) -> str:
    return str(text).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


_FTS_TOKEN_RE = re.compile(r"\w+", re.UNICODE)


def fts_query(text: str) -> str:
    """Turn free text into a safe FTS5 query: every word, prefix-matched, ANDed.

    Raw user/model text can contain FTS5 syntax (quotes, NEAR, column
    filters, unbalanced parentheses) that raises at MATCH time; quoting each
    token makes any input a valid query.
    """
    tokens = _FTS_TOKEN_RE.findall(str(text or ""))
    return " ".join(f'"{t}"*' for t in tokens[:16])


def parse_time_bound(value: Any, default_tz=None) -> Optional[int]:
    """ISO date/datetime (or epoch seconds/ms) -> epoch ms. None if blank/invalid.

    Naive values are read in ``default_tz`` (the user's timezone when the
    caller knows it), else UTC.
    """
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        v = float(value)
        return int(v if v > 1e11 else v * 1000)
    text = str(value).strip()
    if not text:
        return None
    if re.fullmatch(r"\d{9,13}", text):
        return parse_time_bound(int(text))
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=default_tz or timezone.utc)
    return int(dt.timestamp() * 1000)


def _message_select() -> str:
    return (
        "SELECT m.id, m.chat_id, m.sender_name, m.sender_id, m.is_from_me, m.sent_at, m.body, m.kind,"
        " c.title AS chat_title, c.is_group, s.kind AS source_kind"
        " FROM msg_messages m"
        " JOIN msg_chats c ON c.id = m.chat_id"
        " JOIN msg_sources s ON s.id = m.source_id"
    )


def read_chat(owner: Optional[str], chat_id: int, *, before: Any = None, after: Any = None,
              limit: int = 50) -> List[Dict[str, Any]]:
    """Messages in one chat, oldest -> newest. Without bounds, returns the latest ``limit``."""
    bucket = owner_bucket(owner)
    limit = max(1, min(int(limit or 50), 500))
    sql = _message_select() + " WHERE m.chat_id = ? AND m.owner = ? AND s.owner = ? AND s.enabled = 1 AND c.excluded = 0"
    params: List[Any] = [int(chat_id), bucket, bucket]
    before_ms, after_ms = parse_time_bound(before), parse_time_bound(after)
    if before_ms is not None:
        sql += " AND m.sent_at < ?"
        params.append(before_ms)
    if after_ms is not None:
        sql += " AND m.sent_at > ?"
        params.append(after_ms)
    # After-only reads page forwards from the bound; otherwise take the newest.
    order = "ASC" if after_ms is not None and before_ms is None else "DESC"
    sql += f" ORDER BY m.sent_at {order}, m.id {order} LIMIT ?"
    params.append(limit)
    with connect() as conn:
        rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
    if order == "DESC":
        rows.reverse()
    return rows


def search_messages(owner: Optional[str], query: str, *, source: Optional[str] = None,
                    chat_id: Optional[int] = None, sender: Optional[str] = None,
                    since: Any = None, until: Any = None, limit: int = 20) -> List[Dict[str, Any]]:
    bucket = owner_bucket(owner)
    limit = max(1, min(int(limit or 20), 200))
    match = fts_query(query)
    src_sql, src_params = _source_filter_sql(source)
    params: List[Any] = []
    if match:
        sql = (
            "SELECT m.id, m.chat_id, m.sender_name, m.sender_id, m.is_from_me, m.sent_at, m.body, m.kind,"
            " c.title AS chat_title, c.is_group, s.kind AS source_kind,"
            " snippet(msg_messages_fts, 0, '[', ']', ' … ', 24) AS snippet"
            " FROM msg_messages_fts f"
            " JOIN msg_messages m ON m.id = f.rowid"
            " JOIN msg_chats c ON c.id = m.chat_id"
            " JOIN msg_sources s ON s.id = m.source_id"
            " WHERE msg_messages_fts MATCH ?"
        )
        params.append(match)
    else:
        sql = _message_select() + " WHERE 1 = 1"
    sql += " AND m.owner = ? AND s.owner = ? AND s.enabled = 1 AND c.excluded = 0" + src_sql
    params += [bucket, bucket, *src_params]
    if chat_id not in (None, ""):
        sql += " AND m.chat_id = ?"
        params.append(int(chat_id))
    if sender:
        sql += " AND (m.sender_name LIKE ? ESCAPE '\\' OR m.sender_id LIKE ? ESCAPE '\\')"
        like = "%" + _like_escape(sender) + "%"
        params += [like, like]
    since_ms, until_ms = parse_time_bound(since), parse_time_bound(until)
    if since_ms is not None:
        sql += " AND m.sent_at >= ?"
        params.append(since_ms)
    if until_ms is not None:
        sql += " AND m.sent_at <= ?"
        params.append(until_ms)
    sql += (" ORDER BY bm25(msg_messages_fts), m.sent_at DESC" if match else " ORDER BY m.sent_at DESC")
    sql += " LIMIT ?"
    params.append(limit)
    with connect() as conn:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]


def owner_totals(owner: Optional[str]) -> Dict[str, int]:
    bucket = owner_bucket(owner)
    with connect() as conn:
        chats = conn.execute("SELECT COUNT(*) FROM msg_chats WHERE owner = ?", (bucket,)).fetchone()[0]
        msgs = conn.execute("SELECT COUNT(*) FROM msg_messages WHERE owner = ?", (bucket,)).fetchone()[0]
    return {"chats": int(chats), "messages": int(msgs)}


def source_totals(source_id: str) -> Dict[str, int]:
    with connect() as conn:
        chats = conn.execute("SELECT COUNT(*) FROM msg_chats WHERE source_id = ?", (source_id,)).fetchone()[0]
        msgs = conn.execute("SELECT COUNT(*) FROM msg_messages WHERE source_id = ?", (source_id,)).fetchone()[0]
    return {"chats": int(chats), "messages": int(msgs)}
