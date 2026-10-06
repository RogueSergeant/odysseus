"""Sync messaging sources into the local index.

One sync = read a full snapshot of the source, reconcile it into the index
(``store.reconcile_snapshot``), and record the outcome on the source row.
WhatsApp backups are only re-read when the backup file's mtime changes.
"""
from __future__ import annotations

import logging
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from src.constants import MESSAGING_INBOX_DIR, MESSAGING_TMP_DIR
from src.messaging import store

logger = logging.getLogger(__name__)

DEFAULT_COUNTRY_CODE = "44"
WHATSAPP_INBOX = os.path.join(MESSAGING_INBOX_DIR, "whatsapp")
SIGNAL_HOST_DIR = "/host/signal"

_source_locks: Dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()


class SyncError(Exception):
    """User-facing sync failure (message is stored as the source's last_error)."""


def _lock_for(source_id: str) -> threading.Lock:
    with _locks_guard:
        return _source_locks.setdefault(source_id, threading.Lock())


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ── Path policy ──────────────────────────────────────────────────────────

def allowed_roots() -> List[str]:
    """Directories a source path may point into.

    Keeps the settings form (admin-only) from turning into a way to read
    arbitrary files: the inbox Syncthing writes to, the read-only Signal
    mount from docker/messaging.yml, plus anything listed in
    ODYSSEUS_MESSAGING_PATHS (os.pathsep-separated) for native installs.
    """
    roots = [MESSAGING_INBOX_DIR, SIGNAL_HOST_DIR]
    extra = os.getenv("ODYSSEUS_MESSAGING_PATHS", "")
    roots += [p for p in extra.split(os.pathsep) if p.strip()]
    return [os.path.realpath(os.path.expanduser(p.strip())) for p in roots]


def resolve_allowed_path(path: str) -> str:
    real = os.path.realpath(os.path.expanduser(str(path or "").strip()))
    for root in allowed_roots():
        if real == root or real.startswith(root.rstrip(os.sep) + os.sep):
            return real
    raise SyncError(
        "That path is outside the folders Odysseus may read. Use the Syncthing inbox "
        f"({MESSAGING_INBOX_DIR}), the Signal mount ({SIGNAL_HOST_DIR}), or add the folder "
        "to ODYSSEUS_MESSAGING_PATHS."
    )


# ── Contact names ────────────────────────────────────────────────────────

def normalise_phone(raw: str, default_cc: str = DEFAULT_COUNTRY_CODE) -> str:
    """Best-effort E.164 digits without '+': '07700 900123' -> '447700900123' (cc 44)."""
    text = str(raw or "").strip()
    if not text:
        return ""
    plus = text.startswith("+")
    digits = re.sub(r"\D", "", text)
    if not digits:
        return ""
    if plus:
        return digits
    if digits.startswith("00"):
        return digits[2:]
    if digits.startswith("0") and default_cc:
        return default_cc + digits[1:]
    return digits


def build_name_resolver(default_cc: str = DEFAULT_COUNTRY_CODE,
                        contacts: Optional[List[Dict[str, Any]]] = None) -> Callable[[str], Optional[str]]:
    """Map WhatsApp phone digits to Odysseus contact names (CardDAV or local)."""
    if contacts is None:
        try:
            from routes.contacts.contacts_routes import _fetch_contacts
            contacts = _fetch_contacts() or []
        except Exception as exc:  # contacts are a nicety; never fail a sync over them
            logger.debug("messaging: contacts unavailable: %s", exc)
            contacts = []
    exact: Dict[str, str] = {}
    by_tail: Dict[str, set] = {}
    for c in contacts:
        name = str(c.get("name") or "").strip()
        if not name:
            continue
        for phone in c.get("phones") or []:
            digits = normalise_phone(phone, default_cc)
            if len(digits) < 7:
                continue
            exact.setdefault(digits, name)
            by_tail.setdefault(digits[-9:], set()).add(name)

    def resolve(digits: str) -> Optional[str]:
        if not digits:
            return None
        if digits in exact:
            return exact[digits]
        names = by_tail.get(digits[-9:])
        if names and len(names) == 1:
            return next(iter(names))
        return None

    return resolve


# ── WhatsApp ─────────────────────────────────────────────────────────────

def find_whatsapp_backup(config: Dict[str, Any]) -> str:
    """Locate msgstore.db.crypt15 under the configured (or default) folder."""
    from src.messaging.whatsapp_backup import BACKUP_FILENAME

    base = config.get("path") or WHATSAPP_INBOX
    base = resolve_allowed_path(base)
    if os.path.isfile(base):
        return base
    if not os.path.isdir(base):
        raise SyncError(
            f"No backup folder at {base} yet. Pair Syncthing with your phone and share "
            "WhatsApp's Databases folder (see Settings > Messaging)."
        )
    best: Optional[str] = None
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if not d.startswith(".st")]  # Syncthing internals
        if BACKUP_FILENAME in filenames:
            candidate = os.path.join(dirpath, BACKUP_FILENAME)
            if best is None or os.path.getmtime(candidate) > os.path.getmtime(best):
                best = candidate
    if not best:
        crypt14 = any("crypt14" in f for _, _, files in os.walk(base) for f in files)
        if crypt14:
            raise SyncError(
                "Found only a .crypt14 backup. Turn on end-to-end encrypted backup with a "
                "64-digit key in WhatsApp so the phone writes msgstore.db.crypt15."
            )
        raise SyncError(f"No {BACKUP_FILENAME} found under {base} yet.")
    return best


def _sync_whatsapp(owner: Optional[str], source: Dict[str, Any], force: bool) -> Dict[str, Any]:
    from src.secret_storage import decrypt
    from src.messaging.whatsapp_backup import BackupError, decrypt_backup, parse_backup_key, read_msgstore

    config = source.get("config") or {}
    backup = find_whatsapp_backup(config)
    mtime = os.path.getmtime(backup)
    if not force and source.get("last_source_mtime") and float(source["last_source_mtime"]) >= mtime:
        return {"status": "unchanged", "backup_path": backup}

    secret = decrypt(source.get("secret_enc") or "")
    if not secret:
        raise SyncError("No 64-digit backup key saved for this source.")
    try:
        root_key = parse_backup_key(secret)
    except BackupError as exc:
        raise SyncError(str(exc)) from exc

    os.makedirs(MESSAGING_TMP_DIR, mode=0o700, exist_ok=True)
    tmp = os.path.join(MESSAGING_TMP_DIR, f"wa-{uuid.uuid4().hex}.db")
    try:
        try:
            header = decrypt_backup(backup, root_key, tmp)
            resolver = build_name_resolver(str(config.get("country_code") or DEFAULT_COUNTRY_CODE))
            chats, messages, counts = read_msgstore(tmp, resolver)
        except BackupError as exc:
            raise SyncError(str(exc)) from exc
        stats = store.reconcile_snapshot(owner, source["id"], chats, messages)
        stats.extra.update(counts)
        stats.extra["backup_taken_at"] = datetime.fromtimestamp(mtime, timezone.utc).isoformat(timespec="seconds")
        if header.app_version:
            stats.extra["whatsapp_version"] = header.app_version
    finally:
        for suffix in ("", "-journal", "-wal", "-shm"):
            try:
                os.remove(tmp + suffix)
            except OSError:
                pass
    store.update_source(owner, source["id"], last_source_mtime=mtime)
    return {"status": "synced", "backup_path": backup, **stats.as_dict()}


def _test_whatsapp(owner: Optional[str], source: Dict[str, Any]) -> Dict[str, Any]:
    from src.secret_storage import decrypt
    from src.messaging.whatsapp_backup import BackupError, decrypt_backup, parse_backup_key, read_msgstore

    backup = find_whatsapp_backup(source.get("config") or {})
    secret = decrypt(source.get("secret_enc") or "")
    if not secret:
        raise SyncError("No 64-digit backup key saved for this source.")
    try:
        root_key = parse_backup_key(secret)
    except BackupError as exc:
        raise SyncError(str(exc)) from exc
    os.makedirs(MESSAGING_TMP_DIR, mode=0o700, exist_ok=True)
    tmp = os.path.join(MESSAGING_TMP_DIR, f"wa-test-{uuid.uuid4().hex}.db")
    try:
        try:
            header = decrypt_backup(backup, root_key, tmp)
            chats, messages, counts = read_msgstore(tmp)
        except BackupError as exc:
            raise SyncError(str(exc)) from exc
    finally:
        for suffix in ("", "-journal", "-wal", "-shm"):
            try:
                os.remove(tmp + suffix)
            except OSError:
                pass
    mtime = os.path.getmtime(backup)
    return {
        "ok": True,
        "backup_path": backup,
        "backup_taken_at": datetime.fromtimestamp(mtime, timezone.utc).isoformat(timespec="seconds"),
        "whatsapp_version": header.app_version,
        "chats": len(chats),
        "messages": len(messages),
        **counts,
    }


def test_source(owner: Optional[str], source_id: str) -> Dict[str, Any]:
    """Check a source can be read. Returns counts only, never message content."""
    source = store.get_source(owner, source_id)
    if not source:
        raise LookupError("source not found")
    try:
        if source["kind"] == "whatsapp_backup":
            return _test_whatsapp(owner, source)
        if source["kind"] == "signal_desktop":
            from src.messaging.signal_desktop import test_signal_source
            return test_signal_source(owner, source)
        raise SyncError(f"Unknown source kind: {source['kind']}")
    except SyncError as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:
        logger.exception("messaging: test failed for source %s", source_id)
        return {"ok": False, "error": f"Test failed: {type(exc).__name__}"}


test_source.__test__ = False  # not a pytest test despite the name


# ── Dispatcher ───────────────────────────────────────────────────────────

def _sync_signal(owner: Optional[str], source: Dict[str, Any], force: bool) -> Dict[str, Any]:
    from src.messaging.signal_desktop import sync_signal_source
    return sync_signal_source(owner, source, force=force)


_SYNCERS = {
    "whatsapp_backup": _sync_whatsapp,
    "signal_desktop": _sync_signal,
}


def sync_source(owner: Optional[str], source_id: str, *, force: bool = False) -> Dict[str, Any]:
    """Sync one source (blocking — call via asyncio.to_thread from async code)."""
    source = store.get_source(owner, source_id)
    if not source:
        raise LookupError("source not found")
    syncer = _SYNCERS.get(source["kind"])
    if syncer is None:
        raise SyncError(f"Unknown source kind: {source['kind']}")
    lock = _lock_for(source_id)
    if not lock.acquire(blocking=False):
        return {"status": "busy"}
    try:
        try:
            result = syncer(owner, source, force)
        except Exception as exc:
            if isinstance(exc, SyncError):
                msg = str(exc)
            else:  # unexpected: log the detail, store a short message
                logger.exception("messaging: sync failed for source %s", source_id)
                msg = f"Sync failed: {type(exc).__name__}"
            store.update_source(owner, source_id, last_error=msg, last_sync_at=_now_iso())
            # "repeat" lets the scheduled task stay quiet about an error the
            # settings page is already showing.
            return {"status": "error", "error": msg, "repeat": source.get("last_error") == msg}
        fields: Dict[str, Any] = {"last_error": None, "last_sync_at": _now_iso()}
        if result.get("status") == "synced":
            fields["stats"] = {k: v for k, v in result.items() if k not in ("status",)}
        store.update_source(owner, source_id, **fields)
        return result
    finally:
        lock.release()


def sync_all(owner: Optional[str], *, force: bool = False) -> Dict[str, Any]:
    results = {}
    for source in store.list_sources(owner, include_disabled=False):
        results[source["id"]] = {"name": source["name"], **sync_source(owner, source["id"], force=force)}
    return results
