"""Read Signal Desktop's local database (read-only, never touches Signal's servers).

Signal Desktop keeps messages in a SQLCipher database at
``<signal dir>/sql/db.sqlite``. The 32-byte database key (64 hex chars) lives
in ``<signal dir>/config.json`` in one of three forms:

* ``key``: plaintext (Flathub's default ``basic`` password store);
* ``encryptedKey`` = hex(``v10`` + AES-128-CBC(key)): Electron safeStorage with
  the ``basic_text`` backend, password ``peanuts``;
* ``encryptedKey`` = hex(``v11`` + AES-128-CBC(key)): safeStorage backed by
  KWallet / GNOME Keyring. The container can't reach the host keyring, so the
  user pastes that password once (stored encrypted, like email passwords).

Both encrypted forms use Chromium's Linux OSCrypt scheme: PBKDF2-HMAC-SHA1
(salt ``saltysalt``, 1 iteration, 16-byte key), AES-128-CBC, IV of 16 spaces,
PKCS#7 padding. Adapted from signal-export by Chris Arderne (MIT).

The database is copied (with its WAL/SHM side files) to a private temp dir
before opening, because Signal holds it open, and the copy is always deleted.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from src.messaging import store
from src.messaging.store import ChatRecord, MessageRecord

logger = logging.getLogger(__name__)

_HEX_KEY_RE = re.compile(r"[0-9a-fA-F]{64}")
_KEYRING_HELP = (
    "Signal keeps its database key in your desktop keyring. On the host run "
    "`kwallet-query -r \"Chromium Safe Storage\" -f \"Chromium Keys\" kdewallet` (KDE; list "
    "entries with `kwallet-query -l -f \"Chromium Keys\" kdewallet` if that name differs) or "
    "`secret-tool lookup application Signal` (GNOME), then paste the output into the "
    "Signal source's keyring password field."
)
# Message types that carry user text; everything else is a notice.
_CONTENT_TYPES = {"incoming", "outgoing"}


def _sync_error(message: str):
    from src.messaging.sync import SyncError
    return SyncError(message)


# ── Key handling ─────────────────────────────────────────────────────────

def _oscrypt_decrypt(password: str, blob: bytes) -> Optional[str]:
    from cryptography.hazmat.primitives import hashes, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    if not blob or len(blob) % 16:
        return None
    key = PBKDF2HMAC(algorithm=hashes.SHA1(), length=16, salt=b"saltysalt", iterations=1).derive(
        password.encode("utf-8")
    )
    decryptor = Cipher(algorithms.AES(key), modes.CBC(b" " * 16)).decryptor()
    padded = decryptor.update(blob) + decryptor.finalize()
    try:
        unpadder = padding.PKCS7(128).unpadder()
        plain = unpadder.update(padded) + unpadder.finalize()
        text = plain.decode("ascii")
    except (ValueError, UnicodeDecodeError):
        return None
    return text if _HEX_KEY_RE.fullmatch(text) else None


def resolve_db_key(config: Dict[str, Any], keyring_password: str = "") -> str:
    """Return Signal's 64-hex database key from its parsed config.json."""
    plain = config.get("key")
    if isinstance(plain, str) and _HEX_KEY_RE.fullmatch(plain.strip()):
        return plain.strip()
    encrypted = config.get("encryptedKey")
    if not isinstance(encrypted, str) or not encrypted.strip():
        raise _sync_error("Signal's config.json has no database key. Open Signal Desktop once, then try again.")
    try:
        blob = bytes.fromhex(encrypted.strip())
    except ValueError as exc:
        raise _sync_error("Signal's encryptedKey is not valid hex.") from exc

    prefix, body = blob[:3], blob[3:]
    if prefix == b"v10":
        candidates = ["peanuts", keyring_password]
    elif prefix == b"v11":
        candidates = [keyring_password, ""] if keyring_password else [""]
    else:
        raise _sync_error(
            "Signal's key is protected in a way Odysseus can't read here (not v10/v11). "
            "Windows and macOS installs are not supported inside Docker."
        )
    for password in candidates:
        if password is None:
            continue
        key = _oscrypt_decrypt(password, body)
        if key:
            return key
    if prefix == b"v11" and not keyring_password:
        raise _sync_error(_KEYRING_HELP)
    raise _sync_error("That keyring password did not unlock Signal's key. " + _KEYRING_HELP)


# ── Database access ──────────────────────────────────────────────────────

def _signal_dir(source: Dict[str, Any]) -> str:
    from src.messaging.sync import SIGNAL_HOST_DIR, resolve_allowed_path

    base = resolve_allowed_path((source.get("config") or {}).get("path") or SIGNAL_HOST_DIR)
    if not os.path.isdir(base):
        raise _sync_error(
            f"No Signal folder at {base}. Start Odysseus with docker/signal-desktop.yml "
            "(see Settings > Messaging)."
        )
    if not os.path.isfile(os.path.join(base, "config.json")) or not os.path.isfile(
        os.path.join(base, "sql", "db.sqlite")
    ):
        raise _sync_error(
            f"{base} doesn't look like a Signal Desktop folder (config.json and sql/db.sqlite missing). "
            "Check SIGNAL_DESKTOP_DIR, and that PUID matches your host user."
        )
    return base


def _load_config(signal_dir: str) -> Dict[str, Any]:
    try:
        with open(os.path.join(signal_dir, "config.json"), encoding="utf-8") as fh:
            data = json.load(fh)
    except PermissionError as exc:
        raise _sync_error(
            "Permission denied reading Signal's folder. Set PUID/PGID to your host user "
            "(`id -u`/`id -g`); with rootless Podman add `userns_mode: keep-id`."
        ) from exc
    except (OSError, ValueError) as exc:
        raise _sync_error(f"Could not read Signal's config.json: {exc}") from exc
    return data if isinstance(data, dict) else {}


def _sqlcipher():
    try:
        import sqlcipher3
    except ImportError as exc:
        raise _sync_error(
            "Reading Signal needs the optional sqlcipher3-wheels package "
            "(pip install sqlcipher3-wheels; included in the Docker image)."
        ) from exc
    return sqlcipher3


def _snapshot(signal_dir: str) -> str:
    from src.messaging.sync import MESSAGING_TMP_DIR

    os.makedirs(MESSAGING_TMP_DIR, mode=0o700, exist_ok=True)
    tmp_dir = os.path.join(MESSAGING_TMP_DIR, f"signal-{uuid.uuid4().hex}")
    os.makedirs(tmp_dir, mode=0o700)
    src = os.path.join(signal_dir, "sql", "db.sqlite")
    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(src + suffix):
            shutil.copyfile(src + suffix, os.path.join(tmp_dir, "db.sqlite" + suffix))
            os.chmod(os.path.join(tmp_dir, "db.sqlite" + suffix), 0o600)
    return tmp_dir


def open_database(path: str, key_hex: str):
    sqlcipher3 = _sqlcipher()
    if not _HEX_KEY_RE.fullmatch(key_hex or ""):
        raise _sync_error("Signal's database key has an unexpected format.")
    conn = sqlcipher3.connect(path)
    conn.execute(f"PRAGMA key = \"x'{key_hex}'\"")  # validated hex; pragmas can't bind params
    conn.execute("PRAGMA cipher_page_size = 4096")
    conn.execute("PRAGMA cipher_hmac_algorithm = HMAC_SHA512")
    conn.execute("PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512")
    try:
        conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
    except Exception as exc:
        conn.close()
        raise _sync_error("Could not open Signal's database with its key (wrong key or unsupported format).") from exc
    return conn


def _columns(conn, table: str) -> set:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def read_signal_db(conn) -> Tuple[List[ChatRecord], List[MessageRecord], Dict[str, Any]]:
    """Read chats + text messages. Skips disappearing, view-once, deleted and story messages."""
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    if not {"conversations", "messages"} <= tables:
        raise _sync_error("Unsupported Signal database: conversations/messages tables are missing.")
    ccols, mcols = _columns(conn, "conversations"), _columns(conn, "messages")
    missing = ({"id", "type"} - ccols) | ({"id", "conversationId", "type", "body", "sent_at", "json"} - mcols)
    if missing:
        raise _sync_error(f"Unsupported Signal database: missing columns {sorted(missing)}.")

    def ccol(*names):
        for n in names:
            if n in ccols:
                return n
        return "NULL"

    def mcol(*names):
        for n in names:
            if n in mcols:
                return n
        return "NULL"

    service = ccol("serviceId", "uuid")
    convs = conn.execute(
        f"SELECT id, type, {ccol('name')}, {ccol('profileFullName')}, {ccol('profileName')},"
        f" {ccol('e164')}, {service}, {ccol('json')} FROM conversations"
    ).fetchall()
    by_id: Dict[str, Tuple[str, bool]] = {}
    by_service: Dict[str, str] = {}
    for cid, ctype, name, full, profile, e164, svc, cjson in convs:
        nickname = ""
        if cjson:
            try:
                j = json.loads(cjson)
                nickname = " ".join(p for p in (j.get("nicknameGivenName"), j.get("nicknameFamilyName")) if p)
            except (TypeError, ValueError):
                pass
        title = nickname or name or full or profile or e164 or ("Group" if ctype == "group" else "Unknown")
        by_id[cid] = (title, ctype == "group")
        if svc:
            by_service[svc] = title

    rows = conn.execute(
        "SELECT id, conversationId, type, body, sent_at, json,"
        f" {mcol('sourceServiceId', 'sourceUuid')}, {mcol('expireTimer')}, {mcol('isViewOnce')},"
        f" {mcol('isErased')}, {mcol('isStory')}, {mcol('storyId')}, {mcol('hasAttachments')}, {mcol('source')}"
        " FROM messages ORDER BY sent_at"
    )
    chats: Dict[str, ChatRecord] = {}
    messages: List[MessageRecord] = []
    active: set = set()
    counts = {"skipped_ephemeral": 0, "skipped_deleted": 0, "skipped_system": 0}
    for (mid, cid, mtype, body, sent_at, mjson, source_svc, expire, view_once,
         erased, is_story, story_id, has_att, source_e164) in rows:
        if cid in by_id and mtype in _CONTENT_TYPES:
            active.add(cid)
        if cid not in by_id or mtype not in _CONTENT_TYPES or is_story or story_id:
            counts["skipped_system"] += 1
            continue
        if expire:
            counts["skipped_ephemeral"] += 1
            continue
        meta: Dict[str, Any] = {}
        if mjson:
            try:
                meta = json.loads(mjson) or {}
            except (TypeError, ValueError):
                meta = {}
        if erased or view_once or meta.get("deletedForEveryone") or meta.get("isErased"):
            counts["skipped_deleted"] += 1
            continue
        if meta.get("expireTimer"):
            counts["skipped_ephemeral"] += 1
            continue
        text = (body or "").strip()
        label = _attachment_label(meta) if has_att or meta.get("attachments") else ""
        if label:
            text, kind = f"[{label}] {text}".strip(), "media"
        elif text:
            kind = "text"
        else:
            continue
        title, is_group = by_id[cid]
        chats.setdefault(cid, ChatRecord(external_id=cid, title=title, is_group=is_group))
        if mtype == "outgoing":
            sender_id, sender_name, from_me = "me", "Me", True
        elif is_group:
            sender_id = source_svc or source_e164 or ""
            sender_name, from_me = by_service.get(source_svc or "", source_e164 or "Unknown"), False
        else:
            sender_id, sender_name, from_me = source_svc or cid, title, False
        messages.append(MessageRecord(
            external_id=str(mid), chat_external_id=cid, sent_at=int(sent_at or 0), body=text,
            sender_id=sender_id, sender_name=sender_name, is_from_me=from_me, kind=kind,
        ))
    # Signal keeps a conversation row for every contact it has seen. List the
    # ones with real messages (even if all of them were skipped) so they can
    # be excluded, and leave the never-used ones out.
    for cid in active:
        title, is_group = by_id[cid]
        chats.setdefault(cid, ChatRecord(external_id=cid, title=title, is_group=is_group))
    try:
        counts["schema_version"] = int(conn.execute("PRAGMA user_version").fetchone()[0])
    except Exception:
        pass
    return list(chats.values()), messages, counts


def _attachment_label(meta: Dict[str, Any]) -> str:
    attachments = meta.get("attachments") or []
    ctype = ""
    if attachments and isinstance(attachments[0], dict):
        ctype = str(attachments[0].get("contentType") or "")
    if meta.get("sticker"):
        return "sticker"
    if ctype.startswith("image/"):
        return "image"
    if ctype.startswith("video/"):
        return "video"
    if ctype.startswith("audio/"):
        return "voice message" if attachments[0].get("flags") else "audio"
    return "attachment" if attachments else ""


def _read_source(source: Dict[str, Any]):
    from src.secret_storage import decrypt

    signal_dir = _signal_dir(source)
    key = resolve_db_key(_load_config(signal_dir), decrypt(source.get("secret_enc") or ""))
    tmp_dir = _snapshot(signal_dir)
    try:
        conn = open_database(os.path.join(tmp_dir, "db.sqlite"), key)
        try:
            return read_signal_db(conn)
        finally:
            conn.close()
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _db_mtime(signal_dir: str) -> float:
    base = os.path.join(signal_dir, "sql", "db.sqlite")
    return max((os.path.getmtime(base + sfx) for sfx in ("", "-wal") if os.path.exists(base + sfx)), default=0.0)


def sync_signal_source(owner: Optional[str], source: Dict[str, Any], *, force: bool = False) -> Dict[str, Any]:
    signal_dir = _signal_dir(source)
    mtime = _db_mtime(signal_dir)
    if not force and source.get("last_source_mtime") and float(source["last_source_mtime"]) >= mtime:
        return {"status": "unchanged"}
    chats, messages, counts = _read_source(source)
    stats = store.reconcile_snapshot(owner, source["id"], chats, messages)
    stats.extra.update(counts)
    store.update_source(owner, source["id"], last_source_mtime=mtime)
    return {"status": "synced", **stats.as_dict()}


def test_signal_source(owner: Optional[str], source: Dict[str, Any]) -> Dict[str, Any]:
    chats, messages, counts = _read_source(source)
    return {
        "ok": True,
        "chats": len(chats),
        "messages": len(messages),
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        **counts,
    }


test_signal_source.__test__ = False  # not a pytest test despite the name
