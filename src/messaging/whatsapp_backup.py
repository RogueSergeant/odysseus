"""Read an Android WhatsApp backup (``msgstore.db.crypt15``) without touching WhatsApp.

WhatsApp on Android writes an encrypted copy of its message database to
``Android/media/com.whatsapp/WhatsApp/Databases/msgstore.db.crypt15`` every
night. With end-to-end encrypted backup enabled using a 64-digit key, that
file is decryptable with the key alone (no root, no network). Syncthing
copies it to Odysseus (see docker/messaging.yml).

crypt15 layout (as documented by wa-crypt-tools / Whatsapp-Chat-Exporter):

    [1 byte  N = protobuf header length]
    [optional 0x01 byte: "feature table present" flag]
    [N bytes BackupPrefix protobuf; field 3 = C15_IV { field 1 = 16-byte IV }]
    [AES-256-GCM ciphertext of zlib(msgstore.db)]
    [16 bytes GCM tag]
    [16 bytes MD5 of everything before it]   (absent in multi-file backups)

The AES key is derived from the 32-byte root key (the 64 hex digits):
``HMAC-SHA256(key=HMAC-SHA256(key=0x00*32, msg=root), msg=b"backup encryption" + b"\\x01")``.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import sqlite3
import zlib
from dataclasses import dataclass
from typing import Callable, Dict, Iterator, List, Optional, Tuple

from src.messaging.store import ChatRecord, MessageRecord

logger = logging.getLogger(__name__)

BACKUP_FILENAME = "msgstore.db.crypt15"
_CHUNK = 1024 * 1024
_SQLITE_MAGIC = b"SQLite format 3\x00"


class BackupError(Exception):
    """A user-facing problem with the backup file or key (message is safe to show)."""


# ── Key handling ─────────────────────────────────────────────────────────

def parse_backup_key(text: str) -> bytes:
    """Accept the 64-digit key as shown by WhatsApp (spaces/dashes/newlines allowed)."""
    cleaned = re.sub(r"[\s\-:]", "", str(text or ""))
    if not re.fullmatch(r"[0-9a-fA-F]{64}", cleaned):
        raise BackupError(
            "The backup key must be the 64-character key WhatsApp showed when you "
            "turned on end-to-end encrypted backup (digits 0-9 and letters a-f)."
        )
    return bytes.fromhex(cleaned)


def derive_backup_encryption_key(root_key: bytes) -> bytes:
    if len(root_key) != 32:
        raise BackupError("The backup key must decode to 32 bytes.")
    private = hmac.new(b"\x00" * 32, root_key, hashlib.sha256).digest()
    return hmac.new(private, b"backup encryption" + b"\x01", hashlib.sha256).digest()


# ── Minimal protobuf reader for the BackupPrefix header ──────────────────

def _read_varint(buf: bytes, pos: int) -> Tuple[int, int]:
    result, shift = 0, 0
    while True:
        if pos >= len(buf):
            raise BackupError("The backup header is truncated.")
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            raise BackupError("The backup header is malformed.")


def _iter_fields(buf: bytes) -> Iterator[Tuple[int, int, object]]:
    pos = 0
    while pos < len(buf):
        tag, pos = _read_varint(buf, pos)
        field_no, wire = tag >> 3, tag & 7
        if wire == 0:
            value, pos = _read_varint(buf, pos)
        elif wire == 2:
            length, pos = _read_varint(buf, pos)
            if pos + length > len(buf):
                raise BackupError("The backup header is truncated.")
            value = buf[pos:pos + length]
            pos += length
        elif wire == 1:
            value, pos = buf[pos:pos + 8], pos + 8
        elif wire == 5:
            value, pos = buf[pos:pos + 4], pos + 4
        else:
            raise BackupError("The backup header is malformed.")
        yield field_no, wire, value


@dataclass
class BackupHeader:
    header_len: int  # bytes before the ciphertext
    iv: bytes
    app_version: str = ""


def parse_header(prefix: bytes) -> BackupHeader:
    if len(prefix) < 2:
        raise BackupError("This file is too short to be a WhatsApp backup.")
    size = prefix[0]
    offset = 1
    if prefix[1] == 0x01:  # feature-table flag; a protobuf can't start with 0x01
        offset = 2
    proto = prefix[offset:offset + size]
    if len(proto) != size:
        raise BackupError("The backup header is truncated.")
    iv = b""
    crypt14 = False
    app_version = ""
    for field_no, wire, value in _iter_fields(proto):
        if field_no == 3 and wire == 2:
            for sub_no, sub_wire, sub_val in _iter_fields(value):  # type: ignore[arg-type]
                if sub_no == 1 and sub_wire == 2:
                    iv = bytes(sub_val)  # type: ignore[arg-type]
        elif field_no == 2 and wire == 2:
            crypt14 = True
        elif field_no == 4 and wire == 2:
            for sub_no, sub_wire, sub_val in _iter_fields(value):  # type: ignore[arg-type]
                if sub_no == 1 and sub_wire == 2:
                    try:
                        app_version = bytes(sub_val).decode("utf-8", "replace")  # type: ignore[arg-type]
                    except Exception:
                        pass
    if not iv:
        if crypt14:
            raise BackupError(
                "This backup is not end-to-end encrypted with a 64-digit key. In WhatsApp, "
                "turn on Settings > Chats > Chat backup > End-to-end encrypted backup and "
                "choose 'Use 64-digit encryption key instead', then back up again."
            )
        raise BackupError("No encryption IV found in the backup header.")
    if len(iv) != 16:
        raise BackupError("The backup header has an unexpected IV length.")
    return BackupHeader(header_len=offset + size, iv=iv, app_version=app_version)


# ── Decryption ───────────────────────────────────────────────────────────

def decrypt_backup(src_path: str, root_key: bytes, dest_path: str) -> BackupHeader:
    """Decrypt + decompress ``src_path`` into a plain SQLite file at ``dest_path``.

    Streams in 1 MiB chunks so a multi-GB backup never sits in memory. On any
    failure the partial output is removed before the error is raised.
    """
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    try:
        total = os.path.getsize(src_path)
    except OSError as exc:
        raise BackupError(f"Cannot read the backup file: {exc.strerror or exc}") from exc

    with open(src_path, "rb") as fh:
        header = parse_header(fh.read(256))
        if total < header.header_len + 32:
            raise BackupError("The backup file is truncated.")

        # Single-file backups end with tag + MD5(everything before the MD5).
        # Multi-file backups have no MD5, so the last 16 bytes are the tag.
        md5 = hashlib.md5()
        fh.seek(0)
        remaining = total - 16
        while remaining > 0:
            chunk = fh.read(min(_CHUNK, remaining))
            if not chunk:
                break
            md5.update(chunk)
            remaining -= len(chunk)
        trailing = fh.read(16)
        if md5.digest() == trailing:
            cipher_end = total - 32
            fh.seek(total - 32)
            tag = fh.read(16)
        else:
            cipher_end = total - 16
            tag = trailing

        key = derive_backup_encryption_key(root_key)
        decryptor = Cipher(algorithms.AES(key), modes.GCM(header.iv, tag)).decryptor()
        inflater = zlib.decompressobj()
        os.makedirs(os.path.dirname(dest_path) or ".", exist_ok=True)
        fd = os.open(dest_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        ok = False
        try:
            with os.fdopen(fd, "wb") as out:
                fh.seek(header.header_len)
                remaining = cipher_end - header.header_len
                first = True
                while remaining > 0:
                    chunk = fh.read(min(_CHUNK, remaining))
                    if not chunk:
                        raise BackupError("The backup file is truncated.")
                    remaining -= len(chunk)
                    plain = decryptor.update(chunk)
                    try:
                        data = inflater.decompress(plain)
                    except zlib.error as exc:
                        raise BackupError(
                            "Could not decrypt the backup. Check that the 64-digit key is the "
                            "one for this phone's current backup."
                        ) from exc
                    if first and data:
                        if not data.startswith(_SQLITE_MAGIC[:len(data)]):
                            raise BackupError("The decrypted backup is not a WhatsApp message database.")
                        first = False
                    out.write(data)
                try:
                    decryptor.finalize()
                except InvalidTag as exc:
                    raise BackupError(
                        "The backup failed its integrity check: wrong 64-digit key, or the file "
                        "was still being copied. Try again after Syncthing finishes."
                    ) from exc
                out.write(inflater.flush())
            ok = True
        finally:
            if not ok:
                try:
                    os.remove(dest_path)
                except OSError:
                    pass
    return header


# ── msgstore.db reader ───────────────────────────────────────────────────

# message.message_type values in the modern (2021+) schema.
_TYPE_LABELS: Dict[int, str] = {
    1: "image", 2: "audio", 3: "video", 4: "contact card", 5: "location",
    9: "document", 13: "GIF", 16: "live location", 20: "sticker",
}
_TYPE_SYSTEM = 7
_TYPE_REVOKED = 15
# View-once photo / video / voice: the sender asked for them not to be kept.
_TYPES_VIEW_ONCE = frozenset({42, 43, 82})
_SKIP_JIDS = {"status@broadcast"}
_REQUIRED_TABLES = {"message", "chat", "jid"}


def phone_digits_from_jid(jid: Optional[str]) -> str:
    """'447700900123@s.whatsapp.net' -> '447700900123' ('' for groups/LIDs)."""
    if not jid or "@" not in jid:
        return ""
    user, server = jid.split("@", 1)
    if server not in ("s.whatsapp.net", "c.us"):
        return ""
    user = user.split(":", 1)[0].split(".", 1)[0]
    return user if user.isdigit() else ""


def _table_names(conn: sqlite3.Connection) -> set:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def _columns(conn: sqlite3.Connection, table: str) -> set:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def check_schema(conn: sqlite3.Connection) -> None:
    tables = _table_names(conn)
    if not _REQUIRED_TABLES <= tables:
        if "messages" in tables:
            raise BackupError(
                "This backup uses WhatsApp's pre-2022 database layout, which is not supported. "
                "Update WhatsApp on the phone and let it make a new backup."
            )
        raise BackupError("Unsupported msgstore schema: the message/chat/jid tables are missing.")
    needed = {"_id", "chat_row_id", "from_me", "key_id", "sender_jid_row_id", "timestamp",
              "message_type", "text_data"}
    missing = needed - _columns(conn, "message")
    if missing:
        raise BackupError(f"Unsupported msgstore schema: message table lacks {sorted(missing)}.")


NameResolver = Callable[[str], Optional[str]]


def read_msgstore(db_path: str, resolve_name: Optional[NameResolver] = None,
                  ) -> Tuple[List[ChatRecord], List[MessageRecord], Dict[str, int]]:
    """Read chats + messages from a decrypted msgstore.db.

    Skips status updates, system notices, deleted-for-everyone and view-once
    messages, and any message WhatsApp tracks as disappearing
    (``message_ephemeral``).
    ``resolve_name(phone_digits)`` maps a phone number to a contact name.
    """
    resolve_name = resolve_name or (lambda _digits: None)
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        check_schema(conn)
        tables = _table_names(conn)
        has_map = "jid_map" in tables and {"lid_row_id", "jid_row_id"} <= _columns(conn, "jid_map")
        has_eph = "message_ephemeral" in tables
        chat_cols = _columns(conn, "chat")
        subject = "chat.subject" if "subject" in chat_cols else "NULL"

        map_join = (
            " LEFT JOIN jid_map map_chat ON map_chat.lid_row_id = chat.jid_row_id"
            " LEFT JOIN jid chat_phone ON chat_phone._id = map_chat.jid_row_id"
            " LEFT JOIN jid_map map_sender ON map_sender.lid_row_id = m.sender_jid_row_id"
            " LEFT JOIN jid sender_phone ON sender_phone._id = map_sender.jid_row_id"
        ) if has_map else ""
        chat_phone = "chat_phone.raw_string" if has_map else "NULL"
        sender_phone = "sender_phone.raw_string" if has_map else "NULL"
        eph_join = " LEFT JOIN message_ephemeral eph ON eph.message_row_id = m._id" if has_eph else ""
        eph_col = "eph.message_row_id" if has_eph else "NULL"

        sql = (
            "SELECT m._id, m.key_id, m.from_me, m.timestamp, m.text_data, m.message_type,"
            f" chat_jid.raw_string AS chat_jid, {chat_phone} AS chat_phone_jid, {subject} AS subject,"
            f" sender_jid.raw_string AS sender_jid, {sender_phone} AS sender_phone_jid,"
            f" {eph_col} AS ephemeral"
            " FROM message m"
            " JOIN chat ON chat._id = m.chat_row_id"
            " JOIN jid chat_jid ON chat_jid._id = chat.jid_row_id"
            " LEFT JOIN jid sender_jid ON sender_jid._id = m.sender_jid_row_id"
            + map_join + eph_join +
            " ORDER BY m.timestamp, m._id"
        )

        chats: Dict[str, ChatRecord] = {}
        messages: List[MessageRecord] = []
        counts = {"skipped_ephemeral": 0, "skipped_deleted": 0, "skipped_system": 0}
        name_cache: Dict[str, str] = {}

        def display(raw_jid: Optional[str], phone_jid: Optional[str]) -> Tuple[str, str]:
            digits = phone_digits_from_jid(phone_jid) or phone_digits_from_jid(raw_jid)
            if digits:
                if digits not in name_cache:
                    name_cache[digits] = resolve_name(digits) or f"+{digits}"
                return digits, name_cache[digits]
            return (raw_jid or ""), "Unknown"

        for row in conn.execute(sql):
            chat_jid = row["chat_jid"] or ""
            if not chat_jid or chat_jid in _SKIP_JIDS or chat_jid.endswith("@broadcast") or chat_jid == "-1":
                continue
            mtype = row["message_type"] if row["message_type"] is not None else 0
            is_group = chat_jid.endswith("@g.us")
            if chat_jid not in chats:
                if is_group:
                    title = row["subject"] or "Group"
                else:
                    _, title = display(chat_jid, row["chat_phone_jid"])
                chats[chat_jid] = ChatRecord(external_id=chat_jid, title=title, is_group=is_group)
            if row["ephemeral"] is not None:
                counts["skipped_ephemeral"] += 1
                continue
            if mtype == _TYPE_REVOKED or mtype in _TYPES_VIEW_ONCE:
                counts["skipped_deleted"] += 1
                continue
            if mtype == _TYPE_SYSTEM:
                counts["skipped_system"] += 1
                continue
            text = (row["text_data"] or "").strip()
            label = _TYPE_LABELS.get(int(mtype))
            if label:
                body = f"[{label}] {text}".strip()
                kind = "media"
            elif text:
                body, kind = text, "text"
            else:
                continue  # calls, polls, reactions without text — nothing to search
            from_me = bool(row["from_me"])
            if from_me:
                sender_id, sender_name = "me", "Me"
            elif is_group:
                sender_id, sender_name = display(row["sender_jid"], row["sender_phone_jid"])
            else:
                sender_id, sender_name = display(chat_jid, row["chat_phone_jid"])
            messages.append(MessageRecord(
                external_id=f"{chat_jid}|{int(from_me)}|{row['key_id']}",
                chat_external_id=chat_jid,
                sent_at=int(row["timestamp"] or 0),
                body=body,
                sender_id=sender_id,
                sender_name=sender_name,
                is_from_me=from_me,
                kind=kind,
            ))
        return list(chats.values()), messages, counts
    finally:
        conn.close()
