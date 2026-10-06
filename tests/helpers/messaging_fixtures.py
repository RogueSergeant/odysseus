"""Synthetic source databases for the messaging tests.

``build_msgstore`` writes a minimal Android WhatsApp ``msgstore.db`` using the
modern (2021+) table layout the reader targets: ``jid``, ``chat``,
``message``, plus the optional ``jid_map`` (LID -> phone) and
``message_ephemeral`` tables. Only the columns the reader touches exist.
"""
import sqlite3

ME_KEY = "fixture"

# (row id, raw_string, user, server)
JIDS = [
    (1, "447700900001@s.whatsapp.net", "447700900001", "s.whatsapp.net"),  # Alice
    (2, "447700900002@s.whatsapp.net", "447700900002", "s.whatsapp.net"),  # Bob
    (3, "120363000000000001@g.us", "120363000000000001", "g.us"),          # Book club
    (4, "status@broadcast", "status", "broadcast"),
    (5, "99887766554433@lid", "99887766554433", "lid"),                    # Bob's LID
]

# (chat id, jid_row_id, subject)
CHATS = [
    (10, 1, None),
    (11, 3, "Book club"),
    (12, 4, None),
]

# (id, chat_row_id, from_me, key_id, sender_jid_row_id, timestamp_ms, message_type, text)
BASE_MESSAGES = [
    (100, 10, 0, "A1", 0, 1_760_000_000_000, 0, "Are we still on for the dentist on Friday?"),
    (101, 10, 1, "A2", 0, 1_760_000_060_000, 0, "Yes, 3pm. I'll drive."),
    (102, 10, 0, "A3", 0, 1_760_000_120_000, 1, "Parking map"),
    (103, 10, 0, "A4", 0, 1_760_000_180_000, 15, None),           # deleted for everyone
    (104, 10, 0, "A5", 0, 1_760_000_240_000, 0, "This one disappears"),  # ephemeral
    (105, 11, 0, "B1", 5, 1_760_100_000_000, 0, "Next book: Middlemarch"),  # sender via LID
    (106, 11, 0, "B2", 0, 1_760_100_060_000, 7, None),            # system notice
    (107, 12, 0, "S1", 1, 1_760_100_120_000, 0, "status update"),  # status broadcast
    (108, 11, 1, "B3", 0, 1_760_100_180_000, 0, "Lovely, I have a copy"),
]


def build_msgstore(path, messages=None, ephemeral_ids=(104,), with_jid_map=True):
    messages = BASE_MESSAGES if messages is None else messages
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE jid (_id INTEGER PRIMARY KEY, user TEXT, server TEXT, raw_string TEXT);
        CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER, subject TEXT);
        CREATE TABLE message (
            _id INTEGER PRIMARY KEY, chat_row_id INTEGER, from_me INTEGER, key_id TEXT,
            sender_jid_row_id INTEGER, timestamp INTEGER, message_type INTEGER, text_data TEXT
        );
        CREATE TABLE message_ephemeral (message_row_id INTEGER PRIMARY KEY, duration INTEGER);
        """
    )
    if with_jid_map:
        conn.execute("CREATE TABLE jid_map (lid_row_id INTEGER PRIMARY KEY, jid_row_id INTEGER)")
        conn.execute("INSERT INTO jid_map VALUES (5, 2)")
    conn.executemany("INSERT INTO jid (_id, raw_string, user, server) VALUES (?, ?, ?, ?)", JIDS)
    conn.executemany("INSERT INTO chat VALUES (?, ?, ?)", CHATS)
    conn.executemany("INSERT INTO message VALUES (?, ?, ?, ?, ?, ?, ?, ?)", messages)
    conn.executemany("INSERT INTO message_ephemeral VALUES (?, 86400)", [(i,) for i in ephemeral_ids])
    conn.commit()
    conn.close()
    return path


CONTACTS = [
    {"name": "Alice Smith", "phones": ["07700 900001"], "emails": []},
    {"name": "Bob Jones", "phones": ["+44 7700 900002"], "emails": []},
]


FIXTURE_DIR = __import__("pathlib").Path(__file__).resolve().parent.parent / "fixtures" / "messaging"
# Root key the committed crypt15 fixture was encrypted with (wa-crypt-tools).
FIXTURE_KEY_HEX = "00112233445566778899aabbccddeeff" * 2


def use_temp_messaging(monkeypatch, tmp_path):
    """Point the messaging store, inbox and temp dirs at ``tmp_path``.

    Returns the inbox directory WhatsApp backups should be copied into.
    """
    from src.messaging import store, sync

    inbox = tmp_path / "inbox"
    monkeypatch.setattr(store, "DB_PATH", str(tmp_path / "messaging.db"))
    monkeypatch.setattr(sync, "MESSAGING_INBOX_DIR", str(inbox))
    monkeypatch.setattr(sync, "WHATSAPP_INBOX", str(inbox / "whatsapp"))
    monkeypatch.setattr(sync, "MESSAGING_TMP_DIR", str(tmp_path / "tmp"))
    monkeypatch.setattr(sync, "SIGNAL_HOST_DIR", str(tmp_path / "signal"))
    monkeypatch.delenv("ODYSSEUS_MESSAGING_PATHS", raising=False)
    # Contacts come from the fixture list, never the real address book.
    real_builder = sync.build_name_resolver
    monkeypatch.setattr(
        sync, "build_name_resolver",
        lambda default_cc="44", contacts=None: real_builder(default_cc, CONTACTS if contacts is None else contacts),
    )
    return inbox


def encrypt_msgstore_like_fixture(plain_db_path, out_path, key_hex=FIXTURE_KEY_HEX):
    """Encrypt a msgstore.db the way WhatsApp does (crypt15, single file).

    Used to build backups with varying content; the format itself is pinned
    independently by the committed wa-crypt-tools fixture.
    """
    import hashlib
    import hmac
    import os
    import zlib
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    root = bytes.fromhex(key_hex)
    private = hmac.new(b"\x00" * 32, root, hashlib.sha256).digest()
    key = hmac.new(private, b"backup encryption\x01", hashlib.sha256).digest()
    iv = os.urandom(16)
    c15_iv = b"\x0a" + bytes([len(iv)]) + iv            # C15_IV { 1: iv }
    prefix = b"\x08\x01" + b"\x1a" + bytes([len(c15_iv)]) + c15_iv  # key_type=1, field 3
    sealed = AESGCM(key).encrypt(iv, zlib.compress(open(plain_db_path, "rb").read()), None)
    body = bytes([len(prefix)]) + b"\x01" + prefix + sealed
    with open(out_path, "wb") as fh:
        fh.write(body + hashlib.md5(body).digest())
    return out_path


# ── Signal Desktop ────────────────────────────────────────────────────────

SIGNAL_DB_KEY = "7f" * 32
SIGNAL_CONVERSATIONS = [
    # id, type, name, profileFullName, e164, serviceId
    ("c-alice", "private", "Alice Smith", None, "+447700900001", "svc-alice"),
    ("c-bob", "private", None, "Bob Profile", "+447700900002", "svc-bob"),
    ("c-group", "group", "Allotment", None, None, None),
    ("c-stranger", "private", None, "Someone Seen Once", "+447700900009", "svc-stranger"),  # no messages
]
# id, conversationId, type, body, sent_at, json, sourceServiceId, expireTimer, isViewOnce, isErased, hasAttachments
SIGNAL_MESSAGES = [
    ("m1", "c-alice", "incoming", "Lunch on Thursday?", 1_760_000_000_000, "{}", "svc-alice", None, 0, 0, 0),
    ("m2", "c-alice", "outgoing", "Yes, the usual place", 1_760_000_060_000, "{}", None, None, 0, 0, 0),
    ("m3", "c-alice", "incoming", "secret that vanishes", 1_760_000_120_000, "{}", "svc-alice", 3600, 0, 0, 0),
    ("m4", "c-bob", "incoming", "oops", 1_760_000_180_000, '{"deletedForEveryone": true}', "svc-bob", None, 0, 0, 0),
    ("m5", "c-bob", "incoming", "", 1_760_000_240_000,
     '{"attachments": [{"contentType": "image/jpeg"}]}', "svc-bob", None, 0, 0, 1),
    ("m6", "c-group", "incoming", "Courgettes are ready to pick", 1_760_100_000_000, "{}", "svc-bob", None, 0, 0, 0),
    ("m7", "c-group", "group-v2-change", None, 1_760_100_060_000, "{}", None, None, 0, 0, 0),
    ("m8", "c-bob", "incoming", "view once pic", 1_760_100_120_000, "{}", "svc-bob", None, 1, 0, 0),
]


def oscrypt_encrypt(password, plaintext, prefix):
    """Chromium/Electron Linux safeStorage: PBKDF2-SHA1(saltysalt, 1) + AES-128-CBC."""
    from cryptography.hazmat.primitives import hashes, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    key = PBKDF2HMAC(algorithm=hashes.SHA1(), length=16, salt=b"saltysalt", iterations=1).derive(password.encode())
    padder = padding.PKCS7(128).padder()
    data = padder.update(plaintext.encode()) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(b" " * 16)).encryptor()
    return (prefix + enc.update(data) + enc.finalize()).hex()


def build_signal_dir(root, *, key_mode="plain", keyring_password="hunter2", messages=None):
    """Write <root>/config.json + <root>/sql/db.sqlite like Signal Desktop does."""
    import json
    import sqlcipher3

    root.mkdir(parents=True, exist_ok=True)
    (root / "sql").mkdir(exist_ok=True)
    if key_mode == "plain":
        config = {"key": SIGNAL_DB_KEY}
    elif key_mode == "v10":
        config = {"encryptedKey": oscrypt_encrypt("peanuts", SIGNAL_DB_KEY, b"v10"),
                  "safeStorageBackend": "basic_text"}
    elif key_mode == "v11":
        config = {"encryptedKey": oscrypt_encrypt(keyring_password, SIGNAL_DB_KEY, b"v11"),
                  "safeStorageBackend": "kwallet6"}
    else:
        raise ValueError(key_mode)
    (root / "config.json").write_text(json.dumps(config))

    db = root / "sql" / "db.sqlite"
    if db.exists():
        db.unlink()
    conn = sqlcipher3.connect(str(db))
    conn.execute(f"PRAGMA key = \"x'{SIGNAL_DB_KEY}'\"")
    conn.execute("PRAGMA cipher_page_size = 4096")
    conn.execute("PRAGMA cipher_hmac_algorithm = HMAC_SHA512")
    conn.execute("PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512")
    conn.executescript(
        """
        CREATE TABLE conversations (id TEXT PRIMARY KEY, json TEXT, type TEXT, name TEXT,
            profileName TEXT, profileFullName TEXT, e164 TEXT, serviceId TEXT);
        CREATE TABLE messages (id TEXT PRIMARY KEY, json TEXT, conversationId TEXT, type TEXT,
            body TEXT, sent_at INTEGER, sourceServiceId TEXT, expireTimer INTEGER,
            isViewOnce INTEGER, isErased INTEGER, hasAttachments INTEGER, isStory INTEGER DEFAULT 0,
            storyId TEXT);
        PRAGMA user_version = 1360;
        """
    )
    conn.executemany(
        "INSERT INTO conversations (id, type, name, profileFullName, e164, serviceId) VALUES (?, ?, ?, ?, ?, ?)",
        SIGNAL_CONVERSATIONS,
    )
    conn.executemany(
        "INSERT INTO messages (id, conversationId, type, body, sent_at, json, sourceServiceId,"
        " expireTimer, isViewOnce, isErased, hasAttachments) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        SIGNAL_MESSAGES if messages is None else messages,
    )
    conn.commit()
    conn.close()
    return root
