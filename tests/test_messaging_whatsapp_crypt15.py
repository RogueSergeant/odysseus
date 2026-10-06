"""crypt15 decryption, pinned to a fixture made by an independent implementation.

tests/fixtures/messaging/msgstore.db.crypt15 was produced offline by
wa-crypt-tools (ElDavoo) from tests.helpers.messaging_fixtures.build_msgstore,
so a passing known-answer test means our header parsing, key derivation,
AES-GCM framing and zlib handling agree with an implementation we did not write.
"""
import os
import sqlite3

import pytest

from src.messaging.whatsapp_backup import (
    BackupError,
    decrypt_backup,
    derive_backup_encryption_key,
    parse_backup_key,
    parse_header,
)
from tests.helpers.messaging_fixtures import FIXTURE_DIR, FIXTURE_KEY_HEX

FIXTURE = FIXTURE_DIR / "msgstore.db.crypt15"


def test_known_answer_decrypts_reference_fixture(tmp_path):
    out = tmp_path / "msgstore.db"
    header = decrypt_backup(str(FIXTURE), parse_backup_key(FIXTURE_KEY_HEX), str(out))

    assert header.iv == bytes(range(16))
    assert header.app_version == "2.25.10.73"
    conn = sqlite3.connect(out)
    try:
        texts = [r[0] for r in conn.execute("SELECT text_data FROM message WHERE _id = 100")]
    finally:
        conn.close()
    assert texts == ["Are we still on for the dentist on Friday?"]
    assert oct(os.stat(out).st_mode & 0o777) == "0o600"


def test_wrong_key_fails_cleanly_and_leaves_no_plaintext(tmp_path):
    out = tmp_path / "msgstore.db"
    with pytest.raises(BackupError):
        decrypt_backup(str(FIXTURE), parse_backup_key("ab" * 32), str(out))
    assert not out.exists()


def test_truncated_backup_is_rejected(tmp_path):
    data = FIXTURE.read_bytes()
    truncated = tmp_path / "msgstore.db.crypt15"
    truncated.write_bytes(data[: len(data) // 2])
    out = tmp_path / "msgstore.db"
    with pytest.raises(BackupError):
        decrypt_backup(str(truncated), parse_backup_key(FIXTURE_KEY_HEX), str(out))
    assert not out.exists()


def test_multi_file_layout_without_md5_trailer_still_decrypts(tmp_path):
    # Multi-file backups omit the trailing MD5; the last 16 bytes are the tag.
    data = FIXTURE.read_bytes()[:-16]
    path = tmp_path / "msgstore.db.crypt15"
    path.write_bytes(data)
    out = tmp_path / "msgstore.db"
    decrypt_backup(str(path), parse_backup_key(FIXTURE_KEY_HEX), str(out))
    assert out.read_bytes().startswith(b"SQLite format 3\x00")


def test_crypt14_header_explains_how_to_enable_the_64_digit_key():
    # BackupPrefix with only field 2 (c14_cipher) set.
    c14 = b"\x12\x02\x0a\x00"
    prefix = bytes([len(c14)]) + c14
    with pytest.raises(BackupError, match="64-digit"):
        parse_header(prefix + b"\x00" * 64)


@pytest.mark.parametrize("text", [
    FIXTURE_KEY_HEX,
    FIXTURE_KEY_HEX.upper(),
    " ".join(FIXTURE_KEY_HEX[i:i + 4] for i in range(0, 64, 4)),
    FIXTURE_KEY_HEX[:32] + "\n" + FIXTURE_KEY_HEX[32:],
])
def test_backup_key_accepts_whatsapp_display_formats(text):
    assert parse_backup_key(text) == bytes.fromhex(FIXTURE_KEY_HEX)


@pytest.mark.parametrize("text", ["", "1234", FIXTURE_KEY_HEX[:-1], FIXTURE_KEY_HEX[:-1] + "g"])
def test_backup_key_rejects_malformed_input(text):
    with pytest.raises(BackupError):
        parse_backup_key(text)


def test_key_derivation_matches_whatsapp_hmac_loop():
    import hashlib
    import hmac

    root = bytes.fromhex(FIXTURE_KEY_HEX)
    expected = hmac.new(
        hmac.new(b"\x00" * 32, root, hashlib.sha256).digest(),
        b"backup encryption\x01",
        hashlib.sha256,
    ).digest()
    assert derive_backup_encryption_key(root) == expected
