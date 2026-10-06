"""Signal Desktop database-key recovery from config.json (no sqlcipher needed)."""
import pytest

from src.messaging import sync
from src.messaging.signal_desktop import resolve_db_key
from tests.helpers.messaging_fixtures import SIGNAL_DB_KEY, oscrypt_encrypt


def test_plain_key():
    assert resolve_db_key({"key": SIGNAL_DB_KEY}) == SIGNAL_DB_KEY


def test_v10_basic_text_key_needs_no_password():
    cfg = {"encryptedKey": oscrypt_encrypt("peanuts", SIGNAL_DB_KEY, b"v10")}
    assert resolve_db_key(cfg) == SIGNAL_DB_KEY


def test_v11_keyring_key_uses_pasted_password():
    cfg = {"encryptedKey": oscrypt_encrypt("hunter2", SIGNAL_DB_KEY, b"v11")}
    assert resolve_db_key(cfg, "hunter2") == SIGNAL_DB_KEY


def test_v11_keyring_key_with_empty_password_backend():
    # Electron falls back to an empty v11 password when no keyring answers.
    cfg = {"encryptedKey": oscrypt_encrypt("", SIGNAL_DB_KEY, b"v11")}
    assert resolve_db_key(cfg) == SIGNAL_DB_KEY


def test_v11_without_password_explains_the_host_command():
    cfg = {"encryptedKey": oscrypt_encrypt("hunter2", SIGNAL_DB_KEY, b"v11")}
    with pytest.raises(sync.SyncError, match="kwallet-query"):
        resolve_db_key(cfg)


def test_v11_wrong_password_is_reported():
    cfg = {"encryptedKey": oscrypt_encrypt("hunter2", SIGNAL_DB_KEY, b"v11")}
    with pytest.raises(sync.SyncError, match="did not unlock"):
        resolve_db_key(cfg, "wrong")


@pytest.mark.parametrize("cfg", [{}, {"encryptedKey": "zz"}, {"encryptedKey": "763130"},
                                 {"encryptedKey": b"DPAPIxxxx".hex()}])
def test_unusable_configs_raise_sync_errors(cfg):
    with pytest.raises(sync.SyncError):
        resolve_db_key(cfg)
