"""WhatsApp backup -> index, end to end through src.messaging.sync."""
import os
import shutil
import time

import pytest

from src.messaging import store, sync
from src.secret_storage import encrypt
from tests.helpers.messaging_fixtures import (
    BASE_MESSAGES,
    FIXTURE_DIR,
    FIXTURE_KEY_HEX,
    build_msgstore,
    encrypt_msgstore_like_fixture,
    use_temp_messaging,
)

OWNER = "alice"


@pytest.fixture
def inbox(monkeypatch, tmp_path):
    return use_temp_messaging(monkeypatch, tmp_path)


def _source(owner=OWNER, key=FIXTURE_KEY_HEX):
    return store.create_source(owner, kind="whatsapp_backup", name="WhatsApp", secret_enc=encrypt(key))


def _deliver(inbox, tmp_path, messages=None, ephemeral_ids=(104,), bump=0):
    """Simulate Syncthing dropping a fresh nightly backup into the inbox."""
    dest_dir = inbox / "whatsapp" / "Databases"
    dest_dir.mkdir(parents=True, exist_ok=True)
    plain = tmp_path / f"plain-{time.monotonic_ns()}.db"
    build_msgstore(str(plain), messages=messages, ephemeral_ids=ephemeral_ids)
    dest = dest_dir / "msgstore.db.crypt15"
    encrypt_msgstore_like_fixture(str(plain), str(dest))
    plain.unlink()
    mtime = time.time() + bump
    os.utime(dest, (mtime, mtime))
    return dest


def _bodies(owner=OWNER):
    return sorted(r["body"] for r in store.search_messages(owner, "", since="2000-01-01", limit=200))


def test_sync_indexes_reference_backup_with_names_and_skips(inbox, tmp_path):
    dest_dir = inbox / "whatsapp"
    dest_dir.mkdir(parents=True)
    shutil.copy(FIXTURE_DIR / "msgstore.db.crypt15", dest_dir / "msgstore.db.crypt15")
    src = _source()

    result = sync.sync_source(OWNER, src["id"])

    assert result["status"] == "synced", result
    assert result["added"] == 5
    assert result["skipped_ephemeral"] == 1
    assert result["skipped_deleted"] == 1
    assert result["skipped_system"] == 1
    assert "This one disappears" not in _bodies()
    assert "status update" not in _bodies()  # status@broadcast never indexed

    chats = {c["title"]: c for c in store.list_chats(OWNER)}
    assert set(chats) == {"Alice Smith", "Book club"}
    assert chats["Book club"]["is_group"] == 1
    hits = store.search_messages(OWNER, "middlemarch")
    assert [h["sender_name"] for h in hits] == ["Bob Jones"]  # LID mapped to phone, then contact
    mine = store.search_messages(OWNER, "", sender="Me", since="2000-01-01")
    assert {m["is_from_me"] for m in mine} == {1}

    src = store.get_source(OWNER, src["id"])
    assert src["last_error"] is None
    assert src["stats"]["whatsapp_version"] == "2.25.10.73"
    assert not list((tmp_path / "tmp").glob("*")), "decrypted copy must be removed"


def test_unchanged_backup_is_not_reread(inbox, tmp_path):
    _deliver(inbox, tmp_path)
    src = _source()
    assert sync.sync_source(OWNER, src["id"])["status"] == "synced"
    assert sync.sync_source(OWNER, src["id"])["status"] == "unchanged"
    assert sync.sync_source(OWNER, src["id"], force=True)["status"] == "synced"


def test_new_backup_adds_edits_and_propagates_deletions(inbox, tmp_path):
    _deliver(inbox, tmp_path)
    src = _source()
    sync.sync_source(OWNER, src["id"])

    later = [m for m in BASE_MESSAGES if m[0] != 101]  # "Yes, 3pm" deleted on the phone
    later = [(m[0], m[1], m[2], m[3], m[4], m[5], m[6],
              "Next book: Middlemarch (edited)" if m[0] == 105 else m[7]) for m in later]
    later.append((109, 10, 0, "A6", 0, 1_760_200_000_000, 0, "See you at the surgery"))
    _deliver(inbox, tmp_path, messages=later, bump=60)

    result = sync.sync_source(OWNER, src["id"])

    assert result["added"] == 1 and result["removed"] == 1 and result["updated"] == 1
    bodies = _bodies()
    assert "Yes, 3pm. I'll drive." not in bodies
    assert "See you at the surgery" in bodies
    assert "Next book: Middlemarch (edited)" in bodies
    # FTS stays in step with updates and deletes.
    assert store.search_messages(OWNER, "drive") == []
    assert [h["body"] for h in store.search_messages(OWNER, "edited")] == ["Next book: Middlemarch (edited)"]


def test_message_that_becomes_disappearing_is_removed(inbox, tmp_path):
    _deliver(inbox, tmp_path, ephemeral_ids=())
    src = _source()
    sync.sync_source(OWNER, src["id"])
    assert "This one disappears" in _bodies()

    _deliver(inbox, tmp_path, ephemeral_ids=(104,), bump=60)
    sync.sync_source(OWNER, src["id"])
    assert "This one disappears" not in _bodies()


def test_excluded_chat_is_purged_and_stays_out(inbox, tmp_path):
    _deliver(inbox, tmp_path)
    src = _source()
    sync.sync_source(OWNER, src["id"])
    club = next(c for c in store.list_chats(OWNER) if c["title"] == "Book club")

    assert store.set_chat_excluded(OWNER, club["id"], True)
    assert store.search_messages(OWNER, "middlemarch") == []
    sync.sync_source(OWNER, src["id"], force=True)
    assert store.search_messages(OWNER, "middlemarch") == []
    assert all(c["title"] != "Book club" for c in store.list_chats(OWNER))

    assert store.set_chat_excluded(OWNER, club["id"], False)
    sync.sync_source(OWNER, src["id"], force=True)
    assert store.search_messages(OWNER, "middlemarch")


def test_wrong_key_is_reported_on_the_source(inbox, tmp_path):
    _deliver(inbox, tmp_path)
    src = _source(key="ab" * 32)

    first = sync.sync_source(OWNER, src["id"])
    second = sync.sync_source(OWNER, src["id"])

    assert first["status"] == "error" and "64-digit key" in first["error"]
    assert first["repeat"] is False and second["repeat"] is True
    assert store.get_source(OWNER, src["id"])["last_error"] == first["error"]
    assert store.list_chats(OWNER) == []


def test_missing_backup_and_crypt14_only_give_actionable_errors(inbox, tmp_path):
    src = _source()
    assert "Pair Syncthing" in sync.sync_source(OWNER, src["id"])["error"]

    (inbox / "whatsapp").mkdir(parents=True, exist_ok=True)
    (inbox / "whatsapp" / "msgstore.db.crypt14").write_bytes(b"x")
    assert "64-digit key" in sync.sync_source(OWNER, src["id"])["error"]


def test_source_path_outside_allowed_roots_is_refused(inbox, tmp_path):
    with pytest.raises(sync.SyncError):
        sync.resolve_allowed_path("/etc")
    with pytest.raises(sync.SyncError):
        sync.resolve_allowed_path(str(inbox / ".." / ".." / "elsewhere"))
    assert sync.resolve_allowed_path(str(inbox / "whatsapp")) == os.path.realpath(inbox / "whatsapp")


def test_extra_roots_come_from_env(monkeypatch, inbox, tmp_path):
    extra = tmp_path / "native-signal"
    extra.mkdir()
    monkeypatch.setenv("ODYSSEUS_MESSAGING_PATHS", str(extra))
    assert sync.resolve_allowed_path(str(extra)) == os.path.realpath(extra)


def test_test_source_reports_counts_not_content(inbox, tmp_path):
    _deliver(inbox, tmp_path)
    src = _source()
    result = sync.test_source(OWNER, src["id"])
    assert result["ok"] is True
    assert result["chats"] == 2 and result["messages"] == 5
    flat = repr(result)
    assert "dentist" not in flat and "Middlemarch" not in flat
    assert store.list_chats(OWNER) == []  # test never writes to the index


@pytest.mark.parametrize("raw,expected", [
    ("07700 900001", "447700900001"),
    ("+44 7700 900001", "447700900001"),
    ("0044 7700 900001", "447700900001"),
    ("447700900001", "447700900001"),
    ("(0)20 7946 0000", "442079460000"),
    ("", ""),
])
def test_phone_normalisation(raw, expected):
    assert sync.normalise_phone(raw, "44") == expected


def test_view_once_media_is_never_indexed(inbox, tmp_path):
    messages = list(BASE_MESSAGES) + [(110, 10, 0, "A7", 0, 1_760_300_000_000, 42, "one look only")]
    _deliver(inbox, tmp_path, messages=messages)
    src = _source()
    result = sync.sync_source(OWNER, src["id"])
    assert result["skipped_deleted"] == 2  # the revoked one plus the view-once one
    assert all("one look only" not in b for b in _bodies())
