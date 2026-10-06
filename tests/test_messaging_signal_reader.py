"""Signal Desktop reader: SQLCipher read and sync semantics (skipped without sqlcipher3)."""
import json
import os
import time

import pytest

sqlcipher3 = pytest.importorskip("sqlcipher3")

from src.messaging import store, sync  # noqa: E402
from src.secret_storage import encrypt  # noqa: E402
from tests.helpers.messaging_fixtures import (  # noqa: E402
    SIGNAL_MESSAGES,
    build_signal_dir,
    use_temp_messaging,
)

OWNER = "alice"


@pytest.fixture
def signal_dir(monkeypatch, tmp_path):
    use_temp_messaging(monkeypatch, tmp_path)
    return tmp_path / "signal"  # sync.SIGNAL_HOST_DIR in the temp layout


def _source(secret=""):
    return store.create_source(OWNER, kind="signal_desktop", name="Signal",
                               secret_enc=encrypt(secret) if secret else "")


@pytest.mark.parametrize("key_mode", ["plain", "v10", "v11"])
def test_sync_reads_signal_and_skips_disappearing_deleted_and_notices(signal_dir, key_mode, tmp_path):
    build_signal_dir(signal_dir, key_mode=key_mode)
    src = _source("hunter2" if key_mode == "v11" else "")

    result = sync.sync_source(OWNER, src["id"])

    assert result["status"] == "synced", result
    assert result["added"] == 4
    assert result["skipped_ephemeral"] == 1
    assert result["skipped_deleted"] == 2  # delete-for-everyone + view-once
    bodies = {m["body"] for m in store.search_messages(OWNER, "", since="2000-01-01", limit=50)}
    assert bodies == {"Lunch on Thursday?", "Yes, the usual place", "[image]", "Courgettes are ready to pick"}

    chats = {c["title"]: c for c in store.list_chats(OWNER, include_excluded=True)}
    assert set(chats) == {"Alice Smith", "Bob Profile", "Allotment"}  # never-used contacts hidden
    assert chats["Allotment"]["is_group"] == 1
    hit = store.search_messages(OWNER, "courgettes")[0]
    assert hit["sender_name"] == "Bob Profile" and hit["source_kind"] == "signal_desktop"
    assert store.search_messages(OWNER, "", sender="Me", since="2000-01-01")[0]["body"] == "Yes, the usual place"
    assert not any((tmp_path / "tmp").iterdir()), "decrypted snapshot must be removed"


def test_signal_sync_skips_unchanged_db_and_propagates_deletes(signal_dir):
    build_signal_dir(signal_dir)
    src = _source()
    sync.sync_source(OWNER, src["id"])
    assert sync.sync_source(OWNER, src["id"])["status"] == "unchanged"

    remaining = [m for m in SIGNAL_MESSAGES if m[0] != "m1"]
    build_signal_dir(signal_dir, messages=remaining)
    future = time.time() + 60
    os.utime(signal_dir / "sql" / "db.sqlite", (future, future))

    result = sync.sync_source(OWNER, src["id"])
    assert result["status"] == "synced" and result["removed"] == 1
    assert store.search_messages(OWNER, "lunch") == []


def test_signal_test_reports_counts_only(signal_dir):
    build_signal_dir(signal_dir)
    src = _source()
    result = sync.test_source(OWNER, src["id"])
    assert result["ok"] and result["messages"] == 4 and result["schema_version"] == 1360
    assert "Lunch" not in json.dumps(result)


def test_missing_mount_and_wrong_key_are_actionable(signal_dir):
    src = _source()
    assert "docker/signal-desktop.yml" in sync.sync_source(OWNER, src["id"])["error"]

    build_signal_dir(signal_dir)
    (signal_dir / "config.json").write_text(json.dumps({"key": "00" * 32}))
    assert "wrong key" in sync.sync_source(OWNER, src["id"], force=True)["error"]
