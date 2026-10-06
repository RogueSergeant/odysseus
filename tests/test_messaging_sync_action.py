"""The built-in sync_messaging task stays silent unless something changed."""
import asyncio
import shutil

import pytest

from src.builtin_actions import TaskNoop, action_sync_messaging
from src.messaging import store
from src.secret_storage import encrypt
from tests.helpers.messaging_fixtures import FIXTURE_DIR, FIXTURE_KEY_HEX, use_temp_messaging


@pytest.fixture
def fired(monkeypatch):
    import src.event_bus as event_bus

    events = []
    monkeypatch.setattr(event_bus, "fire_event", lambda name, owner=None: events.append((name, owner)))
    return events


@pytest.fixture
def inbox(monkeypatch, tmp_path, fired):
    return use_temp_messaging(monkeypatch, tmp_path)


def _run(owner):
    return asyncio.run(action_sync_messaging(owner))


def test_no_sources_is_a_silent_noop(inbox):
    with pytest.raises(TaskNoop):
        _run("alice")


def test_new_messages_report_and_fire_event_then_go_quiet(inbox, fired):
    (inbox / "whatsapp").mkdir(parents=True)
    shutil.copy(FIXTURE_DIR / "msgstore.db.crypt15", inbox / "whatsapp" / "msgstore.db.crypt15")
    store.create_source("alice", kind="whatsapp_backup", name="WhatsApp", secret_enc=encrypt(FIXTURE_KEY_HEX))

    summary, ok = _run("alice")
    assert ok and "5 new" in summary
    assert fired == [("messages_synced", "alice")]

    with pytest.raises(TaskNoop):  # same backup again: nothing to report
        _run("alice")


def test_repeated_identical_error_is_silent_after_first_report(inbox):
    store.create_source("alice", kind="whatsapp_backup", name="WhatsApp", secret_enc=encrypt(FIXTURE_KEY_HEX))

    summary, ok = _run("alice")  # no backup delivered yet
    assert not ok and "Pair Syncthing" in summary
    with pytest.raises(TaskNoop):
        _run("alice")


def test_sync_messaging_is_a_registered_silent_housekeeping_task():
    from src.builtin_actions import BUILTIN_ACTION_INFO, BUILTIN_ACTIONS
    from src.task_scheduler import HOUSEKEEPING_DEFAULTS, TaskScheduler

    assert BUILTIN_ACTIONS["sync_messaging"] is action_sync_messaging
    assert "sync_messaging" in BUILTIN_ACTION_INFO
    assert HOUSEKEEPING_DEFAULTS["sync_messaging"]["cron_expression"] == "*/15 * * * *"
    assert "sync_messaging" in TaskScheduler._SILENT_ACTIONS
