"""Read-only personal messaging integration (Signal Desktop, WhatsApp backups).

Messages are copied from data the user already holds on their own machine
into a local, owner-scoped SQLite + FTS5 index (``store``), refreshed by an
incremental full-snapshot reconcile (``sync``). Agents read the index through
three read-only tools (``src/tools/messaging.py``). Nothing here connects to
Signal's or WhatsApp's servers, and nothing here can send a message.
"""

SOURCE_KINDS = ("whatsapp_backup", "signal_desktop")
