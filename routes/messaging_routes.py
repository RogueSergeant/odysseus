# routes/messaging_routes.py
"""Settings API for the read-only Signal / WhatsApp message index.

Admin-only (personal messages are privileged data, like email) and
owner-scoped. Secrets (the WhatsApp 64-digit backup key, a Signal keyring
password) are write-only: responses carry ``has_secret`` and never the value.
Test/sync responses report counts and dates, never message content.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel

from core.middleware import require_admin
from src.auth_helpers import get_current_user
from src.messaging import SOURCE_KINDS, store
from src.messaging import sync as msg_sync

logger = logging.getLogger(__name__)

_NAME_MAX = 80


class SourceCreate(BaseModel):
    kind: str
    name: str = ""
    path: Optional[str] = None
    country_code: Optional[str] = None
    secret: Optional[str] = None
    enabled: bool = True


class SourceUpdate(BaseModel):
    name: Optional[str] = None
    path: Optional[str] = None
    country_code: Optional[str] = None
    secret: Optional[str] = None
    enabled: Optional[bool] = None


class ChatUpdate(BaseModel):
    excluded: bool


def _owner(request: Request) -> str:
    require_admin(request)
    return store.owner_bucket(get_current_user(request))


def _public_source(source: Dict[str, Any]) -> Dict[str, Any]:
    out = {k: v for k, v in source.items() if k not in ("secret_enc", "owner")}
    out["has_secret"] = bool(source.get("secret_enc"))
    out["totals"] = store.source_totals(source["id"])
    return out


def _clean_config(kind: str, path: Optional[str], country_code: Optional[str],
                  base: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    config = dict(base or {})
    if path is not None:
        path = path.strip()
        if path:
            try:
                config["path"] = msg_sync.resolve_allowed_path(path)
            except msg_sync.SyncError as exc:
                raise HTTPException(400, str(exc)) from exc
        else:
            config.pop("path", None)
    if country_code is not None:
        cc = re.sub(r"\D", "", country_code)
        if country_code.strip() and not (1 <= len(cc) <= 3):
            raise HTTPException(400, "Country code must be 1-3 digits, e.g. 44")
        if cc:
            config["country_code"] = cc
        else:
            config.pop("country_code", None)
    return config


def _validate_secret(kind: str, secret: str) -> str:
    secret = (secret or "").strip()
    if kind == "whatsapp_backup" and secret:
        from src.messaging.whatsapp_backup import BackupError, parse_backup_key
        try:
            parse_backup_key(secret)
        except BackupError as exc:
            raise HTTPException(400, str(exc)) from exc
    return secret


def setup_messaging_routes() -> APIRouter:
    router = APIRouter(prefix="/api/messaging", tags=["messaging"])

    @router.get("/status")
    async def status(request: Request):
        owner = _owner(request)
        sources = await asyncio.to_thread(store.list_sources, owner)
        try:
            import sqlcipher3  # noqa: F401
            sqlcipher_ok = True
        except Exception:
            sqlcipher_ok = False
        return {
            "sources": [_public_source(s) for s in sources],
            "totals": store.owner_totals(owner),
            "whatsapp_inbox": msg_sync.WHATSAPP_INBOX,
            "signal_mount": msg_sync.SIGNAL_HOST_DIR,
            "signal_mount_present": os.path.isdir(msg_sync.SIGNAL_HOST_DIR),
            "sqlcipher_available": sqlcipher_ok,
            "kinds": list(SOURCE_KINDS),
        }

    @router.post("/sources")
    async def create_source(request: Request, body: SourceCreate):
        owner = _owner(request)
        if body.kind not in SOURCE_KINDS:
            raise HTTPException(400, f"kind must be one of {', '.join(SOURCE_KINDS)}")
        name = (body.name or "").strip()[:_NAME_MAX] or (
            "WhatsApp" if body.kind == "whatsapp_backup" else "Signal"
        )
        config = _clean_config(body.kind, body.path, body.country_code)
        secret = _validate_secret(body.kind, body.secret or "")
        if body.kind == "whatsapp_backup" and not secret:
            raise HTTPException(400, "The 64-digit backup key is required for a WhatsApp source")
        from src.secret_storage import encrypt
        source = await asyncio.to_thread(
            store.create_source, owner, kind=body.kind, name=name, config=config,
            secret_enc=encrypt(secret) if secret else "", enabled=body.enabled,
        )
        return {"source": _public_source(source)}

    @router.put("/sources/{source_id}")
    async def update_source(request: Request, source_id: str, body: SourceUpdate):
        owner = _owner(request)
        source = await asyncio.to_thread(store.get_source, owner, source_id)
        if not source:
            raise HTTPException(404, "Source not found")
        fields: Dict[str, Any] = {}
        if body.name is not None:
            name = body.name.strip()[:_NAME_MAX]
            if not name:
                raise HTTPException(400, "Name cannot be blank")
            fields["name"] = name
        if body.path is not None or body.country_code is not None:
            fields["config"] = _clean_config(source["kind"], body.path, body.country_code, source["config"])
            # A different file/folder must be re-read even if its mtime is older.
            fields["last_source_mtime"] = None
        if body.secret:  # blank keeps the stored secret (same rule as email passwords)
            from src.secret_storage import encrypt
            fields["secret_enc"] = encrypt(_validate_secret(source["kind"], body.secret))
            fields["last_source_mtime"] = None
        if body.enabled is not None:
            fields["enabled"] = body.enabled
        updated = await asyncio.to_thread(lambda: store.update_source(owner, source_id, **fields))
        return {"source": _public_source(updated)}

    @router.delete("/sources/{source_id}")
    async def delete_source(request: Request, source_id: str):
        owner = _owner(request)
        if not await asyncio.to_thread(store.delete_source, owner, source_id):
            raise HTTPException(404, "Source not found")
        return {"ok": True}

    @router.post("/sources/{source_id}/test")
    async def test_source(request: Request, source_id: str):
        owner = _owner(request)
        try:
            return await asyncio.to_thread(msg_sync.test_source, owner, source_id)
        except LookupError:
            raise HTTPException(404, "Source not found")

    @router.post("/sources/{source_id}/sync")
    async def sync_source(request: Request, source_id: str):
        owner = _owner(request)
        try:
            result = await asyncio.to_thread(msg_sync.sync_source, owner, source_id, force=True)
        except LookupError:
            raise HTTPException(404, "Source not found")
        if result.get("added"):
            try:
                from src.event_bus import fire_event
                fire_event("messages_synced", owner)
            except Exception:
                logger.debug("messages_synced event not fired", exc_info=True)
        result.pop("repeat", None)
        return result

    @router.get("/chats")
    async def list_chats(request: Request, source: Optional[str] = Query(None),
                         q: Optional[str] = Query(None), limit: int = Query(200)):
        owner = _owner(request)
        chats = await asyncio.to_thread(
            store.list_chats, owner, source=source, query=q, limit=limit, include_excluded=True,
        )
        return {"chats": chats}

    @router.put("/chats/{chat_id}")
    async def update_chat(request: Request, chat_id: int, body: ChatUpdate):
        owner = _owner(request)
        if not await asyncio.to_thread(store.set_chat_excluded, owner, chat_id, body.excluded):
            raise HTTPException(404, "Chat not found")
        return {"ok": True}

    return router
