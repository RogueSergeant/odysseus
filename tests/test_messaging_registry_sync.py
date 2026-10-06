"""MESSENGER_TOOLS is the single source of truth for the messaging tools.

Mirrors tests/test_email_registry_sync.py: every surface that has to know
about the read-only Signal/WhatsApp tools must agree, so a tool can't become
reachable without also being admin-only, plan-mode classified and treated as
untrusted external content.
"""
import re

import src.agent_tools  # noqa: F401 — resolve the circular-import cluster first
from src.tool_security import (
    MESSENGER_TOOLS,
    NON_ADMIN_BLOCKED_TOOLS,
    PLAN_MODE_READONLY_TOOLS,
    plan_mode_disabled_tools,
)

EXPECTED = {"list_messenger_chats", "read_messenger_chat", "search_messenger_messages"}


def test_messenger_tool_set_is_exactly_the_read_only_trio():
    # No send/reply tool may join this set without revisiting the threat model.
    assert set(MESSENGER_TOOLS) == EXPECTED


def test_fence_tags_cover_messenger_tools():
    from src.agent_tools import TOOL_TAGS

    assert MESSENGER_TOOLS <= set(TOOL_TAGS)


def test_messenger_tools_are_admin_only():
    assert MESSENGER_TOOLS <= NON_ADMIN_BLOCKED_TOOLS


def test_messenger_tools_are_plan_mode_read_only():
    denied = plan_mode_disabled_tools()
    for tool in MESSENGER_TOOLS:
        assert tool in PLAN_MODE_READONLY_TOOLS
        assert tool not in denied


def test_messenger_tools_are_private_untrusted_reads():
    from src.tool_capabilities import ResultIntegrity, ToolEffect, capabilities_for_action

    for tool in MESSENGER_TOOLS:
        caps = capabilities_for_action(tool, "{}")
        assert caps.known
        assert caps.effects == frozenset({ToolEffect.READ_PRIVATE})
        assert caps.result_integrity is ResultIntegrity.EXTERNAL_UNTRUSTED


def test_messenger_tools_have_schemas_descriptions_and_prompt_sections():
    from src.agent_loop import TOOL_SECTIONS, _DOMAIN_TOOL_MAP
    from src.tool_index import ASSISTANT_ALWAYS_AVAILABLE, BUILTIN_TOOL_DESCRIPTIONS
    from src.tool_schemas import FUNCTION_TOOL_SCHEMAS

    schema_names = {s["function"]["name"] for s in FUNCTION_TOOL_SCHEMAS}
    assert MESSENGER_TOOLS <= schema_names
    assert MESSENGER_TOOLS <= set(BUILTIN_TOOL_DESCRIPTIONS)
    assert MESSENGER_TOOLS <= set(TOOL_SECTIONS)
    assert _DOMAIN_TOOL_MAP["messaging"] == set(MESSENGER_TOOLS)
    assert MESSENGER_TOOLS <= ASSISTANT_ALWAYS_AVAILABLE


def test_native_function_calls_reach_the_messenger_dispatch():
    import json
    from src.tool_schemas import function_call_to_tool_block

    block = function_call_to_tool_block("search_messenger_messages", json.dumps({"query": "dentist"}))
    assert block.tool_type == "search_messenger_messages"
    assert json.loads(block.content) == {"query": "dentist"}


def test_whatsapp_and_signal_keywords_pull_in_messenger_tools():
    from src.tool_index import ToolIndex

    for query in ("what did mum say on whatsapp", "search my signal messages", "find that group chat"):
        hinted = set()
        for keywords, tools in ToolIndex._KEYWORD_HINTS.items():
            if any(re.search(rf"\b{re.escape(kw)}\b", query) for kw in keywords):
                hinted |= tools
        assert MESSENGER_TOOLS <= hinted, query

