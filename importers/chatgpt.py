"""ChatGPT JSON export importer (SPEC §4).

Supported input
---------------
A directory containing ``conversations.json`` (the file ChatGPT's "Export
data" zip ships) or the ``conversations.json`` file itself. Each conversation
object is the standard ChatGPT export shape::

    {
      "id": "...", "title": "...",
      "create_time": 1735689600.123, "update_time": 1735689660.0,
      "is_archived": false,
      "mapping": {"<node>": {"id": "<node>", "parent": "...",
                             "message": {"author": {"role": "user"},
                                         "create_time": 1735689600.1,
                                         "content": {"content_type": "text",
                                                     "parts": ["..."]}}}},
      "current_node": "<node>"
    }

Parsing rules (deterministic):

- transcript = messages along the **current branch** (``current_node`` back
  to the root via ``parent``), root-first. If the branch is missing or
  cyclic, fall back to every message node sorted by
  ``(create_time, node id)`` so the output never depends on dict order.
- ``system`` / ``tool`` / ``function`` messages are dropped: they are
  platform scaffolding, not user memory.
- message text is read from ``content.parts``; string parts are kept,
  dict parts keep ``text`` and image pointers become ``[image:<pointer>]``.
- one record per non-empty conversation, ``kind="conversation"``,
  ``lifecycle="archived"`` when the export says archived.
- no consent field exists in this export -> ``consent.exportable = false``
  (SPEC §4); ``provenance.sensitivity = "sensitive"`` (protective default in
  the {public, internal, sensitive, secret} vocabulary).
"""

import json
from pathlib import Path

from ._common import (
    SENSITIVITY_IMPORT_DEFAULT,
    ImportFormatError,
    build_record,
    content_id,
    make_bundle,
    apply_import,
    now_utc,
    read_json,
    require_tombstones,
    rfc3339,
    validate_record,
)

EXPORT_FILENAME = "conversations.json"
SOURCE = "chatgpt-export"
IMPORTER = "chatgpt"
_SKIP_ROLES = {"system", "tool", "function"}


def find_conversations(path):
    """Resolve an export directory/file to the conversations.json path."""
    path = Path(path)
    if path.is_dir():
        candidate = path / EXPORT_FILENAME
        if not candidate.exists():
            raise ImportFormatError(
                f"{path} does not look like a ChatGPT export "
                f"(missing {EXPORT_FILENAME})"
            )
        return candidate
    if not path.exists():
        raise ImportFormatError(f"missing ChatGPT export: {path}")
    return path


def load_conversations(path):
    """Load and type-check the conversations array."""
    data = read_json(find_conversations(path))
    if not isinstance(data, list):
        raise ImportFormatError(
            f"{EXPORT_FILENAME} must contain a JSON array, got {type(data).__name__}"
        )
    for index, conversation in enumerate(data):
        if not isinstance(conversation, dict):
            raise ImportFormatError(
                f"{EXPORT_FILENAME}[{index}] must be an object, "
                f"got {type(conversation).__name__}"
            )
    return data


def _epoch(value):
    if isinstance(value, bool) or value is None:
        return float("-inf")
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(value)
    except (TypeError, ValueError):
        return float("-inf")


def _branch_nodes(conversation):
    """Nodes of the current branch, root-first, or a deterministic fallback."""
    mapping = conversation.get("mapping")
    if not isinstance(mapping, dict):
        return []
    current = conversation.get("current_node")
    chain = []
    seen = set()
    node_id = current
    while isinstance(node_id, str) and node_id in mapping and node_id not in seen:
        seen.add(node_id)
        node = mapping[node_id]
        if not isinstance(node, dict):
            break
        chain.append(node)
        parent = node.get("parent")
        node_id = parent if isinstance(parent, str) else None
    if chain:
        return list(reversed(chain))
    nodes = [
        node
        for node in mapping.values()
        if isinstance(node, dict) and isinstance(node.get("message"), dict)
    ]
    nodes.sort(key=lambda n: (_epoch(n["message"].get("create_time")), str(n.get("id", ""))))
    return nodes


def _part_text(part):
    if isinstance(part, str):
        return part
    if isinstance(part, dict):
        if isinstance(part.get("text"), str):
            return part["text"]
        pointer = part.get("asset_pointer")
        if isinstance(pointer, str):
            return f"[image:{pointer}]"
    return ""


def message_text(message):
    """Extract plain text from a ChatGPT message object."""
    content = message.get("content")
    if not isinstance(content, dict):
        return ""
    parts = content.get("parts")
    if not isinstance(parts, list):
        text = content.get("text")
        return text if isinstance(text, str) else ""
    chunks = [_part_text(part) for part in parts]
    return "\n".join(chunk for chunk in chunks if chunk)


def render_transcript(conversation):
    """Deterministic ``role: text`` transcript of the current branch."""
    lines = []
    for node in _branch_nodes(conversation):
        message = node.get("message")
        if not isinstance(message, dict):
            continue
        author = message.get("author")
        role = author.get("role") if isinstance(author, dict) else None
        role = role if isinstance(role, str) and role else "unknown"
        if role in _SKIP_ROLES:
            continue
        text = message_text(message).strip()
        if not text:
            continue
        lines.append(f"{role}: {text}")
    return "\n\n".join(lines)


def conversation_id(conversation):
    conv_id = conversation.get("id") or conversation.get("conversation_id")
    if isinstance(conv_id, str) and conv_id:
        return conv_id
    # Last-resort deterministic id for malformed exports missing an id.
    return content_id("conv", json.dumps(conversation, sort_keys=True, default=str))


def conversation_to_record(conversation, *, owner, imported_at, default_created):
    """Convert one ChatGPT conversation to an MBCP record (or None if empty)."""
    body = render_transcript(conversation)
    if not body:
        return None
    created = rfc3339(conversation.get("create_time"), default=default_created)
    updated = rfc3339(conversation.get("update_time"))
    extra = {"export_format": "chatgpt-export-v1"}
    title = conversation.get("title")
    if isinstance(title, str):
        extra["title"] = title
    record = build_record(
        f"chatgpt:{conversation_id(conversation)}",
        "conversation",
        body,
        owner,
        created=created,
        imported_at=imported_at,
        source=SOURCE,
        importer=IMPORTER,
        sensitivity=SENSITIVITY_IMPORT_DEFAULT,
        kind_priority="opportunistic",
        max_chars=8000,
        on_budget_exceed="truncate_last",
        lifecycle="archived" if conversation.get("is_archived") is True else "active",
        extra_provenance=extra,
    )
    if updated:
        record["time"]["updated"] = updated
        return validate_record(record)
    return record


def parse_export(path, *, owner, imported_at=None, default_created=None):
    """Parse a ChatGPT export into a deterministic record list."""
    imported_at = imported_at or now_utc()
    default_created = default_created or imported_at
    records = []
    for conversation in load_conversations(path):
        record = conversation_to_record(
            conversation,
            owner=owner,
            imported_at=imported_at,
            default_created=default_created,
        )
        if record is not None:
            records.append(record)
    return records


def build_import_bundle(
    path,
    *,
    bundle_id="chatgpt-export",
    owner,
    imported_at=None,
    default_created=None,
    tombstones=None,
):
    """Parse an export into a validated MBCP manifest.

    ``tombstones`` is REQUIRED (pass ``service.all_tombstones()``); omitting
    it raises TypeError so a re-import can never resurrect deleted records
    by accident (SPEC §1.2/§4).
    """
    records = parse_export(
        path,
        owner=owner,
        imported_at=imported_at,
        default_created=default_created,
    )
    return make_bundle(records, bundle_id, tombstones=require_tombstones(tombstones))


def import_export(store, path, **kwargs):
    """Tombstone-first import of a ChatGPT export into ``store``."""
    return apply_import(store, build_import_bundle(path, **kwargs))


__all__ = [
    "EXPORT_FILENAME",
    "ImportFormatError",
    "build_import_bundle",
    "conversation_id",
    "conversation_to_record",
    "find_conversations",
    "import_export",
    "load_conversations",
    "message_text",
    "parse_export",
    "render_transcript",
]
