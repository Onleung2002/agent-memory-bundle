"""Hermes profile importer (SPEC §4).

Supported input
---------------
A Hermes Agent profile directory::

    profile.yaml            # optional metadata (name/description)
    memories/MEMORY.md      # entries separated by a line containing only "§"
    memories/USER.md        # same delimiter; user preferences
    sessions/*.json|*.jsonl # optional transcripts

Parsing rules (deterministic):

- ``memories/*.md`` is split on lines that are exactly ``§`` (the Hermes
  memory delimiter); each non-empty entry becomes one record. Files without
  a delimiter are treated as a single entry.
- entry ids are **content-addressed** (``sha256(profile, file, entry)``), so
  the same entry keeps the same id across re-imports even if the file is
  reordered — a tombstone issued for one import still targets the same id
  in the next one. Identical duplicate entries collapse to one record.
- ``USER.md`` -> ``kind="preference"``, ``priority="critical"``;
  other files -> ``kind="fact"`` (``note`` for non-MEMORY filenames),
  ``priority="standard"``.
- sessions become ``kind="conversation"`` records with their own
  timestamps when present; memory markdown has no timestamps, so entries
  use ``default_created`` (documented import time fallback).
- no consent field exists in a profile -> ``consent.exportable = false``
  (SPEC §4); ``provenance.sensitivity = "private"``.
"""

import json
import re
from pathlib import Path

from ._common import (
    SENSITIVITY_PRIVATE,
    ImportFormatError,
    apply_import,
    build_record,
    content_id,
    dedupe_sorted,
    make_bundle,
    now_utc,
    rfc3339,
)

SOURCE = "hermes-profile"
IMPORTER = "hermes"
MEMORY_DELIMITER_RE = re.compile(r"^\s*§\s*$")
_SKIP_ROLES = {"system", "tool"}


def split_memory_entries(text):
    """Split a Hermes memory markdown file into stripped, non-empty entries."""
    entries = []
    current = []
    for line in text.splitlines():
        if MEMORY_DELIMITER_RE.match(line):
            entry = "\n".join(current).strip()
            if entry:
                entries.append(entry)
            current = []
        else:
            current.append(line)
    entry = "\n".join(current).strip()
    if entry:
        entries.append(entry)
    return entries


def _read_profile_meta(root):
    """Best-effort flat ``key: value`` parse of profile.yaml (stdlib only)."""
    meta = {}
    path = root / "profile.yaml"
    if not path.exists():
        return meta
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return meta
    for line in text.splitlines():
        if not line or line[0].isspace() or ":" not in line:
            continue
        key, _, value = line.partition(":")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        if key.strip():
            meta[key.strip()] = value
    return meta


def _memory_records(root, profile_name, *, owner, imported_at, default_created):
    memories = root / "memories"
    if not memories.is_dir():
        return []
    records = []
    for path in sorted(memories.glob("*.md")):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as err:
            raise ImportFormatError(f"{path} is not UTF-8: {err}") from err
        rel = path.relative_to(root).as_posix()
        is_user = path.name.upper() == "USER.MD"
        kind = "preference" if is_user else ("fact" if path.name == "MEMORY.md" else "note")
        for entry in split_memory_entries(text):
            records.append(
                build_record(
                    content_id("hermes-mem", profile_name, rel, entry),
                    kind,
                    entry,
                    owner,
                    created=default_created,
                    imported_at=imported_at,
                    source=SOURCE,
                    importer=IMPORTER,
                    sensitivity=SENSITIVITY_PRIVATE,
                    kind_priority="critical" if is_user else "standard",
                    max_chars=4096,
                    on_budget_exceed="skip",
                    extra_provenance={"profile": profile_name, "file": rel},
                )
            )
    return records


def _read_session(path):
    """Return (messages, meta) for a Hermes session file."""
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as err:
        raise ImportFormatError(f"{path} is not UTF-8: {err}") from err
    if path.suffix == ".jsonl":
        messages = []
        for lineno, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                messages.append(json.loads(line))
            except json.JSONDecodeError as err:
                raise ImportFormatError(f"{path}:{lineno}: invalid JSON: {err}") from err
        return messages, {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError as err:
        raise ImportFormatError(f"invalid JSON in {path}: {err}") from err
    if isinstance(data, dict):
        messages = data.get("messages")
        if messages is None and "role" in data:
            messages = [data]
        if messages is not None and not isinstance(messages, list):
            raise ImportFormatError(f"{path}: 'messages' must be an array")
        return list(messages or []), data
    if isinstance(data, list):
        return data, {}
    raise ImportFormatError(f"{path}: expected a session object or message array")


def message_text(message):
    """Extract text from a Hermes/OpenAI-style message content field."""
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        text = content.get("text")
        return text if isinstance(text, str) else ""
    if isinstance(content, list):
        chunks = []
        for block in content:
            if isinstance(block, str):
                chunks.append(block)
            elif isinstance(block, dict) and isinstance(block.get("text"), str):
                chunks.append(block["text"])
        return "\n".join(chunk for chunk in chunks if chunk)
    return ""


def render_session(messages):
    lines = []
    for message in messages:
        if not isinstance(message, dict):
            continue
        role = message.get("role")
        role = role if isinstance(role, str) and role else "unknown"
        if role in _SKIP_ROLES:
            continue
        text = message_text(message).strip()
        if text:
            lines.append(f"{role}: {text}")
    return "\n\n".join(lines)


def _session_records(root, profile_name, *, owner, imported_at, default_created):
    sessions = root / "sessions"
    if not sessions.is_dir():
        return []
    records = []
    for path in sorted(list(sessions.glob("*.json")) + list(sessions.glob("*.jsonl"))):
        messages, meta = _read_session(path)
        body = render_session(messages)
        if not body:
            continue
        session_id = meta.get("id") or meta.get("session_id") or path.stem
        created = (
            rfc3339(meta.get("created_at"))
            or rfc3339(meta.get("created"))
            or next(
                (
                    rfc3339(m.get("timestamp"))
                    for m in messages
                    if isinstance(m, dict) and rfc3339(m.get("timestamp"))
                ),
                None,
            )
            or default_created
        )
        relative = path.relative_to(root).as_posix()
        records.append(
            build_record(
                f"hermes-sess:{session_id}",
                "conversation",
                body,
                owner,
                created=created,
                imported_at=imported_at,
                source=SOURCE,
                importer=IMPORTER,
                sensitivity=SENSITIVITY_PRIVATE,
                kind_priority="opportunistic",
                max_chars=8000,
                on_budget_exceed="truncate_last",
                extra_provenance={"profile": profile_name, "file": relative},
            )
        )
    return records


def parse_profile(
    path,
    *,
    owner,
    imported_at=None,
    default_created=None,
    include_sessions=True,
):
    """Parse a Hermes profile directory into a deterministic record list."""
    root = Path(path)
    if not root.is_dir():
        raise ImportFormatError(f"not a Hermes profile directory: {root}")
    if not any(
        (root / name).exists() for name in ("memories", "sessions", "profile.yaml")
    ):
        raise ImportFormatError(
            f"{root} does not look like a Hermes profile "
            "(no memories/, sessions/ or profile.yaml)"
        )
    imported_at = imported_at or now_utc()
    default_created = default_created or imported_at
    meta = _read_profile_meta(root)
    profile_name = meta.get("name") or root.name
    records = _memory_records(
        root,
        profile_name,
        owner=owner,
        imported_at=imported_at,
        default_created=default_created,
    )
    if include_sessions:
        records.extend(
            _session_records(
                root,
                profile_name,
                owner=owner,
                imported_at=imported_at,
                default_created=default_created,
            )
        )
    return dedupe_sorted(records)


def build_import_bundle(
    path,
    *,
    bundle_id="hermes-profile",
    owner,
    imported_at=None,
    default_created=None,
    include_sessions=True,
    tombstones=(),
):
    """Parse a Hermes profile into a validated MBCP manifest."""
    records = parse_profile(
        path,
        owner=owner,
        imported_at=imported_at,
        default_created=default_created,
        include_sessions=include_sessions,
    )
    return make_bundle(records, bundle_id, tombstones=tombstones)


def import_profile(store, path, **kwargs):
    """Tombstone-first import of a Hermes profile into ``store``."""
    return apply_import(store, build_import_bundle(path, **kwargs))


__all__ = [
    "ImportFormatError",
    "build_import_bundle",
    "import_profile",
    "message_text",
    "parse_profile",
    "render_session",
    "split_memory_entries",
]
