"""Minimal JSON Schema validator (stdlib only).

Supports the subset of draft 2020-12 used by the MBCP schemas:
type, required, properties, additionalProperties, enum, const, pattern,
format ("date-time"), items, minItems, maxItems, minLength, maxLength,
minimum, maximum, and local $ref ("#/$defs/...").
"""

import json
import re
from datetime import datetime
from pathlib import Path

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas"

_DATE_TIME_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


class ValidationError(ValueError):
    """Raised when an instance does not conform to a schema."""


def load_schema(name):
    """Load ``schemas/<name>.json`` from the repository."""
    path = SCHEMA_DIR / f"{name}.json"
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _is_integer(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


_TYPE_CHECKS = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "integer": _is_integer,
    "number": _is_number,
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
}


def _resolve_ref(ref, root):
    if not ref.startswith("#/"):
        raise ValidationError(f"unsupported non-local $ref: {ref!r}")
    node = root
    for part in ref[2:].split("/"):
        node = node[part]
    return node


def validate(instance, schema, root=None, path="$"):
    """Validate ``instance`` against ``schema``; raise ValidationError."""
    if root is None:
        root = schema

    if "$ref" in schema:
        schema = _resolve_ref(schema["$ref"], root)

    if "type" in schema:
        types = schema["type"]
        if isinstance(types, str):
            types = [types]
        if not any(_TYPE_CHECKS[t](instance) for t in types):
            raise ValidationError(
                f"{path}: expected type {'/'.join(types)}, got {type(instance).__name__}"
            )

    if "enum" in schema and instance not in schema["enum"]:
        raise ValidationError(f"{path}: {instance!r} not in enum {schema['enum']!r}")

    if "const" in schema and instance != schema["const"]:
        raise ValidationError(f"{path}: {instance!r} != const {schema['const']!r}")

    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            raise ValidationError(f"{path}: shorter than minLength {schema['minLength']}")
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            raise ValidationError(f"{path}: longer than maxLength {schema['maxLength']}")
        if "pattern" in schema and not re.search(schema["pattern"], instance):
            raise ValidationError(f"{path}: {instance!r} fails pattern {schema['pattern']!r}")
        if schema.get("format") == "date-time":
            if not _DATE_TIME_RE.match(instance):
                raise ValidationError(f"{path}: {instance!r} is not RFC3339 date-time")
            try:
                datetime.fromisoformat(instance.replace("Z", "+00:00"))
            except ValueError:
                raise ValidationError(f"{path}: {instance!r} is not a valid date-time")

    if _is_number(instance):
        if "minimum" in schema and instance < schema["minimum"]:
            raise ValidationError(f"{path}: {instance} < minimum {schema['minimum']}")
        if "maximum" in schema and instance > schema["maximum"]:
            raise ValidationError(f"{path}: {instance} > maximum {schema['maximum']}")

    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            raise ValidationError(f"{path}: fewer than minItems {schema['minItems']}")
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            raise ValidationError(f"{path}: more than maxItems {schema['maxItems']}")
        if "items" in schema:
            for i, item in enumerate(instance):
                validate(item, schema["items"], root, f"{path}[{i}]")

    if isinstance(instance, dict):
        for key in schema.get("required", []):
            if key not in instance:
                raise ValidationError(f"{path}: missing required property {key!r}")
        properties = schema.get("properties", {})
        for key, value in instance.items():
            if key in properties:
                validate(value, properties[key], root, f"{path}.{key}")
            else:
                additional = schema.get("additionalProperties", True)
                if additional is False:
                    raise ValidationError(f"{path}: additional property {key!r} not allowed")
                if isinstance(additional, dict):
                    validate(value, additional, root, f"{path}.{key}")
