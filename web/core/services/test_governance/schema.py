"""Validate a report against ``report.schema.json`` (the versioned JSON Schema; draft 2020-12 subset).

The deployed stack has no ``jsonschema`` package, so this implements exactly the keywords the schema uses:
type, const, enum, pattern, minimum, required, properties, items, minItems, maxItems.  An unsupported keyword is a
programming error (the schema and the validator are tested together), never silently ignored.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache

from .constants import SCHEMA_FILE

SUPPORTED = frozenset({"$schema", "$id", "title", "type", "const", "enum", "pattern", "minimum", "required", "properties", "items",
                       "minItems", "maxItems"})
_TYPES = {"object": dict, "array": list, "string": str, "boolean": bool, "null": type(None)}
MAX_ERRORS = 50


@lru_cache(maxsize=1)
def load_schema() -> dict:
    return json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))


def _type_ok(value, name: str) -> bool:
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return isinstance(value, _TYPES[name])


def validate(value, schema: dict | None = None, path: str = "$", errors: list[str] | None = None) -> list[str]:
    schema = load_schema() if schema is None else schema
    errors = [] if errors is None else errors
    if len(errors) >= MAX_ERRORS:
        return errors
    unknown = set(schema) - SUPPORTED
    if unknown:
        raise ValueError(f"schema keyword(s) not supported by the validator: {sorted(unknown)}")
    if "type" in schema:
        names = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_type_ok(value, n) for n in names):
            errors.append(f"{path}: expected {'/'.join(names)}, got {type(value).__name__}")
            return errors
    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: must equal {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: {value!r} is not one of {schema['enum']}")
    if "pattern" in schema and isinstance(value, str) and not re.search(schema["pattern"], value):
        errors.append(f"{path}: {value[:60]!r} does not match {schema['pattern']}")
    if "minimum" in schema and isinstance(value, (int, float)) and value < schema["minimum"]:
        errors.append(f"{path}: {value} < {schema['minimum']}")
    if isinstance(value, dict):
        for key in schema.get("required", ()):
            if key not in value:
                errors.append(f"{path}: missing required key {key!r}")
        for key, sub in (schema.get("properties") or {}).items():
            if key in value:
                validate(value[key], sub, f"{path}.{key}", errors)
    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(f"{path}: fewer than {schema['minItems']} items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{path}: more than {schema['maxItems']} items")
        if "items" in schema:
            for i, item in enumerate(value):
                validate(item, schema["items"], f"{path}[{i}]", errors)
                if len(errors) >= MAX_ERRORS:
                    break
    return errors
