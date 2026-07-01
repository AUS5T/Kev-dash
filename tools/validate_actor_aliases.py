#!/usr/bin/env python3
"""Validate PatchSignal Actor Activity actor alias records."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


DEFAULT_PATH = Path("review/actor_aliases.example.json")

REQUIRED_FIELDS = (
    "actor_id",
    "display_name",
    "aliases",
    "actor_type",
    "enabled",
)

OPTIONAL_STRING_ARRAY_FIELDS = ("avoid_terms",)

ALLOWED_ACTOR_TYPES = {
    "APT / espionage",
    "Ransomware / extortion",
    "Cybercrime",
    "State-aligned",
    "Hacktivist",
    "Initial access broker",
    "Unknown / mixed",
    "Other",
}


def field_value(record: dict[str, Any], field: str) -> str:
    value = record.get(field)
    return value.strip() if isinstance(value, str) else ""


def add_error(errors: list[str], path: Path, index: int, field: str, issue: str) -> None:
    errors.append(f"{path}: record {index}: {field}: {issue}")


def is_non_empty_string_array(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(isinstance(item, str) and item.strip() for item in value)


def is_string_array(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) and item.strip() for item in value)


def validate_record(
    record: Any,
    index: int,
    path: Path,
    seen_actor_ids: set[str],
    errors: list[str],
) -> None:
    if not isinstance(record, dict):
        errors.append(f"{path}: record {index}: record: must be an object")
        return

    for field in REQUIRED_FIELDS:
        if field not in record:
            add_error(errors, path, index, field, "required field is missing")

    actor_id = field_value(record, "actor_id")
    display_name = field_value(record, "display_name")
    aliases = record.get("aliases")
    actor_type = field_value(record, "actor_type")
    enabled = record.get("enabled")

    if not actor_id:
        add_error(errors, path, index, "actor_id", "must not be empty")
    elif actor_id in seen_actor_ids:
        add_error(errors, path, index, "actor_id", "must be unique")
    else:
        seen_actor_ids.add(actor_id)

    if not display_name:
        add_error(errors, path, index, "display_name", "must not be empty")

    if not is_non_empty_string_array(aliases):
        add_error(errors, path, index, "aliases", "must be a non-empty array of non-empty strings")

    if not actor_type:
        add_error(errors, path, index, "actor_type", "must not be empty")
    elif actor_type not in ALLOWED_ACTOR_TYPES:
        add_error(errors, path, index, "actor_type", f"must be one of: {', '.join(sorted(ALLOWED_ACTOR_TYPES))}")

    if not isinstance(enabled, bool):
        add_error(errors, path, index, "enabled", "must be a boolean")

    for field in OPTIONAL_STRING_ARRAY_FIELDS:
        if field in record and not is_string_array(record.get(field)):
            add_error(errors, path, index, field, "must be an array of non-empty strings when provided")

    if "notes" in record and not isinstance(record.get("notes"), str):
        add_error(errors, path, index, "notes", "must be a string when provided")

    if "source_notes" in record and not isinstance(record.get("source_notes"), str):
        add_error(errors, path, index, "source_notes", "must be a string when provided")


def load_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        print(f"{path}: file not found", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as error:
        print(f"{path}: JSON parse error at line {error.lineno}, column {error.colno}: {error.msg}", file=sys.stderr)
        sys.exit(1)


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PATH
    data = load_json(path)

    errors: list[str] = []
    if not isinstance(data, list):
        errors.append(f"{path}: top-level value must be an array")
    else:
        seen_actor_ids: set[str] = set()
        for index, record in enumerate(data):
            validate_record(record, index, path, seen_actor_ids, errors)

    if errors:
        print("Actor Activity actor alias validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1

    count = len(data) if isinstance(data, list) else 0
    print(f"Actor Activity actor alias validation passed: {path} contains {count} actor alias record(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
