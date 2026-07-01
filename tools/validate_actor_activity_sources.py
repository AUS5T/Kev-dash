#!/usr/bin/env python3
"""Validate PatchSignal Actor Activity source watchlist records."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


DEFAULT_PATH = Path("review/source_watchlist.example.json")

REQUIRED_FIELDS = (
    "source_id",
    "source_name",
    "source_type",
    "homepage_url",
    "enabled",
)

OPTIONAL_URL_FIELDS = ("feed_url", "search_url")

ALLOWED_SOURCE_TYPES = {
    "government",
    "vendor",
    "security_research",
    "security_news",
    "cert",
    "other",
}


def field_value(record: dict[str, Any], field: str) -> str:
    value = record.get(field)
    return value.strip() if isinstance(value, str) else ""


def add_error(errors: list[str], path: Path, index: int, field: str, issue: str) -> None:
    errors.append(f"{path}: record {index}: {field}: {issue}")


def is_http_url(value: str) -> bool:
    return value.startswith(("http://", "https://"))


def validate_record(
    record: Any,
    index: int,
    path: Path,
    seen_source_ids: set[str],
    errors: list[str],
) -> None:
    if not isinstance(record, dict):
        errors.append(f"{path}: record {index}: record: must be an object")
        return

    for field in REQUIRED_FIELDS:
        if field not in record:
            add_error(errors, path, index, field, "required field is missing")

    source_id = field_value(record, "source_id")
    source_name = field_value(record, "source_name")
    source_type = field_value(record, "source_type")
    homepage_url = field_value(record, "homepage_url")
    enabled = record.get("enabled")

    if not source_id:
        add_error(errors, path, index, "source_id", "must not be empty")
    elif source_id in seen_source_ids:
        add_error(errors, path, index, "source_id", "must be unique")
    else:
        seen_source_ids.add(source_id)

    if not source_name:
        add_error(errors, path, index, "source_name", "must not be empty")

    if not source_type:
        add_error(errors, path, index, "source_type", "must not be empty")
    elif source_type not in ALLOWED_SOURCE_TYPES:
        add_error(errors, path, index, "source_type", f"must be one of: {', '.join(sorted(ALLOWED_SOURCE_TYPES))}")

    if not homepage_url:
        add_error(errors, path, index, "homepage_url", "must not be empty")
    elif not is_http_url(homepage_url):
        add_error(errors, path, index, "homepage_url", "must start with http:// or https://")

    if not isinstance(enabled, bool):
        add_error(errors, path, index, "enabled", "must be a boolean")

    for field in OPTIONAL_URL_FIELDS:
        value = field_value(record, field)
        if value and not is_http_url(value):
            add_error(errors, path, index, field, "must start with http:// or https:// when provided")


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
        seen_source_ids: set[str] = set()
        for index, record in enumerate(data):
            validate_record(record, index, path, seen_source_ids, errors)

    if errors:
        print("Actor Activity source watchlist validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1

    count = len(data) if isinstance(data, list) else 0
    print(f"Actor Activity source watchlist validation passed: {path} contains {count} source record(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
