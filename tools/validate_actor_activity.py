#!/usr/bin/env python3
"""Validate approved PatchSignal Actor Activity records."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


DATA_PATH = Path("data/actor_cve_links.json")

REQUIRED_FIELDS = (
    "cve",
    "actor",
    "actor_type",
    "relationship",
    "confidence",
    "evidence_summary",
    "source_name",
    "source_url",
    "source_date",
    "last_reviewed",
)

ALLOWED_CONFIDENCE = {
    "confirmed",
    "reported",
    "suspected",
    "unattributed",
}

ALLOWED_RELATIONSHIP = {
    "exploited",
    "targeted",
    "leveraged",
    "associated",
    "suspected",
    "context",
}

ALLOWED_ACTOR_TYPE = {
    "APT / espionage",
    "Ransomware / extortion",
    "Cybercrime",
    "State-aligned",
    "Hacktivist",
    "Initial access broker",
    "Unknown / mixed",
    "Other",
}

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def field_value(record: dict[str, Any], field: str) -> str:
    value = record.get(field)
    return value.strip() if isinstance(value, str) else ""


def add_error(errors: list[str], path: Path, index: int, field: str, issue: str) -> None:
    errors.append(f"{path}: record {index}: {field}: {issue}")


def validate_record(
    record: Any,
    index: int,
    path: Path,
    seen_keys: set[tuple[str, str, str]],
    errors: list[str],
) -> None:
    if not isinstance(record, dict):
        errors.append(f"{path}: record {index}: record: must be an object")
        return

    for field in REQUIRED_FIELDS:
        if field not in record:
            add_error(errors, path, index, field, "required field is missing")

    cve = field_value(record, "cve")
    actor = field_value(record, "actor")
    actor_type = field_value(record, "actor_type")
    relationship = field_value(record, "relationship")
    confidence = field_value(record, "confidence")
    evidence_summary = field_value(record, "evidence_summary")
    source_name = field_value(record, "source_name")
    source_url = field_value(record, "source_url")
    source_date = field_value(record, "source_date")
    last_reviewed = field_value(record, "last_reviewed")

    if not cve:
        add_error(errors, path, index, "cve", "must not be empty")
    elif not CVE_RE.fullmatch(cve):
        add_error(errors, path, index, "cve", "must match CVE-YYYY-NNNN or longer numeric ID format")

    if not actor:
        add_error(errors, path, index, "actor", "must not be empty")

    if not actor_type:
        add_error(errors, path, index, "actor_type", "must not be empty")
    elif actor_type not in ALLOWED_ACTOR_TYPE:
        add_error(errors, path, index, "actor_type", f"must be one of: {', '.join(sorted(ALLOWED_ACTOR_TYPE))}")

    if not relationship:
        add_error(errors, path, index, "relationship", "must not be empty")
    elif relationship not in ALLOWED_RELATIONSHIP:
        add_error(errors, path, index, "relationship", f"must be one of: {', '.join(sorted(ALLOWED_RELATIONSHIP))}")

    if not confidence:
        add_error(errors, path, index, "confidence", "must not be empty")
    elif confidence not in ALLOWED_CONFIDENCE:
        add_error(errors, path, index, "confidence", f"must be one of: {', '.join(sorted(ALLOWED_CONFIDENCE))}")

    if not evidence_summary:
        add_error(errors, path, index, "evidence_summary", "must not be empty")

    if not source_name:
        add_error(errors, path, index, "source_name", "must not be empty")

    if not source_url:
        add_error(errors, path, index, "source_url", "must not be empty")
    elif not source_url.startswith(("http://", "https://")):
        add_error(errors, path, index, "source_url", "must start with http:// or https://")

    if not source_date:
        add_error(errors, path, index, "source_date", "must not be empty")
    elif not DATE_RE.fullmatch(source_date):
        add_error(errors, path, index, "source_date", "must use YYYY-MM-DD")

    if not last_reviewed:
        add_error(errors, path, index, "last_reviewed", "must not be empty")
    elif not DATE_RE.fullmatch(last_reviewed):
        add_error(errors, path, index, "last_reviewed", "must use YYYY-MM-DD")

    duplicate_key = (cve.upper(), actor.casefold(), source_url)
    if all(duplicate_key):
        if duplicate_key in seen_keys:
            add_error(errors, path, index, "record", "duplicates an existing cve, actor, and source_url combination")
        seen_keys.add(duplicate_key)


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
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else DATA_PATH
    data = load_json(path)

    errors: list[str] = []
    if not isinstance(data, list):
        errors.append(f"{path}: top-level value must be an array")
    else:
        seen_keys: set[tuple[str, str, str]] = set()
        for index, record in enumerate(data):
            validate_record(record, index, path, seen_keys, errors)

    if errors:
        print("Actor Activity validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1

    count = len(data) if isinstance(data, list) else 0
    print(f"Actor Activity validation passed: {path} contains {count} approved record(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
