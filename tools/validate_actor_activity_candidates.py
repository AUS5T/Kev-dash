#!/usr/bin/env python3
"""Validate unpublished PatchSignal Actor Activity candidate records."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


DEFAULT_PATH = Path("review/actor_activity_candidates.example.json")

REQUIRED_FIELDS = (
    "candidate_id",
    "cve",
    "actor_candidate",
    "source_url",
    "source_name",
    "discovered_at",
    "detection_method",
    "evidence_summary_draft",
    "confidence_guess",
    "review_status",
)

OPTIONAL_URL_FIELDS = ("related_issue_url",)
OPTIONAL_DATE_FIELDS = ("source_date",)

ALLOWED_DETECTION_METHODS = {
    "manual",
    "github_issue",
    "curated_source_watch",
    "cve_first_search",
    "actor_first_search",
    "llm_assisted",
    "other",
}

ALLOWED_CONFIDENCE_GUESSES = {
    "confirmed",
    "reported",
    "suspected",
    "unattributed",
    "unknown",
}

ALLOWED_REVIEW_STATUSES = {
    "needs_review",
    "approved",
    "rejected",
    "needs_more_sources",
    "duplicate",
    "out_of_scope",
    "published",
}

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


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
    seen_candidate_ids: set[str],
    errors: list[str],
) -> None:
    if not isinstance(record, dict):
        errors.append(f"{path}: record {index}: record: must be an object")
        return

    for field in REQUIRED_FIELDS:
        if field not in record:
            add_error(errors, path, index, field, "required field is missing")

    candidate_id = field_value(record, "candidate_id")
    cve = field_value(record, "cve")
    actor_candidate = field_value(record, "actor_candidate")
    source_url = field_value(record, "source_url")
    source_name = field_value(record, "source_name")
    discovered_at = field_value(record, "discovered_at")
    detection_method = field_value(record, "detection_method")
    evidence_summary_draft = field_value(record, "evidence_summary_draft")
    confidence_guess = field_value(record, "confidence_guess")
    review_status = field_value(record, "review_status")

    if not candidate_id:
        add_error(errors, path, index, "candidate_id", "must not be empty")
    elif candidate_id in seen_candidate_ids:
        add_error(errors, path, index, "candidate_id", "must be unique")
    else:
        seen_candidate_ids.add(candidate_id)

    if not cve:
        add_error(errors, path, index, "cve", "must not be empty")
    elif not CVE_RE.fullmatch(cve):
        add_error(errors, path, index, "cve", "must match CVE-YYYY-NNNN or longer numeric ID format")

    if not actor_candidate:
        add_error(errors, path, index, "actor_candidate", "must not be empty")

    if not source_url:
        add_error(errors, path, index, "source_url", "must not be empty")
    elif not is_http_url(source_url):
        add_error(errors, path, index, "source_url", "must start with http:// or https://")

    if not source_name:
        add_error(errors, path, index, "source_name", "must not be empty")

    if not discovered_at:
        add_error(errors, path, index, "discovered_at", "must not be empty")

    if not detection_method:
        add_error(errors, path, index, "detection_method", "must not be empty")
    elif detection_method not in ALLOWED_DETECTION_METHODS:
        add_error(errors, path, index, "detection_method", f"must be one of: {', '.join(sorted(ALLOWED_DETECTION_METHODS))}")

    if not evidence_summary_draft:
        add_error(errors, path, index, "evidence_summary_draft", "must not be empty")

    if not confidence_guess:
        add_error(errors, path, index, "confidence_guess", "must not be empty")
    elif confidence_guess not in ALLOWED_CONFIDENCE_GUESSES:
        add_error(errors, path, index, "confidence_guess", f"must be one of: {', '.join(sorted(ALLOWED_CONFIDENCE_GUESSES))}")

    if not review_status:
        add_error(errors, path, index, "review_status", "must not be empty")
    elif review_status not in ALLOWED_REVIEW_STATUSES:
        add_error(errors, path, index, "review_status", f"must be one of: {', '.join(sorted(ALLOWED_REVIEW_STATUSES))}")

    for field in OPTIONAL_URL_FIELDS:
        value = field_value(record, field)
        if value and not is_http_url(value):
            add_error(errors, path, index, field, "must start with http:// or https:// when provided")

    for field in OPTIONAL_DATE_FIELDS:
        value = field_value(record, field)
        if value and not DATE_RE.fullmatch(value):
            add_error(errors, path, index, field, "must use YYYY-MM-DD when provided")


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
        seen_candidate_ids: set[str] = set()
        for index, record in enumerate(data):
            validate_record(record, index, path, seen_candidate_ids, errors)

    if errors:
        print("Actor Activity candidate validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1

    count = len(data) if isinstance(data, list) else 0
    print(f"Actor Activity candidate validation passed: {path} contains {count} candidate record(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
