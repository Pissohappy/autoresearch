"""Lightweight HarmBench data loading utilities."""

from __future__ import annotations

import json
import random
import re
from collections import Counter
from pathlib import Path
from statistics import mean
from typing import Any

MAX_PROMPT_CHARS = 2000
DEFAULT_SEED = 42

_PROMPT_KEYS = (
    "original_prompt",
    "prompt",
    "input",
    "instruction",
    "query",
    "question",
    "goal",
)
_CATEGORY_KEYS = ("category", "label", "topic", "domain", "taxonomy")
_EXPECTED_BEHAVIOR_KEYS = (
    "expected_behavior",
    "expected",
    "target_behavior",
    "behavior",
)


def _pick_str(payload: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def _clean_text(text: str, max_len: int = MAX_PROMPT_CHARS) -> str:
    text = text.strip()
    # remove illegal control chars but keep common whitespace
    text = "".join(ch for ch in text if ch == "\n" or ch == "\t" or ord(ch) >= 32)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > max_len:
        text = text[:max_len].rstrip()
    return text


def _iter_records(path: str) -> list[dict[str, Any]]:
    file_path = Path(path)
    if not file_path.exists():
        return []

    if file_path.suffix == ".jsonl":
        records: list[dict[str, Any]] = []
        with file_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                if isinstance(obj, dict):
                    records.append(obj)
        return records

    with file_path.open("r", encoding="utf-8") as f:
        payload = json.load(f)

    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if isinstance(payload, dict):
        # support datasets organized as {"train": [...], "test": [...]} etc.
        nested: list[dict[str, Any]] = []
        for value in payload.values():
            if isinstance(value, list):
                nested.extend(row for row in value if isinstance(row, dict))
        if nested:
            return nested
    return []


def load_harmbench(
    split: str,
    path: str,
    *,
    max_samples: int | None = None,
    seed: int = DEFAULT_SEED,
) -> list[dict[str, str]]:
    """Load HarmBench-like data with schema normalization and deterministic sampling."""
    raw_records = _iter_records(path)

    normalized: list[dict[str, str]] = []
    seen_prompts: set[str] = set()

    for idx, raw in enumerate(raw_records):
        row_split = str(raw.get("split", "")).strip().lower()
        if split and row_split and row_split != split.lower():
            continue

        original_prompt = _pick_str(raw, _PROMPT_KEYS)
        if not original_prompt:
            continue
        original_prompt = _clean_text(original_prompt)
        if not original_prompt:
            continue

        dedup_key = original_prompt.casefold()
        if dedup_key in seen_prompts:
            continue
        seen_prompts.add(dedup_key)

        category = _pick_str(raw, _CATEGORY_KEYS) or "uncategorized"
        category = _clean_text(category, max_len=128)
        expected_behavior = _pick_str(raw, _EXPECTED_BEHAVIOR_KEYS)
        expected_behavior = _clean_text(expected_behavior, max_len=512) if expected_behavior else ""

        sample_id = raw.get("id")
        if sample_id is None:
            sample_id = f"{split or 'all'}-{idx}"

        normalized.append(
            {
                "id": str(sample_id),
                "category": category,
                "original_prompt": original_prompt,
                "expected_behavior": expected_behavior,
            }
        )

    if max_samples is not None and len(normalized) > max_samples:
        rng = random.Random(seed)
        selected_indices = sorted(rng.sample(range(len(normalized)), k=max_samples))
        normalized = [normalized[i] for i in selected_indices]

    return normalized


def summarize_harmbench(samples: list[dict[str, str]]) -> dict[str, Any]:
    categories = Counter(row.get("category", "uncategorized") for row in samples)
    avg_length = mean(len(row.get("original_prompt", "")) for row in samples) if samples else 0.0
    return {
        "num_samples": len(samples),
        "category_distribution": dict(categories),
        "avg_prompt_length": avg_length,
    }
