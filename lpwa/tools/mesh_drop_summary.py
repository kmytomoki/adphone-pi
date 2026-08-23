#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""meshログからDROP系イベントを集計する簡易ツール。

使い方:
    python3 tools/mesh_drop_summary.py /path/to/mesh.log
"""

from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path


PATTERNS = {
    "drop_dup": re.compile(r"\[DROP \]"),
    "drop_short_group": re.compile(r"\[DROP-G\]"),
    "drop_short_data": re.compile(r"\[DROP-D\]"),
    "drop_unknown_type": re.compile(r"\[DROP-U\]"),
    "drop_ttl": re.compile(r"\[DROP-TTL\]"),
    "drop_frame": re.compile(r"\[DROP-FRAME\]"),
    "warn_key_mismatch": re.compile(r"key_id mismatch"),
    "relay_ann": re.compile(r"\[RELAY-ANN\]"),
    "relay_group": re.compile(r"\[RELAY-GBCAST\]"),
}


def summarize(path: Path) -> Counter:
    counts: Counter[str] = Counter()
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            for key, pat in PATTERNS.items():
                if pat.search(line):
                    counts[key] += 1
    return counts


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python3 tools/mesh_drop_summary.py <log_file>")
        return 2

    path = Path(sys.argv[1])
    if not path.exists():
        print(f"[ERROR] file not found: {path}")
        return 1

    counts = summarize(path)
    total_drop = sum(v for k, v in counts.items() if k.startswith("drop_"))

    print("=== Mesh Drop Summary ===")
    print(f"log_file: {path}")
    print(f"total_drop_events: {total_drop}")
    for key in sorted(PATTERNS.keys()):
        print(f"{key:18s}: {counts.get(key, 0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
