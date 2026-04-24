#!/usr/bin/env python3
# Copyright (c) 2026 Reindert Pelsma
# SPDX-License-Identifier: ISC

from __future__ import annotations

import os
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC_FILES = [
    ROOT / "README.md",
    ROOT / "examples" / "README.md",
    ROOT / "turn" / "README.md",
]
DOC_FILES.extend((ROOT / "docs").rglob("*.md"))

LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
BAD_TEXT_RE = re.compile(r"<<<<<<<|=======|>>>>>>>|\[TODO\]|TODO|FIXME")


def main() -> int:
    errors: list[str] = []

    for path in DOC_FILES:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")

        bad = BAD_TEXT_RE.search(text)
        if bad:
            errors.append(f"{path.relative_to(ROOT)}: found disallowed marker {bad.group(0)!r}")

        for match in LINK_RE.finditer(text):
            target = match.group(1).split("#", 1)[0]
            if not target or target.startswith(("http://", "https://", "mailto:")):
                continue
            full = (path.parent / target).resolve()
            if not full.exists():
                errors.append(
                    f"{path.relative_to(ROOT)}: broken link {target!r} -> {full.relative_to(ROOT)!s}"
                )

    if errors:
        for err in errors:
            print(err)
        return 1

    print("docs check ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
