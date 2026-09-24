#!/usr/bin/env python3
"""A comment run is one line, and it states one technical fact about the code.

A run of two or more comment lines is a defect. The rule, why, and where the
detail went: call/0037, and the harvest record of 2026-09-23.

Run from the repository root:

    python3 tools/comment-lint.py
"""

import pathlib
import sys

# Every authored file in this repository that carries comments.
ROOTS = (
    "src/*.rs",
    "tools/argdoc/src/*.rs",
    "deploy/*.py",
    "deploy/*.sh",
    "deploy/*.init",
    "tools/*.sh",
    "Cargo.toml",
    "tools/argdoc/Cargo.toml",
    ".github/workflows/*.yml",
)


def is_comment(line: str, rust: bool) -> bool:
    """In Rust a hash introduces an attribute, so only `//` begins a comment."""
    s = line.strip()
    if rust:
        return s.startswith("//")
    if s.startswith("#!"):
        return False  # a shebang is a directive
    return s.startswith("#")


def runs(text: str, rust: bool):
    """Every run of consecutive comment lines, as (first line number, lines)."""
    found, current, first = [], [], 0
    for number, line in enumerate(text.split("\n"), 1):
        if is_comment(line, rust):
            if not current:
                first = number
            current.append(line)
        elif current:
            found.append((first, current))
            current = []
    if current:
        found.append((first, current))
    return found


def main() -> int:
    files = []
    for pattern in ROOTS:
        files.extend(sorted(pathlib.Path(".").glob(pattern)))
    bad = 0
    for path in files:
        for first, run in runs(path.read_text(), path.suffix == ".rs"):
            if len(run) > 1:
                bad += 1
                print(f"{path}:{first}: {len(run)} comment lines in one run")
    if bad:
        print(f"comment lint: {bad} run(s) span more than one line, which call/0037 refuses")
        return 1
    print(f"comment lint: {len(files)} file(s) read, and every comment run is one line")
    return 0


if __name__ == "__main__":
    sys.exit(main())