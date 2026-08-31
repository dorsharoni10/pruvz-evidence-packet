#!/usr/bin/env python3
"""Vendors the package data the installed Python verifier needs (PRUVZ-101).

Copies the published schema releases and the verifier/v1 golden vectors from
the repository into pruvz_verifier/_data/, so the built wheel is
self-sufficient offline. The _data directory is generated output (gitignored):
run this immediately before `python -m build`, never edit its contents.

With --check, verifies instead that every vendored file is byte-identical to
its repository source and that nothing extra is present — the release workflow
runs this against the exact bytes that went into the wheel.
"""

from __future__ import annotations

import filecmp
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
DATA_ROOT = os.path.join(HERE, "pruvz_verifier", "_data")

# (repository-relative source, _data-relative destination)
TREES = [("schema", "schema")]
FILES = [(os.path.join("verifier", "v1", "golden-vectors.json"), os.path.join("verifier", "v1", "golden-vectors.json"))]


def vendor() -> None:
    if os.path.isdir(DATA_ROOT):
        shutil.rmtree(DATA_ROOT)
    for source, destination in TREES:
        shutil.copytree(os.path.join(REPO_ROOT, source), os.path.join(DATA_ROOT, destination))
    for source, destination in FILES:
        target = os.path.join(DATA_ROOT, destination)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copyfile(os.path.join(REPO_ROOT, source), target)
    print(f"vendored package data into {DATA_ROOT}")


def check() -> int:
    problems = []
    expected = set()
    for source, destination in TREES:
        for directory, _, names in os.walk(os.path.join(REPO_ROOT, source)):
            for name in names:
                source_file = os.path.join(directory, name)
                relative = os.path.relpath(source_file, os.path.join(REPO_ROOT, source))
                expected.add(os.path.normpath(os.path.join(destination, relative)))
    for _, destination in FILES:
        expected.add(os.path.normpath(destination))

    present = set()
    for directory, _, names in os.walk(DATA_ROOT):
        for name in names:
            present.add(os.path.normpath(os.path.relpath(os.path.join(directory, name), DATA_ROOT)))

    for missing in sorted(expected - present):
        problems.append(f"missing from _data: {missing}")
    for extra in sorted(present - expected):
        problems.append(f"unexpected in _data: {extra}")

    sources = {os.path.normpath(d): os.path.join(REPO_ROOT, s) for s, d in FILES}
    for relative in sorted(expected & present):
        for source, destination in TREES:
            if relative.startswith(os.path.normpath(destination) + os.sep):
                sources[relative] = os.path.join(REPO_ROOT, source, os.path.relpath(relative, destination))
    for relative in sorted(expected & present):
        if not filecmp.cmp(sources[relative], os.path.join(DATA_ROOT, relative), shallow=False):
            problems.append(f"differs from repository source: {relative}")

    for problem in problems:
        print(problem, file=sys.stderr)
    print("package data check: " + ("FAILED" if problems else "OK, byte-identical to the repository sources"))
    return 1 if problems else 0


if __name__ == "__main__":
    if "--check" in sys.argv[1:]:
        raise SystemExit(check())
    vendor()
