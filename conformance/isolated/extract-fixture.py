#!/usr/bin/env python3
"""Extracts the isolated-offline fixture from a built wheel (PRUVZ-101).

Usage: python conformance/isolated/extract-fixture.py <wheel> <out-dir>

Reads the verifier/v1 golden vectors OUT OF THE WHEEL'S package data — not out
of the repository — so a wheel that shipped without its data fails here, and
writes the fixture an auditor scenario needs: the one FULLY_VERIFIED bundle,
the pinned TSA roots, and the trust pin. The containers that consume this
fixture run with --network none and contain no repository clone
(docs/CONFORMANCE-SUITE.md, isolated offline acceptance).

Stdlib only: zipfile + json.
"""

from __future__ import annotations

import json
import os
import sys
import zipfile


def main() -> None:
    if len(sys.argv) != 3:
        print("Usage: python conformance/isolated/extract-fixture.py <wheel> <out-dir>", file=sys.stderr)
        raise SystemExit(2)
    wheel_path, out_dir = sys.argv[1], sys.argv[2]

    with zipfile.ZipFile(wheel_path) as wheel:
        vectors = json.loads(wheel.read("pruvz_verifier/_data/verifier/v1/golden-vectors.json").decode("utf-8"))

    fully = [case for case in vectors["cases"] if case["expect"]["verdict"] == "FULLY_VERIFIED"]
    if len(fully) != 1:
        print(f"FAIL  expected exactly one FULLY_VERIFIED golden case, found {len(fully)}", file=sys.stderr)
        raise SystemExit(1)
    case = fully[0]

    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "bundle.json"), "w", encoding="utf-8") as handle:
        json.dump(vectors["bundles"][case["bundle"]], handle, indent=1, ensure_ascii=False)
        handle.write("\n")
    with open(os.path.join(out_dir, "tsa-roots.pem"), "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(vectors["tsaRoots"]) + "\n")
    with open(os.path.join(out_dir, "pin.env"), "w", encoding="utf-8", newline="\n") as handle:
        handle.write(f"PIN_ISSUER='{vectors['pin']['issuer']}'\n")
        handle.write(f"PIN_ROOT='{vectors['pin']['root']}'\n")
        handle.write(f"PIN_TENANT='{case['options']['tenant']}'\n")
    print(f"fixture for golden case {case['id']!r} written to {out_dir}")


if __name__ == "__main__":
    main()
