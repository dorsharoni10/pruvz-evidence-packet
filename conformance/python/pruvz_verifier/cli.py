"""The offline Evidence Packet verifier CLI (PRUVZ-101).

Usage: pruvz-verify <bundle.json> --issuer <issuer> --root <thumbprint>
                    [--tenant <tenantId>] [--tsa-roots <pem-file>]
                    [--tsa-policy <oid> ...] [--state <state.json>]
                    [--no-update-state] [--json]

The argument surface, output and exit codes mirror the npm CLI
(bin/verify.mjs): 0 FULLY_VERIFIED, 3 PARTIALLY_VERIFIED, 1 NOT_VERIFIED,
2 usage or unreadable input. The trust anchor (--issuer and --root) is the pin
established out of band (docs/TRUST-REGISTRY.md section 4) and is mandatory:
there is no pinless mode, and nothing is ever fetched from a Pruvz deployment
or website.

--state names a JSON file holding what this verifier accepted before (the
registry version and checkpoint it saw). When given, rollback and fork
presentations become refusals instead of surprises, and the file is updated
after a run unless --no-update-state. A first run writes the initial state. A
file that is not exactly what a previous run returned is refused as unusable
input (STATE_MALFORMED) rather than reinterpreted, and only checkpoints
verified under the pinned registry are ever written into it.
"""

from __future__ import annotations

import json
import os
import re
import sys

from . import json_io, verify

USAGE = (
    "Usage: pruvz-verify <bundle.json> --issuer <issuer> --root <thumbprint>\n"
    "                    [--tenant <tenantId>] [--tsa-roots <pem-file>]\n"
    "                    [--tsa-policy <oid> ...] [--state <state.json>]\n"
    "                    [--no-update-state] [--json]"
)


def _usage() -> "SystemExit":
    print(USAGE, file=sys.stderr)
    return SystemExit(2)


def _read_json(file: str, what: str):
    try:
        with open(file, encoding="utf-8") as handle:
            text = handle.read()
        # One byte string that parses as two different documents (duplicate
        # member names) is unusable input at a trust boundary, not a nuance —
        # conformance/v1 `duplicate-member-refused`.
        return json_io.loads(text)
    except Exception as error:  # noqa: BLE001 — mirror bin/verify.mjs exactly
        print(f"FAIL  {what} {file} is not readable as JSON: {error}", file=sys.stderr)
        raise SystemExit(2) from error


def main(argv=None) -> None:
    args = list(sys.argv[1:] if argv is None else argv)

    bundle_file = None
    issuer = None
    root = None
    tenant = None
    tsa_roots_file = None
    tsa_policy_oids: list = []
    state_file = None
    update_state = True
    as_json = False

    index = 0
    while index < len(args):
        arg = args[index]

        def next_value() -> str:
            nonlocal index
            index += 1
            if index >= len(args):
                raise _usage()
            return args[index]

        if arg == "--issuer":
            issuer = next_value()
        elif arg == "--root":
            root = next_value()
        elif arg == "--tenant":
            tenant = next_value()
        elif arg == "--tsa-roots":
            tsa_roots_file = next_value()
        elif arg == "--tsa-policy":
            tsa_policy_oids.append(next_value())
        elif arg == "--state":
            state_file = next_value()
        elif arg == "--no-update-state":
            update_state = False
        elif arg == "--json":
            as_json = True
        elif arg.startswith("--"):
            raise _usage()
        elif bundle_file is None:
            bundle_file = arg
        else:
            raise _usage()
        index += 1

    if bundle_file is None or issuer is None or root is None:
        raise _usage()

    bundle = _read_json(bundle_file, "bundle")
    state = _read_json(state_file, "state") if state_file is not None and os.path.exists(state_file) else None

    tsa_roots = None
    if tsa_roots_file is not None:
        with open(tsa_roots_file, encoding="utf-8") as handle:
            pem = handle.read()
        tsa_roots = re.findall(r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----", pem)
        if len(tsa_roots) == 0:
            print(f"FAIL  {tsa_roots_file} contains no PEM certificates", file=sys.stderr)
            raise SystemExit(2)

    try:
        report = verify.verify_bundle(
            bundle,
            {"issuer": issuer, "root": root},
            tenant,
            tsa_roots,
            tsa_policy_oids if len(tsa_policy_oids) > 0 else None,
            state,
        )
    except Exception as error:  # noqa: BLE001 — mirror bin/verify.mjs exactly
        code = getattr(error, "code", None) or "ERROR"
        print(f"FAIL  {code}  {error}", file=sys.stderr)
        raise SystemExit(2) from error

    if state_file is not None and update_state and report["verdict"] != "NOT_VERIFIED":
        with open(state_file, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(report["state"], indent=2, ensure_ascii=False) + "\n")

    if as_json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(f"Verdict: {report['verdict']}")
        print("")
        print("Dimensions:")
        for name, dimension in report["dimensions"].items():
            print(f"  {name.ljust(18)} {dimension.get('status')}")
        if len(report["evidence"]) > 0:
            print("")
            print("Evidence:")
            for entry in report["evidence"]:
                sequence = "?" if entry.get("sequence") is None else str(entry["sequence"])
                seal = (entry.get("seal") or {}).get("status")
                inclusion = (entry.get("inclusion") or {}).get("status")
                print(
                    f"  {sequence.rjust(3)}  {entry.get('evidenceId')}  "
                    f"commitment={entry.get('commitment')}  seal={seal}  inclusion={inclusion}"
                )
        if len(report["reasonCodes"]) > 0:
            print("")
            print(f"Reason codes: {', '.join(report['reasonCodes'])}")
        for explanation in report["explanations"]:
            print(f"  - [{explanation['code']}] {explanation['message']}")

    verdict = report["verdict"]
    raise SystemExit(0 if verdict == "FULLY_VERIFIED" else 3 if verdict == "PARTIALLY_VERIFIED" else 1)


if __name__ == "__main__":
    main()
