#!/bin/sh
# The isolated offline acceptance (PRUVZ-101 acceptance criterion 3).
#
# Runs INSIDE a container started with --network none that contains only the
# installed package and this script — no repository clone, no schema files, no
# network. The installed `pruvz-verify` must reach FULLY_VERIFIED (exit 0) on
# the golden bundle from a read-only /fixture mount, and must refuse unusable
# input with exit 2. If the package is not self-sufficient (missing schemas or
# vectors), there is nothing here for it to silently fall back to.
set -eu

FIXTURE="${1:-/fixture}"
WORK="$(mktemp -d)"
cd "$WORK"
. "$FIXTURE/pin.env"

set +e
pruvz-verify "$FIXTURE/bundle.json" --issuer "$PIN_ISSUER" --root "$PIN_ROOT" \
  --tenant "$PIN_TENANT" --tsa-roots "$FIXTURE/tsa-roots.pem" >report.txt 2>&1
STATUS=$?
set -e
cat report.txt
if [ "$STATUS" -ne 0 ]; then
  echo "FAIL  expected exit 0 (FULLY_VERIFIED), got $STATUS"
  exit 1
fi
if ! grep -q "Verdict: FULLY_VERIFIED" report.txt; then
  echo "FAIL  expected the report to say Verdict: FULLY_VERIFIED"
  exit 1
fi

printf '{' >bad.json
set +e
pruvz-verify bad.json --issuer "$PIN_ISSUER" --root "$PIN_ROOT" >bad.txt 2>&1
STATUS=$?
set -e
if [ "$STATUS" -ne 2 ]; then
  echo "FAIL  expected exit 2 for unusable input, got $STATUS"
  cat bad.txt
  exit 1
fi

echo "isolated offline check: OK — FULLY_VERIFIED with no network and no repository"
