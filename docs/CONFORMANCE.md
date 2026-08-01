# How this schema is kept true to the product

The core promise of this repository is that the published schema describes the Public Evidence Packet the Pruvz product demonstration actually exports — no more, no less. This page states exactly what backs that promise today, and what the repeatable path from a live product run to a conforming packet looks like.

## Where the schema comes from

The schema was derived field-for-field from the product's wire contract: the response types of the action details view (`GET /api/actions/{actionId}`) and the evidence timeline view (`GET /api/actions/{actionId}/evidence`) of the Pruvz product API, including their serialization conventions (camelCase names, UPPER_SNAKE enum strings, Z-suffixed UTC timestamps) and their documented conditional rules (which blocks appear for which verification status). The product's own contract tests pin those responses on the product side.

## The repeatable bridge: composing a packet from a live run

A Public Evidence Packet is, by definition, the two API responses under a version envelope. The bundled composer makes that definition executable:

```bash
# 1. Run the product demo and save the two responses of one action:
#      action.json    — the response of GET /api/actions/{actionId}
#      evidence.json  — the response of GET /api/actions/{actionId}/evidence
# 2. Compose and validate the packet:
npm run compose -- action.json evidence.json my-action.packet.json
```

Composition adds the `packetFormatVersion` envelope and nothing else, then runs full validation (schema + packet-level consistency) before writing. If a real product response ever stops conforming, the composer fails loudly — that failure means the contract and the schema have diverged, which is a bug in one of them and worth [reporting](../CONTRIBUTING.md).

## Honest limits, and the standing guard

- The examples in this repository are synthetic, authored to the same contract — they are not captured product output. A sanitized packet composed from a real demo run is planned to be published alongside the packet walkthrough (see the README's related-material section).
- The durable guard against silent drift belongs on the product side: a contract test in the product repository that validates its serialized API responses against this published schema on every product change. Until that test exists, conformance rests on the derivation above plus the composer check against real runs.
