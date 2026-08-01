# Security policy

## Reporting

If you believe you have found a security issue in this repository — or anything in it that looks like a secret, an internal endpoint, an internal identifier, or real (non-synthetic) customer-like data — please email **hello@pruvz.ai** with the subject line "Security — evidence packet repository". Please do not open a public issue for suspected sensitive-data exposure before we have had a chance to respond. We aim to acknowledge reports within a few business days.

## Scope of this repository

This repository contains only a published JSON Schema, synthetic examples, documentation, and a local structural validator. By design it must never contain:

- Pruvz verification logic, connectors, system-of-record access logic, or policy evaluation logic.
- Internal service code, internal endpoints, internal identifiers, or infrastructure details.
- Credentials, secrets, customer data, or sensitive operational data.

If you spot anything that violates this boundary, that is a valid report — see above.

## The validator

The validator performs structural JSON Schema validation only, entirely on your machine. It makes no network calls and sends no telemetry and no packet contents to Pruvz or anyone else. It requires no Pruvz account and no API key. You can confirm all of this by reading [`lib/validator.mjs`](lib/validator.mjs) and [`bin/validate.mjs`](bin/validate.mjs) — together well under two hundred lines.
