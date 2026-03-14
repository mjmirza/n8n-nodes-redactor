<p align="center">
  <img src="https://unpkg.com/n8n-nodes-redactor@1.0.2/dist/nodes/PiiRedactor/redact.png" alt="PII Redactor" width="80" />
</p>

<h1 align="center">n8n-nodes-redactor</h1>

<p align="center">
  <strong>Local PII detection and reversible redaction engine for n8n workflows</strong><br/>
  30+ PII patterns &bull; 4 redaction modes &bull; Persistent vault &bull; Field targeting &bull; Audit trail<br/>
  <em>Intellectual property of <a href="https://next8n.com">next8n</a></em>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/n8n-nodes-redactor"><img src="https://img.shields.io/npm/v/n8n-nodes-redactor?style=flat-square&color=CB3837" alt="npm" /></a>
  <img src="https://img.shields.io/badge/tests-127_passed-brightgreen?style=flat-square" alt="tests" />
  <img src="https://img.shields.io/badge/license-FUCL-orange?style=flat-square" alt="license" />
  <img src="https://img.shields.io/badge/TypeScript-strict-3178C6?style=flat-square" alt="TypeScript" />
</p>

---

## Architecture

```
src/nodes/PiiRedactor/
├── PiiRedactor.node.ts   # n8n node — UI properties, operations, wiring
├── engine.ts             # Redaction/restore engine — recursive JSON walk, field targeting
├── patterns.ts           # 30+ PII regex patterns with validators (Luhn, IBAN, NHS)
├── vault.ts              # Storage backends — MemoryVault + FileVault with TTL
├── types.ts              # Shared TypeScript interfaces
└── __tests__/
    ├── patterns.test.ts  # 62 tests — every pattern, positive + negative cases
    ├── vault.test.ts     # 22 tests — memory, file, TTL, corruption, factory
    └── engine.test.ts    # 43 tests — redaction, restore, modes, dedup, edge cases
```

## Module Breakdown

### `patterns.ts` — PII Detection

| Category | Patterns | Validation |
|----------|----------|------------|
| Contact | Email, Phone (intl), Phone (UK) | — |
| Identity | Person names (title-prefix heuristic), SSN, Passports (US/EU), Driver License, German National ID, NHS, EIN | NHS mod-11 checksum |
| Financial | Credit Card, IBAN, BIC/SWIFT, EU VAT (27 states), UK Bank Account | Luhn (CC), ISO 13616 (IBAN) |
| Network | IPv4, IPv6, MAC, URL | IPv4 range validation |
| Location | US ZIP, UK Postcode, DE Postcode, GPS Coordinates | GPS precision filter |
| Temporal | Dates (slash/dash/dot/ISO), DOB with label | — |
| Medical | MRN (prefix-based) | — |
| Crypto | Bitcoin (Legacy + Bech32), Ethereum | — |

### `vault.ts` — Token Storage

Two backends implementing `IVault` interface:

- **`MemoryVault`** — `Map<string, VaultSession>`, fast, ephemeral
- **`FileVault`** — JSON files in `~/.n8n/pii-vault/`, SHA-256 hashed filenames, survives restarts

Both support: TTL auto-expiry, session CRUD, `findByOriginal()` for deduplication, `cleanup()` for garbage collection.

### `engine.ts` — Redaction Engine

- Recursive JSON walker — handles nested objects, arrays, mixed types
- Field path matching with wildcards (`user.email`, `*.phone`, `items[*].name`)
- 4 modes: `token` (reversible), `mask` (smart partial), `hash` (SHA-256), `redact` (full removal)
- Deduplication — same PII value → same token across all fields
- Audit report builder — hits by category, by pattern, per field, per item

### `PiiRedactor.node.ts` — n8n Integration

3 operations: **Redact**, **Restore**, **Stats**

Dual output on Redact: processed data (output 1) + audit report (output 2, optional).

## Build

```bash
npm install
npm run build     # tsc → dist/
npm run dev       # tsc --watch
npm test          # jest, 127 tests
```

## Test Coverage

```
Test Suites: 3 passed, 3 total
Tests:       127 passed, 127 total

patterns.test.ts  — 62 tests (every PII type, positive + negative, validators)
vault.test.ts     — 22 tests (memory, file, TTL, corruption, factory)
engine.test.ts    — 43 tests (redact, restore, modes, dedup, fields, edge cases)
```

Edge cases covered: long strings (10K chars), 100-item batch, Unicode, re-redaction prevention, Luhn false positive rejection, IBAN checksum rejection, corrupt vault files, expired TTL, missing sessions, null values, empty objects, LLM token rephrasing.

## Publish Flow

Uses the same pattern as `n8n-nodes-xentral`:

```bash
npm run prepublishOnly   # Swaps README.npm.md → README.md, builds
npm publish              # Publishes to npm with user-facing README
npm run postpublish      # Restores technical README
```

---

## License

**Fair Use Code License (FUCL)**

Copyright (c) 2026 Mirza Iqbal / [next8n](https://next8n.com). All rights reserved.

**All intellectual property, source code, and associated rights are owned exclusively by the copyright holder.**

**Permitted:** Install and use for internal workflows and business automation.

**Prohibited without explicit written consent:** Copying, forking, reproducing, redistributing, reselling, sublicensing, white-labeling, creating derivative works, using as part of a commercial service offering, removing copyright notices.

This software is provided "as is", without warranty of any kind.

For commercial licensing, partnership, or custom development: [services.next8n.com](https://services.next8n.com)
