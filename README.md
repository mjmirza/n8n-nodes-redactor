<p align="center">
  <img src="https://unpkg.com/n8n-nodes-redactor@2.0.0/dist/nodes/PiiRedactor/redact.png" alt="Redactor" width="80" />
</p>

<h1 align="center">n8n-nodes-redactor</h1>

<p align="center">
  <strong>Enterprise-grade PII detection, redaction, and compliance for n8n workflows</strong><br/>
  216 patterns, 35+ countries, 22 regulations, 15 modules, 426 tests<br/>
  <em>Intellectual property of <a href="https://next8n.com">next8n</a></em>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/n8n-nodes-redactor"><img src="https://img.shields.io/npm/v/n8n-nodes-redactor?style=flat-square&color=CB3837" alt="npm" /></a>
  <img src="https://img.shields.io/badge/tests-426_passed-brightgreen?style=flat-square" alt="tests" />
  <img src="https://img.shields.io/badge/license-FUCL-orange?style=flat-square" alt="license" />
  <img src="https://img.shields.io/badge/TypeScript-strict-3178C6?style=flat-square" alt="TypeScript" />
</p>

---

## Architecture

```
src/nodes/PiiRedactor/
├── PiiRedactor.node.ts   # n8n node (8 operations, UI properties)
├── engine.ts             # Core redaction/restore engine
├── patterns.ts           # 216 regex patterns with validators
├── context.ts            # Confidence scoring, context word boosting
├── names.ts              # Name dictionary (3000+ names, 15 languages)
├── vault.ts              # Memory + File vault with encryption
├── encryption.ts         # AES-256-GCM vault encryption (scrypt KDF)
├── presidio.ts           # Optional Presidio NLP client (circuit breaker)
├── classification.ts     # Data sensitivity classification (4 levels)
├── injection.ts          # Prompt injection detection (25+ patterns)
├── audit.ts              # JSONL audit logger (GDPR/HIPAA/SOX compliant)
├── pseudonymize.ts       # Format-preserving pseudonymization (seeded RNG)
├── profiles.ts           # Per-tenant profile management
├── ropa.ts               # GDPR Art.30 ROPA report generator
├── types.ts              # TypeScript interfaces
└── __tests__/            # 12 test suites, 426 tests
```

## Operations

| Operation | Purpose | Output 1 | Output 2 |
|-----------|---------|----------|----------|
| Redact | Replace PII with tokens/masks/pseudonyms | Redacted data | Audit report (if enabled) |
| Restore | Swap tokens back to originals | Restored data | - |
| Detect | Scan without modifying | Original data | Detection report |
| Verify | Confirm no PII leaked | PASS/FAIL | - |
| Classify | Assign sensitivity labels | PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED | - |
| Purge | Delete vault sessions (GDPR Art.17) | Confirmation | - |
| Stats | Monitor vault health | Session list | - |

Production flow: `Detect > Redact > [LLM] > Verify > Restore > Purge`

## Redaction Modes

| Mode | Output | Reversible | GDPR |
|------|--------|------------|------|
| Token | `[EMAIL_0]` | Yes | Tokenization |
| Mask | `j***@e***.com` | No | Masking |
| Hash | `[EMAIL:a3f2b8c91d4e]` | No | Hashing |
| Redact | `[REDACTED]` | No | Anonymization |
| Pseudonymize | `sarah.miller@example.com` | Yes | Pseudonymization (Art.4(5)) |

## Security Features

- **Vault encryption**: AES-256-GCM with scrypt key derivation
- **Tenant isolation**: Different passphrases = different encryption keys
- **ReDoS protection**: All user-supplied regex validated by `isSafeRegex()`
- **No PII in reports**: Original values never appear in audit reports
- **Prompt injection detection**: 25+ patterns, 6 attack categories
- **Circuit breaker**: Presidio failures don't cascade
- **Atomic file writes**: Write to temp, rename (no corruption)
- **Memory limits**: 1000-session cap, TTL auto-expiry

## Enterprise Features

- **Confidence scoring**: 0.0-1.0 per detection, tunable threshold
- **Context word boosting**: 120+ patterns with nearby-keyword analysis
- **Allow/Deny lists**: Bypass or force-flag specific values
- **Name dictionary**: 3000+ names across 15 languages for free-text detection
- **Semantic field detection**: 30+ categories, 1000+ field name variations
- **Context-aware detection**: Sibling field analysis for ambiguous fields
- **Per-tenant profiles**: Save/load per-client configurations
- **GDPR Art.30 ROPA reports**: Auto-generated compliance records
- **Persistent audit log**: JSONL, Splunk/ELK compatible, daily rotation
- **Optional Presidio NLP**: Docker sidecar for ML-level name detection

## Build

```bash
npm install
npm run build
npm test          # 426 tests
npm run dev       # tsc --watch
```

## Enhanced NLP Detection (Optional)

For ML-level person name and organization detection, optionally integrate with Microsoft Presidio:

```bash
docker run -d -p 5002:3000 mcr.microsoft.com/presidio-analyzer
```

See [docs/PRESIDIO_SETUP.md](docs/PRESIDIO_SETUP.md) for full setup guide with docker-compose.

## Documentation

- [docs/MARKET_RESEARCH.md](docs/MARKET_RESEARCH.md) - Competitive analysis
- [docs/IMPLEMENTATION_CHECKLIST.md](docs/IMPLEMENTATION_CHECKLIST.md) - Development roadmap
- [docs/PRESIDIO_SETUP.md](docs/PRESIDIO_SETUP.md) - Presidio Docker setup guide
- [examples/](examples/) - Importable n8n workflow templates

---

## License

**Fair Use Code License (FUCL)**

Copyright (c) 2026 Mirza Iqbal / [next8n](https://next8n.com). All rights reserved.

This node is published as an n8n community node for the benefit of the n8n ecosystem and the teams building AI workflows that need to handle customer data responsibly. However, the intellectual property, source code, and all associated rights are owned exclusively by the copyright holder.

**Permitted:**
- Install and use this node for your own internal workflows and business automation

**Prohibited without explicit written consent:**
- Copying, forking, or reproducing the source code in any form
- Commercial redistribution, resale, sublicensing, or white-labeling
- Creating derivative works or competing products based on this code
- Public redistribution of modified or unmodified versions
- Using the Software as part of a commercial service offering
- Removing or altering copyright notices or attribution

**Attribution:** This node was developed and is actively maintained by [next8n](https://next8n.com). Attribution must be preserved in all copies.

This software is provided "as is", without warranty of any kind, express or implied.

**We built it. We maintain it. We own the rights to the code.**

**Legal notice:** This is an original, independently authored work. The entire source code is the intellectual property of the copyright holder. No third-party proprietary code is included. All PII detection runs locally using pattern matching and validation algorithms authored by next8n.

Interested in collaborating or contributing? We're open to partnerships. Let's talk.

**Missing a use case?** If there is a specific scenario not covered by the built-in 216+ patterns, reach out. We will be happy to enhance the node so everyone benefits.

For commercial licensing, partnership, custom patterns, or feature requests: [services.next8n.com](https://services.next8n.com)
