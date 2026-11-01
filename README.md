<p align="center">
  <img src="https://raw.githubusercontent.com/mjmirza/n8n-nodes-redactor/master/.github/assets/logo.png" alt="Redactor" width="96" />
</p>

<h1 align="center">n8n-nodes-redactor</h1>

<p align="center">
  <strong>Keep personal data out of OpenAI, Claude and Gemini while your n8n AI workflows keep working.</strong><br/>
  Built and maintained by <a href="https://next8n.com">next8n</a>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/n8n-nodes-redactor"><img src="https://img.shields.io/npm/v/n8n-nodes-redactor?label=npm" alt="npm version" /></a>
  <a href="https://www.npmjs.com/package/n8n-nodes-redactor"><img src="https://img.shields.io/npm/dm/n8n-nodes-redactor?label=downloads" alt="npm downloads" /></a>
  <a href="https://github.com/mjmirza/n8n-nodes-redactor/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/mjmirza/n8n-nodes-redactor/ci.yml?branch=master&label=CI" alt="CI status" /></a>
  <a href="https://www.npmjs.com/package/n8n-nodes-redactor#provenance"><img src="https://img.shields.io/badge/npm-provenance%20signed-brightgreen" alt="npm provenance" /></a>
  <a href="#license"><img src="https://img.shields.io/npm/l/n8n-nodes-redactor" alt="MIT License" /></a>
  <img src="https://img.shields.io/badge/PII%20patterns-216-blue" alt="216 PII patterns" />
  <img src="https://img.shields.io/badge/n8n-Cloud%20%2B%20self--hosted-FF6D5A" alt="n8n Cloud and self-hosted" />
</p>

## What you get

- **Personal data never reaches the model.** Emails, phone numbers, IBANs, card numbers, national IDs and 200 more kinds of data are swapped for safe tokens before the LLM call.
- **The answer still makes sense.** After the model replies, the node puts the real values back, so your output reads naturally.
- **Fewer false alarms.** Card numbers are Luhn checked, IBANs checksum verified, NHS numbers mod 11 validated, so random digits are left alone.
- **Proof for your records.** An optional audit report, and a GDPR Article 30 processing record built from each run.
- **No new vendor.** Everything runs inside your n8n, on n8n Cloud or self-hosted. No extra service, no API key, no runtime dependency.

## From install to first result

1. In n8n open **Settings**, then **Community Nodes**, enter `n8n-nodes-redactor` and install.
2. Add a **Redactor** node before your OpenAI, Claude or Gemini node and set the operation to **Redact**.
3. Add a second **Redactor** node after the model and set it to **Restore**.
4. Run the workflow. Both nodes share the execution ID as Session ID, so a full run works with no extra setup. When testing one node at a time, set the same fixed Session ID, for example `test-1`, on both.

The model receives tokens instead of personal data.

```json
{ "message": "[PERSON_0] ([EMAIL_1]) reported a billing issue. SSN [SSN_2]" }
```

After Restore, your workflow gets the real values back.

```json
{ "reply": "I resolved the billing issue for Mrs. Sarah Johnson and sent a confirmation to sarah@bigcorp.com." }
```

## Compatibility

| Environment | Status |
|---|---|
| n8n Cloud | Supported from 4.0.0 |
| Self-hosted n8n 1.x and 2.x | Supported |
| n8n verified community nodes | Eligible from 4.0.0. Passes n8n's verification scanner with no findings |

Version 4.0.0 uses no local disk. The vault lives in workflow storage and audit records go to the Report output. Upgrading from 1.x? Read [docs/MIGRATION.md](https://github.com/mjmirza/n8n-nodes-redactor/blob/master/docs/MIGRATION.md). The 1.x line stays installable with `npm install n8n-nodes-redactor@v1-legacy`.

## Operations

| Operation | Use it when | What it does |
|---|---|---|
| Redact | Before an LLM, API or third party | Replaces sensitive values with tokens, stores originals in the vault, and checks the input for prompt injection |
| Restore | After the model or service replies | Swaps tokens back to the original values |
| Detect | Assessing data before deciding | Reports what personal data exists without changing anything |
| Verify | After redaction | Rescans the output and returns PASS or FAIL with any leaked values |
| Classify | Governance and routing | Labels data PUBLIC, INTERNAL, CONFIDENTIAL or RESTRICTED |
| Purge | Erasure requests and cleanup | Deletes vault sessions from memory or workflow storage, supporting GDPR Article 17 |
| Stats | Debugging | Lists active vault sessions with entry counts and TTL |

The recommended production chain looks like this.

```
Data source > Redact > Verify > LLM > Restore > Output > Purge
```

Detect is for a dry run before you set up redaction. It adds a summary item to its output by default, so keep it out of this chain, or turn on Include Audit Report, which moves the summary to a second output.

Set Verify Output on the Verify node to Items, Stop on FAIL. Verify then passes the redacted items on unchanged when nothing leaks, and stops the run before the LLM when something does, so the model never receives data that failed the check. With the default Report output, Verify returns one report instead of the items, so it cannot sit in this chain. Verify also fails when an item carries a binary attachment, because attachments are not scanned. Redact removes attachments by default. Set Binary Attachments to Keep Unscanned only when the files hold no personal data.

## Redaction modes

| Mode | Output | Reversible | Best for |
|---|---|---|---|
| Token | `[EMAIL_0]` | Yes | LLM workflows, the default |
| Pseudonymize | `sarah.miller@example.com` | Yes | Demo data, QA, GDPR pseudonymization |
| Mask | `j***@e***.com` | No | Logs and support tickets |
| Hash | `[EMAIL:a3f2b8c91d4e]` | No | Analytics and deduplication |
| Redact | `[REDACTED]` | No | Maximum privacy |
| Blackout | `████████` | No | Visual censoring |
| Remove | empty string | No | Leaving no trace |

## What it detects

216 patterns across 11 categories.

| Category | Examples |
|---|---|
| Contact | Email, international and UK phone numbers, titled person names |
| Financial | Credit cards (Luhn), IBAN (ISO 13616), BIC, EU VAT numbers, UK bank accounts |
| Government IDs | 25+ countries, including US SSN, UK NINO and NHS, German Steuer-ID and Personalausweis, Spanish DNI and NIE, Dutch BSN, Polish PESEL, Indian Aadhaar and PAN, Brazilian CPF |
| Network | IPv4, IPv6, MAC addresses, URLs, Bitcoin and Ethereum addresses |
| Location and dates | US ZIP, UK postcodes, GPS coordinates, dates and dates of birth |
| Medical | Medical record numbers |
| Infrastructure | Internal hostnames, UNC paths, LDAP names, connection strings, cloud API keys, JWTs, PEM keys, Slack webhooks |
| Vehicle | VIN, German, UK and French plates |
| Digital identity | UUIDs, social handles, IMEI, ICCID |
| Custom | Your own regex patterns, for example `ORD-\d{6}` |

## Features in detail

| Feature | Detail |
|---|---|
| Deduplication | The same value gets the same token everywhere, so the model keeps relationships between fields |
| Field targeting | Allowlist or denylist paths such as `user.email`, `*.phone` or `metadata.*` |
| Vault | Workflow Storage by default, so Restore works in later production runs of the same workflow, or In-Memory. Sessions expire after 60 minutes by default |
| Vault encryption | AES-256-GCM with scrypt key derivation, one passphrase per tenant, kept in a Redactor Vault credential. See [Vault encryption](#vault-encryption) |
| Confidence threshold | Each match carries a 0.0 to 1.0 score. Checksum validated patterns score 0.95 |
| Allow and deny lists | Values to never redact, such as your support address, and values to always redact, such as project codenames |
| Prompt injection check | 25+ patterns, including instruction overrides, delimiter escapes, encoded payloads and zero width characters. Returns BLOCK, FLAG or CLEAN |
| Audit report | A second output with hits by category and pattern |
| Audit log | Turn on Audit Log to get an `audit` record (counts, labels, timing, never values) on the Report output. Send it to any database, sheet or SIEM node |
| ROPA record | Turn on Include Audit Report, then Include GDPR Art.30 ROPA Record, and fill in the controller details |
| Presidio | Optional Microsoft Presidio container for names and organisations in free text. See [docs/PRESIDIO_SETUP.md](https://github.com/mjmirza/n8n-nodes-redactor/blob/master/docs/PRESIDIO_SETUP.md). Falls back to built-in patterns when unreachable |
| Per-tenant profiles | Turn on Use Tenant Profile and paste JSON. Validated on every run. Fields are listed in [docs/MIGRATION.md](https://github.com/mjmirza/n8n-nodes-redactor/blob/master/docs/MIGRATION.md#tenant-profile-fields) |

This node reduces what reaches a model. It is not legal advice and does not on its own make a workflow GDPR or HIPAA compliant.

## Vault encryption

Workflow Storage keeps sessions with the workflow. To encrypt them, create a **Redactor Vault** credential with a passphrase of at least 12 characters and attach it to both the Redact and the Restore node. n8n stores credentials encrypted and apart from the workflow, so the passphrase never sits next to the data it protects. Give each tenant its own credential.

The older Vault Encryption Passphrase field still works so workflows saved with it keep restoring, but it is saved in plain text inside the workflow. When both are set, the credential wins.

Restore needs the same passphrase that Redact used. If Redact meets a session ID that a different passphrase wrote, it stops with an error instead of overwriting it.

### Concurrent runs

n8n saves workflow storage as one block at the end of each production run and does not merge it. If two runs of the same workflow overlap, the one that finishes last wins. A session created by the other run can be lost, and a session purged by the other run can come back until its TTL expires. The node cannot prevent this from inside n8n. To stay safe, keep the Session TTL short, avoid overlapping runs of a workflow that uses Purge (for example by limiting production concurrency on your instance), or use In-Memory storage when Redact and Restore run in the same execution.

In-Memory sessions are kept per workflow and are never visible to another workflow.

## For developers

| Area | Detail |
|---|---|
| Language | TypeScript, strict mode |
| Runtime dependencies | None. Only `n8n-workflow` as a peer |
| Tests | Jest, run on every push in CI |
| Node.js | 24, as pinned in `.nvmrc` and CI. Node 26 has no prebuilt `isolated-vm`, which `n8n-workflow` loads in tests |

```bash
npm ci
npm run typecheck
npm run lint
npm test
npm run build
```

Project layout:
- `nodes/Redactor/` holds the node, the detection engine, patterns, vault and reports
- `test/` holds the Jest suites
- `tools/check-tarball.sh` makes sure only the built node ships to npm
- `.github/workflows/` holds CI and the signed publish workflow

Releases are cut by pushing a `vX.Y.Z` tag. The publish workflow tests, builds and publishes with npm provenance.

## Support

- Custom patterns, new use cases or setup help go to [services.next8n.com](https://services.next8n.com)
- Bugs and feature requests go to [GitHub issues](https://github.com/mjmirza/n8n-nodes-redactor/issues)
- Also by next8n, [n8n-nodes-xentral](https://www.npmjs.com/package/n8n-nodes-xentral) for Xentral ERP

## License

MIT. See [LICENSE](LICENSE). Copyright (c) 2026 Mirza Iqbal, [next8n](https://next8n.com).
