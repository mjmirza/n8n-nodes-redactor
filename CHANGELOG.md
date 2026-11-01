# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

Planned: random scoped tokens, and numbers restored as numbers.

## [2.0.0] - 2026-11-01

Runs on n8n Cloud and passes n8n's verification scanner with zero findings. 1.x stays available on the `v1-legacy` npm tag for self-hosted setups that need the disk vault. See [docs/MIGRATION.md](docs/MIGRATION.md).

### BREAKING
- **The vault no longer writes to disk.** Vault Storage now offers Workflow Storage (default) and In-Memory. Workflow Storage keeps sessions with the workflow through n8n's workflow static data, encrypted with the same AES-256-GCM passphrase. Previously sessions lived in files under `~/.n8n/pii-vault/`. A saved 1.x value of `file` is treated as Workflow Storage. Restore now works only in the workflow that ran Redact, and n8n saves the storage after production runs of an active workflow.
- **The Vault Directory parameter is removed.** It only applied to the file vault.
- **The audit log no longer writes JSONL files.** With Audit Log on, an `audit` record (counts, labels, severity, timing, never values) is added to the Report output, which now also appears when only Audit Log is on. Previously it appended to `~/.n8n/pii-audit/`. Store the record with any node.
- **Tenant profiles come from the node, not from disk.** Turn on Use Tenant Profile and paste JSON. Profiles are validated and unknown fields are rejected. Previously profile files in `~/.n8n/pii-profiles/` could not be reached from the node at all.

### Changed
- A single resource (Data) sits above the seven operations, as n8n's resource and operation rule requires. Its default fills in for saved workflows and no operation value changed.
- Presidio is called through n8n's HTTP helper instead of Node's `http` and `https` modules. Only `http` and `https` Presidio URLs are called.
- Publishing picks the npm dist-tag from the git tag. `v1.*` publishes to `v1-legacy`, never `latest`, and `v2` or later to `latest`. The choice lives in `tools/npm-dist-tag.sh`, which has its own tests and fails closed on a malformed tag.
- Lint now runs the exact rule set of n8n's verification scanner, and n8n-workflow 2.45.4, the stable release, is used for development.

### Fixed
- **The Presidio circuit breaker never opened on network errors.** A failed connection recorded the failure without a URL, so a down Presidio was retried for every field. It now stops after three failures per URL and execution.
- **Detect ignored Audit Log.** The toggle was shown for Detect but no record was written. Detect now adds its audit record too.
- **The audit `processingTimeMs` was always about zero.** The timer started one line before it was read. It now measures from the start of the execution.
- **Encrypted vault sessions never expired without the passphrase.** Cleanup had to decrypt a session to read its TTL. Creation time and TTL are now stored next to the ciphertext, so expired sessions are removed either way.

## [1.11.1] - 2026-11-01

### Documentation
- README rewritten to the project standard. It previously opened with fear framing, carried a duplicated redaction-modes table, an unverified "up to 50%" false-positive claim and a hardcoded test-count badge (437, the suite has 438). It now leads with outcomes, states plainly that the node is self-hosted only because the vault and audit log use the local disk, and adds a developer section.

### Changed
- `.nvmrc` pins Node 24, matching CI. Node 26 has no prebuilt `isolated-vm`, so `test/execute.test.ts` could not load there.


## [1.11.0] - 2026-10-19

### Security
- **Restore could return another session's data.** If the requested session was missing and exactly one other session existed, Restore used that one, which could hand one tenant's originals to another workflow. Restore now fails with a clear message instead. Previously step-by-step testing relied on this fallback; now set the same fixed Session ID on both nodes when testing one step at a time.

- **IBANs and card numbers in free text were only partly redacted.** A loose pattern (for example a Swiss phone number) could match digits inside an IBAN or card number before the checksum-validated pattern ran, so `DE89370400440532013000` became `DE8937[PHONE_CH_0]013000` and most of the number still reached the LLM. Verify then reported PASS because the fragment no longer looked like an IBAN. Checksum-validated patterns now run first. Across 52 IBAN and card cases in text, partial leaks went from 24 to 0.

### Fixed
- **Purge crashed** with "Could not get parameter: sessionId". Purge and Stats no longer read the Redact-only Session ID.
- **Numeric fields ignored field exclusion.** A number in an excluded field was redacted anyway. It is now left alone.
- **Item linking.** Every output item now carries `pairedItem`, so expressions like `$('Redactor').item` resolve correctly. Summary items link to all inputs.
- **Logo missing on npm and GitHub.** The README pointed at version 1.0.2, which no longer exists, so the image 404ed. It now loads from the repository.
- **Example `multi-stage-verify.json`** fed Verify's PASS/FAIL summary into Restore. Restore now receives the redacted data, and a check stops the run on a leak.

### Added
- **GDPR Art.30 ROPA record** on the Redact report output (Include Audit Report, then Include GDPR Art.30 ROPA Record). The README listed this before, but it was not reachable from the node.
- Vector node icon with light and dark variants (was a 60px PNG with a white box in dark mode).
- npm provenance: releases are now published from GitHub Actions with a signed provenance statement, as n8n requires for community nodes.
- End-to-end tests that run the node's `execute()`; 437 tests in total.

### Changed
- License is now **MIT** (was FUCL in package.json and OpenRoots 1.1 in LICENSE, which contradicted each other).
- Built with n8n's official `@n8n/node-cli` toolchain; lint is clean (0 errors, was 143). Source moved from `src/nodes/PiiRedactor` to `nodes/Redactor`. The installed node type stays `n8n-nodes-redactor.redactor`, so saved workflows keep working.
- Operation and option lists are alphabetical, per n8n UI guidelines. Values are unchanged.
- README: corrected counts (7 operations, 11 categories, 216 patterns), marked per-client profiles as coming in 2.0.0 (they were never reachable), and replaced "compliant" claims with what the node actually does.

### Removed
- Unused tests and source maps from the npm tarball (tests were previously shipped inside `dist`).
- `README.npm.md` (identical duplicate of README.md).
