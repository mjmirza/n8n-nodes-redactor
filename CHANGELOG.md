# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

Planned: random scoped tokens.

## [5.0.0] - 2026-11-01

Fixes every finding from a fourth adversarial review, run against 4.3.0. Each one has a regression test in `test/codex-review-43.test.ts`. The major version reflects one new failure mode. a custom or deny list regex now stops the run on a value over 20,000 characters instead of scanning it.

### Security
- **4.3.0 could miss built-in detections.** User regexes ran on 2048-character windows, and the window edges also split built-in matching, so an email near an edge stayed in the output. Windowing is removed. Every pattern scans the full value again.
- **Windows invented anchors.** `^SECRET` matched at a window start in the middle of the text. Anchors keep their meaning again.
- **Three slow regexes passed the safety check.** Groups that can match nothing, such as `(?:b|)`, no longer count as separators, escapes such as `\x61` are read whole, and case folding happens after a class is complemented, so `[^a]` correctly overlaps `A`.
- **User regexes now have a hard input limit.** A custom or deny list regex on a value longer than 20,000 characters stops the run with an error naming the regex and the limit. An allow list regex is never tested on such a value, so the value stays redacted.

### Fixed
- Presidio skipped a nested field whose path text equalled a dotted key, such as `a.b`. Replacements are now remembered per output object and key, not per path string.
- A value under an empty key `""` was pseudonymized twice and could not be restored. It now round trips.
- A number and a string with the same digits could produce the same composite token, so the string restored as a number. A partly matched number now gets its own `NUMBER` token.
- A repeated name was scored only at its first mention. Each mention is now scored on its own context.

## [4.3.0] - 2026-11-01

Fixes every finding from a third adversarial security review, run against 4.2.0. Each one has a regression test in `test/codex-review-42.test.ts`.

### Security
- **A pseudonym could hide another person's original name.** If the pseudonym for one name equalled another name in the same text, the second name was treated as already replaced and stayed in the output. Replacements are now tracked by position, not by text, and a pseudonym never equals text already present in the input.
- **A failed legacy passphrase stored originals in plain text.** When the legacy passphrase expression could not be evaluated, the node continued without encryption. Only an absent or empty legacy setting means no encryption now. A failed evaluation stops the run before anything is stored.
- **Regexes with repeated parts in a row could stall a run.** `^a+a+a+a+a+!$` passed the safety check. Two repetitions in a row that can match the same characters are now refused, and user regexes run on bounded windows of long text.

### Fixed
- Confidence scoring used the wrong text position after an earlier replacement, so an SSN with its `SSN` label could fall below the threshold. Scoring now uses the original position.
- Presidio could pseudonymize a pseudonym the regex pass had produced, so Restore returned the first pseudonym. Presidio now skips every replacement the regex pass produced.
- A string and a number with the same digits could share one vault entry, so the string restored as a number. Their mappings are now separate. A number that a pattern matched only in part, such as `123456` with `[0-9]{3}`, now restores as a number.

## [4.2.0] - 2026-11-01

Fixes every finding from a second adversarial security review, run against 4.1.0. Each one has a regression test in `test/codex-review-41.test.ts`.

### Security
- **An attached Vault credential could fail open.** If it could not be decrypted, the node fell back to the empty legacy passphrase and stored originals in plain text. An attached credential that cannot be read, or has an empty passphrase, now stops the run before anything is stored. The legacy parameter is used only when no credential is attached.
- **Injection diagnostics could still carry content.** A value matched by a custom pattern or deny list could appear in a diagnostic field path. Diagnostics now carry only the detector category, description, severity and score.
- **Presidio could receive excluded fields.** When a parent key was redacted, Presidio checked field rules against the redacted path and missed the exclusion. Field rules now always use the original path.
- **Purge left expired records behind.** Purge All and Purge Specific skipped sessions that had expired or could not be decrypted, while reporting success. Both now delete by stored record.

### Fixed
- Redact now scans numeric values, so a card number stored as a JSON number is redacted. A number that becomes a whole token restores as a number.
- A later detector could edit a token that an earlier one produced, such as a digit pattern rewriting `[EMAIL_1]`, which lost data on Restore. Each detector now leaves earlier replacements untouched.
- A redacted key could overwrite another key, and a generated token could equal token-shaped text already in the input. Generated tokens now skip anything token-shaped in the input, and redacted keys never take another key's name.
- Regexes such as `^(?:(?:a|aa))+$` and `^(a?)+$` passed the safety check. Alternation and optional atoms now count inside wrapper groups.
- A pseudonym could equal the original name. It never does now.

## [4.1.0] - 2026-11-01

Fixes every High and Medium finding from an adversarial security review of 4.0.0. Each one has a regression test in `test/codex-review.test.ts`.

### Security
- **The vault passphrase can now live in an n8n credential.** Attach a Redactor Vault credential to the node. n8n stores it encrypted, apart from the workflow JSON, and it takes priority. Previously the passphrase was a node parameter, saved in plain text next to the encrypted vault, so anyone who could read the workflow could decrypt it. The old field still works so saved workflows keep restoring, and it is marked deprecated. See [docs/MIGRATION.md](docs/MIGRATION.md#moving-the-passphrase-to-a-credential).
- **In-Memory sessions no longer cross workflows.** The memory vault was one map for the whole n8n process, so a second workflow could list another workflow's session IDs with Stats, restore its tokens to the original values, and purge them. Sessions are now kept per workflow, including listing, eviction and purge.
- **Prompt injection diagnostics no longer carry PII.** A Base64 payload was decoded and its text, including any email or name in it, was put into `_promptInjection` on the Data output. The decoded text is now withheld and every excerpt and field path is redacted before it is emitted.
- **Presidio offsets now match JavaScript strings.** Presidio counts Unicode code points and the node sliced UTF-16 units, so an emoji before a name shifted the span and left the name in the output. Offsets are converted before any text is replaced.
- **Presidio now analyzes strings inside arrays.** Values such as `notes: ["Call Xochitl Quispe"]` were never sent, so names in lists reached the model. One walker now handles objects and arrays alike.
- **PII in JSON keys is redacted.** A key such as `alice@example.com` passed through to the output and appeared in report field paths. Keys are now scanned like values, report paths use the redacted key, and Restore puts the original key back.
- **A different passphrase can no longer overwrite an encrypted session.** Redacting into a session ID that another passphrase wrote treated the record as missing and replaced it, so the first workflow lost its data. The node now stops with an error and leaves the record alone.
- **Unsafe regexes are refused instead of run or silently skipped.** Tenant profiles accepted `^(a+)+$`, which could stall a run, while the runtime silently skipped valid patterns such as `EMP-[0-9]{6}?`. Profiles and the runtime now share one structural check that refuses nested or alternated repetition with a clear error, and accepts lazy quantifiers.

### Fixed
- **Restore rescanned the values it inserted.** An original that looked like a token, such as `[EMAIL_1]`, was replaced a second time. Restore is now a single pass over the source text.
- **Two people could get the same pseudonym.** Different names that hashed to the same fake name overwrote each other, so Restore returned one person for both. Pseudonyms are now unique within a session, and the vault refuses a token that already maps to a different value.
- **Overlapping Presidio spans corrupted tokens.** A PERSON and an ORGANIZATION span over the same text produced a broken token. The stronger span now wins and originals are read from the untouched source.
- **Presidio ignored field exclusions.** An excluded field was still sent to Presidio. The same field rules, with full nested paths, now apply before the call.
- **Verify passed numeric PII.** `{ "ssn": 123456789 }` and a numeric card number returned PASS. Detect and Verify now scan numbers as text.
- **Read-only runs no longer rewrite workflow storage.** Stats, and Restore with Delete After Restore off, used to remove expired sessions, which made n8n save a full copy of the storage. Expired sessions are now skipped on read and removed on the next Redact, so fewer runs can write a stale copy. See the note on concurrent runs in the README.

### Changed
- Type declaration files are no longer shipped in the package. n8n loads the compiled JavaScript only.

## [4.0.0] - 2026-11-01

The version skips to 4.0.0 because 2.0.0 and 3.0.0 to 3.0.2 were published in March 2026 and later withdrawn, and npm never reuses a version number.

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
