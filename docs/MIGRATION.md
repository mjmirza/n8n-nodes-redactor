# Migrating from 1.x to 4.0

Version 4.0 removes every use of the local disk so the node runs on n8n Cloud and passes n8n's verification scanner. Three 1.x features stored data in files. This page shows what replaces each one and what to do before you upgrade. The version jumps from 1.x to 4.0 because 2.0.0 and 3.0.x were published briefly in March 2026 and withdrawn, and npm never allows a version number to be reused.

## Before you upgrade

1. Let running Redact and Restore pairs finish. Sessions expire after their TTL (60 minutes by default), so waiting one TTL is enough.
2. If you rely on the JSONL audit files in `~/.n8n/pii-audit/`, copy them somewhere safe. 4.0 does not read or delete them.
3. If you keep tenant profiles in `~/.n8n/pii-profiles/`, open each `profile_*.json`. You will paste its content into the node.

Need the disk-based behaviour? Stay on the 1.x line, which still gets security and correctness fixes.

```bash
npm install n8n-nodes-redactor@v1-legacy
```

## What changed

| 1.x | 4.0 | What to do |
|---|---|---|
| File vault in `~/.n8n/pii-vault/` (Vault Storage set to File-Based) | Workflow Storage, kept with the workflow by n8n | Nothing. Workflows that never changed Vault Storage switch automatically. A saved value of `file` is treated as Workflow Storage |
| Vault Directory parameter | Removed | Nothing. The setting is ignored |
| Encrypted vault files (passphrase) | Encrypted Workflow Storage, same AES-256-GCM and passphrase | Nothing. Keep the passphrase on both nodes |
| JSONL audit log in `~/.n8n/pii-audit/` | An `audit` record on the Report output | Turn on Audit Log, then connect the Report output to a node that stores it, for example Postgres, Google Sheets, or a file node on self-hosted n8n |
| Profiles in `~/.n8n/pii-profiles/` (not reachable from the node) | Use Tenant Profile and a JSON field on Redact | Turn on Use Tenant Profile and paste the profile JSON |
| Operation without a resource | One resource called Data | Nothing. The default fills in for saved workflows and every operation keeps its value |

## How Workflow Storage behaves

- Redact and Restore share sessions only inside the same workflow. Restoring tokens in a different workflow is no longer possible. Keep both nodes in one workflow.
- n8n saves workflow storage after production runs of an active workflow. In a manual run of the whole workflow, Redact and Restore still share the session for that run.
- Stored sessions keep their TTL. Expired sessions are removed on the next run, with or without the passphrase.
- At most 500 sessions are kept per workflow. The oldest are removed first.

## Moving the passphrase to a credential

From 4.1 the vault passphrase belongs in a Redactor Vault credential. The old Vault Encryption Passphrase field is saved in plain text with the workflow, next to the encrypted sessions.

1. Create a Redactor Vault credential and enter the same passphrase you use today.
2. Attach it to every Redact and Restore node that shares sessions.
3. Clear the Vault Encryption Passphrase field on those nodes and save the workflow.

Sessions written before the change keep working, because the passphrase is the same. If you leave the old field filled in, the credential still takes priority.

## Other behaviour changes in 4.1

- Custom patterns, allow list and deny list regexes that repeat a group containing a quantifier or an alternation, such as `(a+)+` or `(a|b)+`, now stop the run with an error. Rewrite them without the nested repetition, for example `[ab]+`. Tenant profiles refuse them the same way.
- Keys that contain PII are redacted in the output and in report paths. Restore puts them back.
- Detect and Verify scan numeric values, so a card number stored as a number is reported.
- In-Memory sessions are kept per workflow. A workflow can no longer list, restore or purge another workflow's sessions.

## Behaviour changes in 4.2

- An attached Redactor Vault credential that cannot be read, or has an empty passphrase, stops the run. Re-enter the passphrase in the credential, or remove the credential to use the legacy field.
- Redact scans numbers as well as text, so a number that matches a pattern, such as a card number, is replaced. Restore returns it as a number. A semantic field such as a salary also restores as a number now, where 4.1 returned a string.
- The regex safety check also refuses alternation or optional parts hidden inside a wrapper group, such as `^(?:(?:a|aa))+$` or `(a?)+`.
- Purge removes expired sessions and sessions encrypted with a different passphrase too.

## Behaviour changes in 4.3

- The regex safety check refuses two repetitions in a row that can match the same characters, such as `\d+\d+`, `a*a*b` or `[a-z]+\w+@`. Such patterns can take exponential time on short input. The check compares the characters each part can match, treats upper and lower case as the same, and counts every character outside ASCII as one shared character. A fixed separator between the parts makes the pattern safe again, as in `[A-Z]+-[0-9]+` or `\w+@\w+[.]\w+`. Patterns such as `[A-Z]{2}[0-9]+`, `EMP-[0-9]{6}?`, `\d{3}-\d{4}` and `[0-9]{3}` are still accepted.
- Custom pattern and deny list regexes run on windows of at most 2048 characters of long text, split at a space when one is near. A match that would cross a window edge is not found.
- A legacy passphrase expression that fails to evaluate stops the run. Fix the expression or move the passphrase into a Redactor Vault credential.
- A pseudonym never equals text present anywhere in the input of the run, so some pseudonyms differ from 4.2 for the same session and value. Existing mappings are reused.
- A number and a string with the same digits get separate vault entries, so each restores with its own type.

## Behaviour changes in 5.0

- A custom pattern or deny list regex stops the run when it would scan a value longer than 20,000 characters. The error names the regex and the limit. Exclude long fields with field rules, or remove the regex. Built-in patterns, exact and contains deny list entries are not limited.
- An allow list regex is never tested on a value longer than 20,000 characters, so such a value is not allow-listed and stays redacted.
- The 2048-character windows from 4.3 are gone. Every pattern scans the whole value, and `^` and `$` mean the start and end of the value again.
- The regex safety check is stricter. A group that can match nothing, such as `(?:b|)`, no longer separates two repetitions, escapes such as `\x61` count as the character they stand for, and a negated class such as `[^a]` is compared case-insensitively after negation. Patterns such as `^a+(?:b|)a+`, `\x61+\x61+` and `A+[^a]A+` are now refused.
- A number that a pattern matched only in part is replaced with one `[NUMBER_n]` token, so it never shares a token with a string of the same digits.
- Each mention of a repeated name is scored on its own context, so a later mention with a context word such as "spoke with" can be redacted at a threshold the first mention misses.

## Behaviour changes in 5.1

- The regex safety check refuses the empty classes `[]` and `[^]`, legacy octal escapes such as `\061`, letter escapes it does not know such as `\a` or `\p`, and class ranges with `\d`, `\w` or `\s` as an end such as `[a-\d]`. These were misread by the check and could hide slow patterns. Write the character itself, a `\xHH` escape, or a plain range instead.
- Each detector matches against the original value, not the partly redacted one. A lookbehind such as `(?<=ID )[0-9]+` still sees text an earlier detector replaced, and `^` only matches at the start of the value.
- Tokens for a custom label keep only letters, digits and underscores, so the label `my-secret` produces `[MY_SECRET_0]`. Restore still reads tokens from earlier versions.
- A key named `__proto__` is kept as an ordinary property on Redact and Restore.

## Behaviour changes in 5.2

- Input text equal to a token the session already maps, such as `[EMAIL_0]` from an earlier run, is replaced with a `[LITERAL_n]` token and restores as that same text. If a workflow redacts already redacted data in the same session, run Restore twice to get back to the originals.
- The regex safety check refuses a variable repetition inside a lookahead or lookbehind, such as `(?=a+)`. Fixed counts such as `(?=[0-9]{4})` are still accepted.

## Moving to 6.0 and node version 2

New Redactor nodes use node version 2. Saved workflows keep version 1 until you replace the node, so nothing below changes for them silently.

Version 2 only, the two output changes:

- In the ROPA record, `processingSummary.hitsByCategory` counts PII categories such as `contact`. The sensitivity level counts move to `hitsBySensitivity`. Version 1 keeps the levels under `hitsByCategory` and adds `hitsByPiiCategory`.
- A custom pattern whose category is not one of the listed categories stops the run with an error. Version 1 files it under `other`.

Every version, the detection and correctness fixes:

- More text is redacted. Names after words such as `This`, surnames such as `Qureshi`, 13 to 19 digit cards, compact `+49` numbers, whole private key blocks, apostrophes and quoted local parts in emails, and international email domains. Check downstream steps that expected these values in clear text.
- Deny list entries and custom patterns now apply to text that looks like a token, such as `[SECRET_123]`.
- The ROPA retention text and `auditLogRetentionDays` (now `null`) state only what the node enforces.
- Presidio also analyzes keys that contain spaces or punctuation. Single-word keys are not sent, see [DESIGN-DECISIONS.md](DESIGN-DECISIONS.md).

## Moving to 6.1

Node version 2 only:

- Verify also checks free text for person names, so a run with a leaked name now reports `FAIL`. Version 1 keeps the earlier behaviour.

Every version:

- More text is redacted. Short IBANs, cards followed by another number, `+33`, `+44` and `+31` phones, compressed IPv6, punycode and address-literal emails, and names with apostrophes, hyphens, `Mc` or accents. Check downstream steps that expected these values in clear text.
- Prompt injection checks also read keys, so a workflow that only had injection text in a key can now be flagged or blocked.
- Presidio entities take the category of the built-in pattern with the same label, so a VAT code is counted as financial.
- The ROPA record reports the TTL of an existing session rather than the one requested.

## Moving to 7.0

7.0 is a major release because saved workflows of every node version can produce different output. Nothing needs to be reconfigured, but check downstream steps that read redacted values.

- Connection-string detection consumes complete ODBC brace-enclosed values, including semicolons and doubled closing braces, so password suffixes cannot survive Redact or pass Verify.
- Connection-string keys accept spaces and tabs around equals signs, and quoted passwords with doubled quotes are consumed whole.
- JWT headers are detected after hyphen boundaries with a constant number of linear scans, so URL prefixes cannot hide encoded personal data from Redact or Verify.
- Unsecured JWTs whose decoded header specifies alg none are detected with their trailing empty signature. Other algorithms still require a nonempty signature.
- Session IDs are converted to strings once when read, so numeric expressions use the same identifier for storage, restoration and opaque report and audit references without value-bearing hash errors.
- The final pseudonym restoration check compares objects independently of property order while preserving array order and value types, so integer-like pseudonym keys no longer falsely stop valid output.
- Pseudonym repair reserves token-shaped text from every generated output before allocating repair tokens and checks restoration against the final vault, including after workflow storage is reloaded.
- Connection-string detection consumes quoted values with embedded semicolons and doubled enclosing quotes, so no password suffix survives Redact or passes Verify.
- JWT detection scans Base64URL segments and validates decoded JSON objects instead of requiring fixed prefixes, so legal whitespace before claims is covered by Redact and Verify.
- Presidio responses with negative, empty, reversed or out-of-range spans count as scan failures. Bounds use the submitted text's code-point length. The default stops output, and explicit continuation reports unscanned texts and PARTIAL audit status.
- Direct PII Types selections must be arrays of known pattern names, and unknown Detection Scope values stop the run instead of silently disabling detection.
- If Presidio Fails accepts only stop or continue. Invalid expression results stop the run before scanning.
- Allow list and deny list regex errors identify the list and its one-based row index without exposing entry contents, including input-length failures.
- Audit records and full redaction reports use a deterministic opaque session reference instead of the raw Session ID. Session errors omit the identifier, including missing, expired and unreadable sessions.
- The comparison guide describes audit records on Report and explains that downstream storage controls persistence, rotation and retention. Audit Log alone retains no audit trail.
- CI now runs on pushes to every branch, as well as pull requests, while keeping GitHub Actions pinned by SHA.

- More text is redacted: five-word names, decomposed accents, names with particles such as `van` or `de`, labelled names with apostrophes, hyphens or inner capitals, a valid card after a stray digit, Unicode email local parts, IBANs grouped with nonbreaking spaces, IPv6 after a colon label, the address `::`, full `AB` blood types, connection-string passwords of any length on one line, and LDAP DNs of any length. A connection-string password and an LDAP value now end at a line break.
- An element of an array is judged with the keys next to the array, so `id: ["ACME-SECRET-ID"]` beside a name is redacted like `id: "ACME-SECRET-ID"`.
- A boolean under a sensitive key, such as `disability: true`, is replaced with a token and counted in Classify and ROPA. Restore returns the boolean.
- In Pseudonymize mode, a value whose pseudonym would run together with the text beside it gets a bracketed token such as `[SALARY_3]` instead, so Restore returns the exact original.
- Overlapping Presidio entities are covered as a whole. Touching parts of the same type become one replacement, and parts of different types keep their own.
- Presidio is asked for scores from the configured confidence threshold, where 6.x always asked for 0.4 and up. A threshold of 0, the default, still asks for 0.4.
- Restore and Detect keep binary attachments. Redact removes them unless Binary Attachments is set to Keep Unscanned, because the node does not scan file content. Verify reports `FAIL` and counts `unscannedAttachments` when an item carries an attachment.
- In Pseudonymize mode, a string or key that would not restore exactly, because a mapping made for another field spells text next to it, is replaced whole by a `[TEXT_n]` token.
- A Prompt Injection or Presidio setting whose expression fails stops the run with that error.
- A run-wide setting given by an expression, such as Session ID or Tenant Profile, must give the same value for every item. When items disagree the run stops. Split mixed batches first, for example with Loop Over Items, so each run sees one tenant.
- More credentials and identifiers are redacted: OpenAI project, service-account and admin keys, GitHub fine-grained tokens, and nine-character German ID card serial numbers.
- Verify has a new Verify Output option. The default, Report, is unchanged. Items, Stop on FAIL returns the checked items and stops the run on `FAIL`.
- Bearer tokens and Basic authentication headers match in any letter case, and Basic authentication is part of the recommended patterns. A bearer token needs at least eight characters.
- Secrets such as `password=...` are matched with quoted values taken whole, spaces included, and passwords of any length.
- An unknown word inside a name run that holds a known name, as in `Alice Beth Claire Xochitl Quispe`, is redacted with the rest of the name.
- A Redact run whose session expires before it finishes stops with an error instead of returning tokens.
- More names are redacted: every word after a title such as `Mr.` or `Dr.`, all-capitals names such as `JOHN SMITH`, and long labelled full names. A labelled name still stops at a lower-case word after its first four words.
- Compact international phone numbers such as `+436641234567` are redacted by the new `phoneE164` pattern, which is part of the recommended set.
- Secrets under quoted keys, as in `{"password":"..."}`, are redacted.
- On Detect, a failed Include Audit Report or Audit Log expression stops the run instead of dropping the report.
- A tenant profile with a `NaN` confidence threshold is refused.
- A built-in pattern match that overlaps an earlier replacement no longer causes a rescan from the next character. Its free parts are still redacted.
- A Redaction Mode expression must give one of the listed modes. An unknown value stops the run instead of passing data through.
- Basic credentials are redacted wherever they appear: as a header value, under an `authorization` or `proxy_authorization` key, and inside serialized JSON. The Basic header pattern replaces only the `Basic ...` part, so `Authorization: Basic abc` becomes `Authorization: [HTTP_BASIC_AUTH_0]` where 6.x replaced the whole line.
- Any value under an `authorization` key, including a bearer token, is redacted as a credential.
- Quoted environment values such as `DB_PASS='azure zebra'` are replaced whole, quotes included, where 6.x stopped at the first space.
- A tenant profile that sets `fieldMode` without `fieldRules` applies that mode to the node's own field rules.
- A negative Session TTL stops the run. Use 0 to keep the session until it is purged.
- With Presidio on, a text Presidio could not scan stops the run by default, because 6.x passed it through as if scanned. Set the new If Presidio Fails option to Continue With Patterns Only to keep the 6.x behaviour; the report then counts the unscanned texts in `presidioUnscannedTexts`.
- A blank Allow List row is ignored. In 6.x it allowed every value through.
- Restore stops when two keys would restore to the same name, instead of keeping only one of their values.
- With Deduplicate on, repeated numbers and booleans under sensitive keys share one token, as repeated text always did. A number never shares a token with the same digits as text.
- Email pseudonyms use only domains reserved for documentation, such as `example.com` and `shop.test`.
- After a pseudonym repair, report hits name the repaired key and its token, so each hit points at a field in the output.
- With Presidio on, an empty or invalid Presidio URL stops the run, and an unusable Presidio answer counts as an unscanned text.
- A Confidence Threshold outside 0 to 1 stops the run.
- Slack `xapp-` and `xoxe.` tokens are redacted.
- An audit record is `PARTIAL` with `presidioUnscannedTexts` when Presidio skipped any text.

## Tenant profile fields

All fields are optional. Unknown fields are rejected so a typo never passes silently.

| Field | Type | Overrides |
|---|---|---|
| `enabledPatterns` | array of pattern names | Detection Scope and PII Types to Detect |
| `customPatterns` | array of `{ "label", "regex", "category" }` | Custom Patterns |
| `confidenceThreshold` | number from 0 to 1 | Confidence Threshold |
| `redactionMode` | token, mask, hash, redact, pseudonymize, blackout or remove | Redaction Mode |
| `dedup` | true or false | Deduplicate |
| `fieldMode` | all, allowlist or denylist | Field Targeting |
| `fieldRules` | array of `{ "field", "mode" }`, mode include or exclude | Field Rules |
| `allowList`, `denyList` | array of `{ "value", "type" }`, type exact, contains or regex | Allow List (Never Redact) and Deny List (Always Redact) |
| `retentionMinutes` | minutes, 0 or more | Session TTL (Minutes) |
| `auditLog` | true or false | Audit Log, when the node shows the Report output |

`profileId`, `displayName`, `region`, `createdAt` and `updatedAt` are accepted as labels and have no effect on redaction.

```json
{
  "profileId": "acme",
  "redactionMode": "token",
  "enabledPatterns": ["email", "phone", "iban"],
  "allowList": [{ "value": "@acme.com", "type": "contains" }],
  "retentionMinutes": 30
}
```
