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
