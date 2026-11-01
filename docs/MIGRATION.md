# Migrating from 1.x to 2.0

Version 2.0 removes every use of the local disk so the node runs on n8n Cloud and passes n8n's verification scanner. Three 1.x features stored data in files. This page shows what replaces each one and what to do before you upgrade.

## Before you upgrade

1. Let running Redact and Restore pairs finish. Sessions expire after their TTL (60 minutes by default), so waiting one TTL is enough.
2. If you rely on the JSONL audit files in `~/.n8n/pii-audit/`, copy them somewhere safe. 2.0 does not read or delete them.
3. If you keep tenant profiles in `~/.n8n/pii-profiles/`, open each `profile_*.json`. You will paste its content into the node.

Need the disk-based behaviour? Stay on the 1.x line, which still gets security and correctness fixes.

```bash
npm install n8n-nodes-redactor@v1-legacy
```

## What changed

| 1.x | 2.0 | What to do |
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
