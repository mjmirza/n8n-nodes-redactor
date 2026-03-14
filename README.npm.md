<p align="center">
  <img src="https://unpkg.com/n8n-nodes-redactor@1.0.2/dist/nodes/PiiRedactor/redact.png" alt="Redactor" width="80" />
</p>

<h1 align="center">n8n-nodes-redactor</h1>

<p align="center">
  <strong>Stop sending your customer data to OpenAI, Claude, and Gemini unprotected.</strong><br/>
  Built, maintained, and owned by <a href="https://next8n.com">next8n</a>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/n8n-nodes-redactor"><img src="https://img.shields.io/npm/v/n8n-nodes-redactor?style=for-the-badge&color=CB3837&label=npm" alt="npm version" /></a>
  <a href="https://www.npmjs.com/package/n8n-nodes-redactor"><img src="https://img.shields.io/npm/dt/n8n-nodes-redactor?style=for-the-badge&color=blue&label=downloads" alt="npm downloads" /></a>
  <a href="#license"><img src="https://img.shields.io/badge/license-FUCL-orange?style=for-the-badge" alt="License" /></a>
  <img src="https://img.shields.io/badge/PII_Types-125+-success?style=for-the-badge" alt="125+ PII Types" />
  <img src="https://img.shields.io/badge/Tests-229_Passed-brightgreen?style=for-the-badge" alt="229 Tests Passed" />
  <img src="https://img.shields.io/badge/Categories-11-success?style=for-the-badge" alt="11 Categories" />
  <img src="https://img.shields.io/badge/Countries-25+-success?style=for-the-badge" alt="25+ Countries" />
  <img src="https://img.shields.io/badge/Vault-Reversible-7B61FF?style=for-the-badge" alt="Reversible Vault" />
  <img src="https://img.shields.io/badge/GDPR-Ready-00C4B4?style=for-the-badge" alt="GDPR Ready" />
  <img src="https://img.shields.io/badge/HIPAA-Ready-00C4B4?style=for-the-badge" alt="HIPAA Ready" />
  <img src="https://img.shields.io/badge/100%25-Local_Processing-10A37F?style=for-the-badge" alt="100% Local" />
  <img src="https://img.shields.io/badge/n8n-Community_Node-FF6D5A?style=for-the-badge" alt="n8n Community Node" />
  <img src="https://img.shields.io/badge/AI_Agent-Compatible-10A37F?style=for-the-badge" alt="AI Agent Compatible" />
  <img src="https://img.shields.io/badge/TypeScript-Strict-3178C6?style=for-the-badge&logo=typescript&logoColor=white" alt="TypeScript" />
  <img src="https://img.shields.io/badge/Maintained-Active-brightgreen?style=for-the-badge" alt="Actively Maintained" />
</p>

---

## Your customer data is leaving your server right now.

Every time your n8n workflow sends a customer email, phone number, address, IBAN, or credit card to OpenAI or Claude - **that data is gone**. You don't control it anymore. Your customer didn't consent to it. And under GDPR, **you're liable**.

You know this is a problem. Your clients know it too. But rebuilding every workflow to strip PII manually? That's weeks of work nobody has time for.

**This node fixes it in 2 minutes.**

Drop it between your data source and your LLM node. It automatically detects and replaces 125+ types of sensitive data with safe tokens. The LLM processes the clean data. Then the node swaps the original values back in. Your customer data never leaves your server.

No cloud service. No API keys. No third-party dependency. Everything runs locally on your machine.

<p align="center">
  <a href="https://services.next8n.com"><img src="https://img.shields.io/badge/Need_Help_Setting_Up%3F-Book_a_Free_Call-FF6D5A?style=for-the-badge&logoColor=white" alt="Book a consultation" /></a>
</p>

---

## How it works

```
[Your Data] --> [PII Redactor: REDACT] --> [OpenAI / Claude / Gemini] --> [PII Redactor: RESTORE] --> [Clean Output]
```

**Before the LLM sees it:**
```json
{
  "message": "Mrs. Sarah Johnson (sarah@bigcorp.com) reported a billing issue. SSN: 987-65-4321"
}
```

**What the LLM actually receives:**
```json
{
  "message": "[PERSON_0] ([EMAIL_1]) reported a billing issue. SSN: [SSN_2]"
}
```

**After the LLM responds, the node restores everything automatically:**
```json
{
  "reply": "I've resolved the billing issue for Mrs. Sarah Johnson. A confirmation has been sent to sarah@bigcorp.com."
}
```

The LLM never saw the real data. Your customer never knew the difference.

---

## What it detects (125+ sensitive data types across 11 categories)

### Contact Information
| Type | Examples |
|------|----------|
| Email | `john@company.com`, `user+tag@sub.domain.co.uk` |
| Phone | `(555) 123-4567`, `+49 30 1234-5678` |
| UK Phone | `020 7946 0958`, `+44 7911 123456` |
| Person Names | `Mr. John Smith`, `Dr. Anna Wilson`, `Frau Weber`, `Señor García` |

### Financial Data
| Type | Validation |
|------|------------|
| Credit Cards | Luhn algorithm verified - rejects random 16-digit numbers |
| IBAN | ISO 13616 checksum verified - rejects invalid checksums |
| BIC/SWIFT | `DEUTDEFF`, `DEUTDEFF500` |
| EU VAT Numbers | All 27 EU member states covered |
| UK Bank Accounts | Sort code + account number |

### Government IDs
| Type | Coverage |
|------|----------|
| US SSN | `123-45-6789` |
| US/EU Passports | `C12345678`, `AB1234567` |
| UK NHS Numbers | With mod-11 checksum validation |
| German National ID | 10-character format |
| US EIN | `12-3456789` |
| US Driver License | Common format |

### Network & Digital
| Type | Examples |
|------|----------|
| IPv4 / IPv6 | `192.168.1.1`, full IPv6 |
| MAC Addresses | `00:1A:2B:3C:4D:5E` |
| URLs | Any `http://` or `https://` URL |
| Bitcoin Addresses | Legacy (`1...`) and Bech32 (`bc1...`) |
| Ethereum Addresses | `0x742d35Cc...` |

### Location & Dates
| Type | Examples |
|------|----------|
| US ZIP Codes | `90210`, `90210-1234` |
| UK Postcodes | `SW1A 1AA`, `EC1A1BB` |
| GPS Coordinates | `51.5074, -0.1278` |
| Dates | `15/03/1990`, `2024-03-15`, `15.03.1990` |
| Dates of Birth | `DOB: 15/03/1990` |

### Medical & Compliance
| Type | Examples |
|------|----------|
| Medical Record Numbers | `MRN: 12345678`, `MRN#987654` |

### Government IDs (25+ countries)
| Country | Types |
|---------|-------|
| USA | SSN, ITIN, EIN, Driver License (contextual), Passport |
| Canada | SIN (Luhn validated) |
| UK | NINO, NHS (mod-11 checksum), Passport |
| Germany | Personalausweis, Steuer-ID, Sozialversicherungsnummer, Reisepass, Handelsregister (HRB) |
| Austria | Sozialversicherungsnummer (date validated) |
| Switzerland | AHV/AVS number |
| France | NIR (social security) |
| Italy | Codice Fiscale, Carta d'Identita |
| Spain | DNI, NIE, NIF |
| Netherlands | BSN (11-check validated) |
| Belgium | Rijksregisternummer |
| Poland | PESEL (checksum validated) |
| Sweden | Personnummer |
| Norway | Fodselsnummer |
| Denmark | CPR-nummer |
| Finland | Henkilotunnus (HETU) |
| Portugal | NIF (checksum validated) |
| Ireland | PPS Number |
| Australia | TFN (checksum validated), Medicare |
| New Zealand | IRD Number |
| Japan | My Number |
| South Korea | RRN |
| Singapore | NRIC/FIN |
| India | Aadhaar, PAN |
| Brazil | CPF |

### Enterprise and Infrastructure
| Type | Examples |
|------|----------|
| Internal Hostnames | `server-web-01.internal`, `db-prod.corp.local`, `nas.lan` |
| Windows UNC Paths | `\\fileserver\shared\docs` |
| LDAP Distinguished Names | `CN=John,OU=Users,DC=corp,DC=local` |
| Active Directory Users | `CORP\jsmith` |
| Private IPs (RFC 1918) | `10.0.1.50`, `172.16.0.1`, `192.168.1.1` |
| Database Connection Strings | JDBC, MongoDB, PostgreSQL, MySQL, Redis, MSSQL |
| API Keys | AWS (`AKIA...`), GCP (`AIza...`), Stripe, OpenAI, GitHub, Slack |
| Auth Tokens | Bearer tokens, JWT tokens |
| Cryptographic Material | PEM private keys, SSH public keys |
| Secrets in Config | `password=`, `api_key=`, `secret=`, `token=` patterns |
| Azure Keys | Storage keys, SAS tokens |
| Slack Webhooks | `hooks.slack.com/services/...` |

### Vehicle
| Type | Examples |
|------|----------|
| VIN | `1HGBH41JXMN109186` (17-character) |
| License Plates | German (`M AB 1234`), UK (`AB12 CDE`), French (`AB-123-CD`) |

### Biometric and Digital Identity
| Type | Examples |
|------|----------|
| UUID/GUID | `550e8400-e29b-41d4-a716-446655440000` |
| Social Media Handles | `@username` |
| IMEI | Device identifiers |
| ICCID | SIM card numbers |

### Custom Business Identifiers
Add your own patterns for anything specific to your business:
| Example | Regex |
|---------|-------|
| Order IDs | `ORD-\d{6}` |
| SKU Codes | `SKU-[A-Z0-9]{8}` |
| Ticket Numbers | `TICKET-\d+` |

---

## 6 Operations: When to use what

| Operation | When to use it | What it does | Example workflow |
|-----------|---------------|-------------|-----------------|
| **Redact** | Before sending data to an LLM, API, or third-party service | Detects and replaces all sensitive data with safe tokens. Stores originals in vault for later restoration. | `[Data Source] > Redact > [OpenAI] > Restore > [Output]` |
| **Restore** | After the LLM or service has processed the tokenized data | Swaps all tokens back to original values using the vault. Your output has real data again. | Place after your LLM node, before the final output. |
| **Detect** | Compliance audits, data assessment, before deciding to redact | Scans all data for sensitive information and returns a full report. Does NOT modify the data. Use this to understand what PII exists. | `[Data Source] > Detect > [If PII found] > Redact` |
| **Verify** | After redaction, to confirm nothing leaked through | Re-scans redacted output to check if any PII slipped past. Returns PASS or FAIL with details of any leaks. Defense-in-depth. | `[Data Source] > Redact > [LLM] > Verify > [Alert if FAIL]` |
| **Purge** | GDPR right to erasure, cleanup, end of workflow | Deletes vault sessions from memory or disk. Ensures no PII mapping data remains after processing. Required for GDPR Article 17 compliance. | `[End of workflow] > Purge` |
| **Stats** | Debugging, monitoring, admin | Shows all active vault sessions with entry counts and creation times. Use to monitor vault health and check for stale sessions. | Run manually to inspect vault state. |

**Recommended workflow for production:**
```
[Data Source] > Detect (assess) > Redact (protect) > [LLM] > Verify (confirm) > Restore (recover) > [Output] > Purge (cleanup)
```

---

## 4 ways to redact

Choose the right mode for your use case:

| Mode | Output | Reversible? | Best for |
|------|--------|-------------|----------|
| **Token** | `[EMAIL_0]` | Yes - vault restores originals | LLM workflows (recommended) |
| **Mask** | `j***@e***.com` | No | Logs, dashboards, support tickets |
| **Hash** | `[EMAIL:a3f2b8c91d4e]` | No | Analytics, deduplication |
| **Redact** | `[REDACTED]` | No | Maximum privacy, audit trails |

---

## Smart features that matter

### Deduplication
When the same email appears in 5 fields, it gets the same token (`[EMAIL_0]`) everywhere. The LLM understands it's the same person. Relationships in your data are preserved.

### Field Targeting
Don't want to scan internal IDs or metadata? Use allowlist or denylist mode:
- **Allowlist:** Only scan `user.email`, `*.phone`, `contacts[*].name`
- **Denylist:** Skip `internalId`, `metadata.*`, `debug`

### Persistent Vault
Choose between in-memory (fast, lost on restart) or file-based vault (survives n8n restarts). File vault stores encrypted mappings in `~/.n8n/pii-vault/`.

### Session TTL
Vault sessions auto-expire after 60 minutes by default. No unbounded memory growth. Configurable per workflow.

### Audit Report
Enable the second output to get a full compliance trail:
```json
{
  "totalHits": 7,
  "hitsByCategory": { "contact": 3, "identity": 2, "financial": 2 },
  "hitsByPattern": { "EMAIL": 2, "PHONE": 1, "SSN": 1, "CREDIT_CARD": 1, "PERSON": 2 },
  "hits": [...]
}
```

### Validation - Not Just Regex
Credit card numbers are **Luhn-checked**. IBANs are **checksum-verified** (ISO 13616). NHS numbers pass **mod-11 validation**. This means fewer false positives and less over-redaction that kills your LLM output quality.

---

## Installation

### From n8n (Recommended)
1. Go to **Settings > Community Nodes**
2. Enter `n8n-nodes-redactor`
3. Click **Install**
4. Done. The "Redactor" node appears in your node palette.

### Manual
```bash
cd ~/.n8n/nodes
npm install n8n-nodes-redactor
# Restart n8n
```

---

## Quick Start (2 minutes)

1. **Install** the node
2. **Add "Redactor"** to your workflow, set operation to **Redact**
3. **Connect it** before your OpenAI/Claude/Gemini node
4. **Add another "Redactor"** after the LLM node, set operation to **Restore**
5. Both nodes share the same Session ID (defaults to execution ID - works automatically)
6. **Run your workflow.** Customer data stays on your server.

That's it. No configuration needed for the default case.

---

## Who this is for

- **n8n consultants** building AI workflows for clients who ask "is our data safe?"
- **Agencies** delivering GDPR-compliant automation for EU clients
- **Companies** processing customer support tickets, emails, or documents through LLMs
- **Healthcare** organizations that need HIPAA compliance before sending data to AI
- **Anyone** who lies awake thinking about what happens when customer data hits an external API

---

## We build GDPR-compliant AI workflows. For a living.

We've delivered n8n + AI automation for clients across **e-commerce**, **healthcare**, **financial services**, and **consulting**. The GDPR question around client data hitting external APIs keeps coming up. We built this node because we needed it for real client projects.

**This node exists because we solve this problem every day.**

If you need help setting up PII-safe AI workflows, custom redaction rules, or end-to-end GDPR-compliant automation - we've done it before and would be happy to do it for you.

<p align="center">
  <a href="https://services.next8n.com"><img src="https://img.shields.io/badge/Book_a_Free_Consultation-services.next8n.com-FF6D5A?style=for-the-badge&logoColor=white" alt="Book a consultation" /></a>
</p>

<p align="center">
  <a href="https://next8n.com"><strong>next8n.com</strong></a> &nbsp;|&nbsp; <a href="https://services.next8n.com"><strong>Schedule a call</strong></a>
</p>

---

## Missing a use case? We'll build it for you.

This node covers 210+ data types across 22 privacy regulations. But every business has unique data: internal codes, proprietary identifiers, industry-specific formats.

**You can add your own patterns directly in the node UI** using the Custom Patterns section. Define any regex, give it a label, and the engine will detect and redact it alongside the built-in patterns.

If there is a specific use case that is not covered here and you want us to cover it so that everyone can benefit from it, or if you want a customized implementation built on top of this node, **reach out to us and we will be happy to enhance it accordingly.**

<p align="center">
  <a href="https://services.next8n.com"><img src="https://img.shields.io/badge/Request_a_Custom_Pattern_or_Feature-services.next8n.com-7B61FF?style=for-the-badge&logoColor=white" alt="Request a feature" /></a>
</p>

---

## Also by next8n

<p align="center">
  <a href="https://www.npmjs.com/package/n8n-nodes-xentral"><img src="https://img.shields.io/badge/n8n--nodes--xentral-30_Resources_|_163_Operations_|_58_Webhooks-00C4B4?style=for-the-badge" alt="n8n-nodes-xentral" /></a>
</p>

**[n8n-nodes-xentral](https://www.npmjs.com/package/n8n-nodes-xentral)** - The most comprehensive n8n community node for Xentral ERP. 30 resources, 163 operations, 58 webhook events. Full API audit verified. If you're automating Xentral workflows, this is the node you need.

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

For commercial licensing, partnership, or custom development: [services.next8n.com](https://services.next8n.com)
