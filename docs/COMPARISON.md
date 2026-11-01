# n8n-nodes-redactor vs. The Competition

## Why This Node Exists

Every n8n consultant building AI workflows for clients faces the same question: **"Is our customer data safe when it goes to OpenAI?"**

The answer with most tools is either "no" or "it's complicated." With Redactor, the answer is: **"Yes. The LLM never sees the real data. And we can prove it."**

---

## Complete Feature Matrix (All Competitors Side-by-Side)

| Feature | **Redactor** | n8n Guardrails | SecureNode | Aparavi | PromptLock Guard | Presidio | Google DLP | Private AI | Nightfall AI |
|---------|-------------|----------------|------------|---------|-----------------|----------|------------|-----------|-------------|
| **Price** | **Free** | Free | $149 | Free (API key) | Free (API key) | Free | $1-3/GB | ~$46K/yr | $4-25/user/mo |
| **Platform** | **n8n node** | n8n built-in | Docker + HTTP | n8n node | n8n node | Python lib | Cloud API | Container | Cloud SaaS |
| **Installation** | **One-click** | Built-in | Docker + config | One-click | One-click | Docker + code | Cloud setup | Container deploy | SaaS signup |
| | | | | | | | | | |
| **DETECTION** | | | | | | | | | |
| PII types | **217+** | ~4 | ~40 (Presidio) | Unknown | Limited | ~40 | 150+ | 50+ | 100+ |
| Categories | **12** | 1 | 4 | Unknown | 2 | 4 | 10+ | 10+ | 10+ |
| Countries covered | **35+** | US only | 4 | 60 langs | US only | 10+ | 40+ | 50+ | 30+ |
| Person name detection | **Semantic + Dictionary + NLP** | No | Presidio NER | Unknown | No | spaCy NER | ML-based | ML-based | ML-based |
| Name dictionary size | **15,875 names** | 0 | 0 | Unknown | 0 | 0 | N/A | N/A | N/A |
| Semantic field detection | **30+ categories, 15 languages** | No | No | No | No | No | No | No | No |
| Context-aware (sibling analysis) | **Yes** | No | No | No | No | No | No | No | No |
| Confidence scoring | **0.0-1.0 with threshold** | No | Presidio scores | No | No | Yes | Yes (likelihood) | Yes | Yes |
| Context word boosting | **120+ patterns** | No | Presidio basic | No | No | Basic | N/A | N/A | N/A |
| Custom patterns (UI) | **Yes (regex)** | No | Yes (regex) | No | No | Code required | Cloud console | Config | Yes |
| Allow list (bypass) | **Yes (exact/contains/regex)** | No | No | No | No | Yes (code) | Yes | Yes | Yes |
| Deny list (always flag) | **Yes (exact/contains/regex)** | No | No | No | No | No | Yes | No | Yes |
| Checksum validators | **10 (Luhn, IBAN, PESEL, etc.)** | No | Presidio | Unknown | No | Some | Yes | Yes | Some |
| | | | | | | | | | |
| **REDACTION** | | | | | | | | | |
| Redaction modes | **7** | 1 | 2 | 1 | 1 | 5 | 8 | 4 | 3 |
| Token (reversible) | **Yes** | No | Yes | No | No | No | Complex | No | No |
| Mask (partial) | **Yes** | No | No | No | No | Yes | Yes | Yes | Yes |
| Hash (deterministic) | **Yes** | No | No | No | No | Yes | Yes | No | No |
| Redact (placeholder) | **Yes** | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Pseudonymize (fake data) | **Yes (format-preserving)** | No | No | No | No | No | Yes (FPE) | Yes | No |
| Blackout (visual bars) | **Yes (████████)** | No | No | No | No | No | No | No | No |
| Remove (complete deletion) | **Yes (empty string)** | No | No | No | No | No | Yes | No | No |
| | | | | | | | | | |
| **VAULT & STORAGE** | | | | | | | | | |
| Reversible vault | **Yes (memory + file)** | No | Yes | No | No | No | No | No | No |
| Vault encryption (AES-256-GCM) | **Yes** | No | No | No | No | N/A | N/A | N/A | N/A |
| Cross-tenant isolation | **Yes (per-passphrase)** | No | No | No | No | N/A | IAM-based | Container | Account |
| Auto-expiry (TTL) | **Yes (configurable)** | No | Unknown | No | No | N/A | N/A | N/A | N/A |
| Deduplication | **Yes (same PII = same token)** | No | Unknown | No | No | No | No | No | No |
| Graceful filesystem fallback | **Yes (file fails -> memory)** | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A |
| Max session cap | **1000 (prevents memory bloat)** | N/A | Unknown | N/A | N/A | N/A | N/A | N/A | N/A |
| | | | | | | | | | |
| **OPERATIONS** | | | | | | | | | |
| Total operations | **8** | 1 | 2 | 1 | 1 | 2 | 3 | 2 | 2 |
| Redact | **Yes** | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Restore | **Yes** | No | Yes | No | No | Separate tool | Complex | No | No |
| Detect (scan only) | **Yes** | No | No | No | No | Yes | Yes | Yes | Yes |
| Verify (leak check) | **Yes** | No | No | No | No | No | No | No | No |
| Classify (sensitivity labels) | **Yes (4 levels + escalation)** | No | No | No | No | No | Yes | No | No |
| Purge (GDPR Art.17) | **Yes** | No | No | No | No | No | No | No | No |
| Stats (vault monitoring) | **Yes** | No | No | No | No | No | N/A | No | No |
| ROPA Report (GDPR Art.30) | **Yes** | No | No | No | No | No | No | No | No |
| | | | | | | | | | |
| **SECURITY** | | | | | | | | | |
| Prompt injection detection | **Yes (25+ patterns, 6 categories)** | Yes | No | No | Yes (API) | No | No | No | No |
| Injection scoring (BLOCK/FLAG) | **Yes (composite threat score)** | Basic | No | No | Yes | No | No | No | No |
| Base64 payload detection | **Yes** | No | No | No | Unknown | No | No | No | No |
| Zero-width char detection | **Yes** | No | No | No | No | No | No | No | No |
| ReDoS protection | **Yes (isSafeRegex validator)** | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A |
| Circuit breaker (Presidio) | **Yes (per-URL, auto-reset)** | N/A | No | N/A | N/A | N/A | N/A | N/A | N/A |
| Atomic file writes | **Yes (write-then-rename)** | N/A | Unknown | N/A | N/A | N/A | N/A | N/A | N/A |
| PII never in audit reports | **Yes (always ***) ** | N/A | Unknown | N/A | N/A | N/A | Configurable | Configurable | Configurable |
| | | | | | | | | | |
| **COMPLIANCE** | | | | | | | | | |
| GDPR ready | **Yes** | Partial | Yes | Partial | Partial | Yes | Yes | Yes | Yes |
| HIPAA ready | **Yes** | No | No | Yes | No | Partial | Yes | Yes | Yes |
| CCPA/CPRA | **Yes** | No | No | Unknown | No | Yes | Yes | Yes | Yes |
| PCI-DSS | **Yes (Luhn validated)** | Partial | Presidio | Unknown | No | Partial | Yes | Yes | Partial |
| SOX audit retention | **Yes (7-year JSONL logs)** | No | No | No | No | No | Yes | Unknown | Partial |
| GDPR Art.9 special categories | **Yes (race, religion, political, health, sexual orientation)** | No | No | Unknown | No | Partial | Yes | Yes | Partial |
| GDPR Art.17 right to erasure | **Yes (Purge operation)** | No | No | No | No | No | Yes | Unknown | Partial |
| GDPR Art.30 ROPA | **Yes (auto-generated reports)** | No | No | No | No | No | No | No | No |
| Persistent audit log | **Yes (JSONL, daily rotation)** | No | No | No | No | No | Yes | Yes | Yes |
| Data classification labels | **Yes (4 levels with escalation)** | No | No | No | No | No | Yes | No | Yes |
| | | | | | | | | | |
| **ENTERPRISE** | | | | | | | | | |
| Per-tenant profiles | **Yes** | No | No | No | No | No | Yes | Yes | Yes |
| Enterprise secrets detection | **38 patterns (AWS, GCP, Stripe, JWT, SSH, etc.)** | API keys only | No | No | No | No | Partial | No | Yes |
| Internal hostname detection | **Yes (.internal, .local, .corp, .lan)** | No | No | No | No | No | No | No | No |
| LDAP/AD detection | **Yes (DN + DOMAIN\user)** | No | No | No | No | No | No | No | No |
| Database conn string detection | **Yes (JDBC, MongoDB, PostgreSQL, etc.)** | No | No | No | No | No | No | No | No |
| Env variable secrets | **Yes (DATABASE_URL, DB_PASSWORD, etc.)** | No | No | No | No | No | No | No | No |
| AI Agent compatible | **Yes (usableAsTool)** | Yes | No | No | No | No | N/A | N/A | N/A |
| Optional NLP upgrade | **Yes (Presidio Docker)** | N/A | Mandatory | N/A | N/A | Native | Native | Native | Native |
| | | | | | | | | | |
| **DATA PROCESSING** | | | | | | | | | |
| Processing location | **100% local** | LLM API call | Docker local | **Cloud API** | **Cloud API** | Local (Docker) | **Google Cloud** | Local | **Cloud** |
| Data leaves server | **Never** | Yes (to LLM) | No | **Yes** | **Yes** | No | **Yes** | No | **Yes** |
| External dependency | **None (Presidio optional)** | LLM provider | Docker (mandatory) | Aparavi API | PromptShield API | Docker + Python | Google Cloud | Docker | Nightfall Cloud |
| Processing speed | **Milliseconds** | 8-25 minutes | Seconds | API latency | API latency | Seconds | API latency | Seconds | API latency |
| Handles structured JSON | **Yes (recursive)** | Basic | Basic | Unknown | Basic | Text only | Yes | Yes | Yes |
| Semantic field names (15 langs) | **Yes** | No | No | No | No | No | No | No | No |
| Context-aware ambiguous fields | **Yes** | No | No | No | No | No | No | No | No |
| | | | | | | | | | |
| **TESTING & QUALITY** | | | | | | | | | |
| Test suites | **12** | Unknown | Unknown | Unknown | Unknown | Yes | N/A | Unknown | N/A |
| Total tests | **426** | Unknown | Unknown | Unknown | Unknown | Yes | N/A | Unknown | N/A |
| Security audit (multi-persona) | **Yes (10 personas)** | Unknown | Unknown | No | No | Community | Internal | Internal | SOC 2 |
| Open source | **FUCL (free to use)** | n8n license | Proprietary | Proprietary | Proprietary | MIT | Proprietary | Proprietary | Proprietary |
| TypeScript strict mode | **Yes** | Yes | Unknown | Unknown | Unknown | Python | N/A | N/A | N/A |

---

## The Numbers That Matter

| Metric | Redactor | Best Alternative |
|--------|----------|-----------------|
| PII pattern count | **217** | Google DLP: 150 |
| Redaction modes | **7** | Google DLP: 8 |
| Operations | **8** | Google DLP: 3 |
| Countries | **35+** | Private AI: 50+ |
| Languages (semantic) | **15** | None: 0 |
| Name dictionary | **15,875** | None: 0 |
| Tests | **426** | Presidio: unknown |
| Price | **$0** | SecureNode: $149 |
| Data leaves server | **Never** | Aparavi/Nightfall: Always |
| Setup time | **30 seconds** | Google DLP: hours |
| Docker required | **No** | SecureNode: Yes |
| API key required | **No** | Aparavi/PromptLock: Yes |

---

## What Only Redactor Can Do (No Competitor Matches)

### 1. Semantic Field-Name Detection
When the field is called `Gehalt`, `salaire`, `stipendio`, or `salary` in any of 15 languages, Redactor knows it's compensation data and redacts the value. **No other tool does this.**

### 2. Context-Aware Ambiguous Field Detection
When `{ id: "D41BRX4M", name: "Amelia", email: "a@b.com" }` is processed, Redactor sees that `name` and `email` confirm this is a person record, so the ambiguous `id` field gets redacted too. **No other tool does this.**

### 3. Reversible Vault with AES-256-GCM Encryption
Strip PII before the LLM, restore it after, with the mapping encrypted at rest so even filesystem access can't leak the data. **No other n8n tool combines all three.**

### 4. 7 Redaction Modes Including Blackout and Pseudonymization
Token, Mask, Hash, Redact, Pseudonymize (fake realistic data), Blackout (████████ visual bars), Remove (complete deletion). **No other n8n tool offers all 7.**

### 5. Prompt Injection + PII Protection in One Node
Detect jailbreaks, instruction overrides, delimiter escapes, encoded payloads, AND 217+ PII types in a single node. **Guardrails does injection but not PII restoration. PromptLock does injection but needs an external API.**

### 6. GDPR Art.30 ROPA Report Generation
Auto-generates Records of Processing Activities covering all 8 fields required by Article 30(1). **No other n8n tool or even most enterprise tools do this.**

### 7. 15,875-Name Dictionary Across 20 Countries
Detects person names in free text without NLP models. Covers US, UK, Germany, France, Spain, Italy, Netherlands, Poland, Turkey, Arabic, India, China, Japan, Korea, Brazil, Russia, Sweden, Norway, Denmark, Finland. **No regex-based tool has this.**

---

## Cost Comparison (Annual for a 10-person team)

| Tool | Annual Cost | What you get |
|------|-----------|-------------|
| **Redactor** | **$0** | Everything listed above |
| SecureNode | $149 (one-time) | Presidio wrapper, 2 operations, no encryption |
| Nightfall AI | $480 - $3,000 | Cloud SaaS DLP, data leaves server |
| Google Cloud DLP | $1,000 - $10,000+ | Pay-per-GB, data goes to Google |
| Private AI | $46,000 | Maximum accuracy, on-premise, 52 languages |
| OneTrust | $24,000+ | GDPR compliance platform (not PII redaction) |

---

## Compliance Coverage Matrix

| Regulation | Article/Section | Redactor | Guardrails | SecureNode | Google DLP |
|-----------|----------------|----------|-----------|-----------|-----------|
| GDPR Art.4(5) Pseudonymization | Data processing | **Yes (pseudonymize mode)** | No | No | Yes (FPE) |
| GDPR Art.9 Special categories | Race, religion, health, etc. | **Yes (explicit patterns)** | No | Partial | Yes |
| GDPR Art.17 Right to erasure | Data deletion | **Yes (Purge operation)** | No | No | Yes |
| GDPR Art.25 Data protection by design | Technical measures | **Yes (vault, encryption, audit)** | Partial | Partial | Yes |
| GDPR Art.30 Records of processing | ROPA documentation | **Yes (auto-generated)** | No | No | No |
| GDPR Art.33 Breach notification | 72-hour reporting | **Audit log provides evidence** | No | No | Yes |
| HIPAA Safe Harbor | 18 PHI identifiers | **All 18 covered** | 4 covered | Partial | Yes |
| HIPAA Audit Trail | 6-year retention | **Yes (JSONL logs)** | No | No | Yes |
| PCI-DSS | Cardholder data | **Yes (Luhn, expiry, CVV)** | CC only | Partial | Yes |
| SOX | 7-year audit retention | **Yes (configurable)** | No | No | Yes |
| CCPA/CPRA | Consumer data rights | **Yes** | No | No | Yes |

---

## Why Consultants Choose Redactor

### The Problem
Your client asks: "We want to use AI for customer support, but GDPR says we can't send customer data to OpenAI."

### With Guardrails
You tell the client: "We can strip the PII, but the AI response will say '[PHONE_NUMBER]' instead of the actual number. The customer experience is broken."

### With Redactor
You tell the client: "We strip the PII, the AI processes it, and we put the real data back. The customer gets a perfect response. The AI never saw the real data. Here's the audit log proving it. Here's the GDPR Art.30 compliance report. The vault is encrypted with AES-256. Total cost: zero."

**That's why Redactor wins.**

---

*Document prepared by next8n. For commercial licensing, partnerships, or custom development: [services.next8n.com](https://services.next8n.com)*
