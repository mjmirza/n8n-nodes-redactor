# Enhanced NLP Detection with Presidio (Optional)

## What is Presidio?

Microsoft Presidio is an open-source (MIT license) NLP-based PII detection engine. It uses machine learning models (spaCy) to detect person names, locations, and organizations in free text — something regex alone cannot do reliably.

**Example: What Presidio catches that regex misses:**
```
"Spoke with Sarah Johnson about her account at Goldman Sachs"
```
- **Regex only:** Misses "Sarah Johnson" (no title prefix) and "Goldman Sachs" (organization)
- **With Presidio:** Detects both as PERSON and ORGANIZATION with 0.85+ confidence

## Is Presidio required?

**No.** The Redactor node works perfectly without Presidio. It uses 200+ regex patterns, semantic field-name detection, context-aware analysis, and a name dictionary to detect PII.

Presidio is an **optional upgrade** for users who need NLP-level accuracy in free-text fields.

## Quick Setup (One Command)

```bash
docker run -d --name presidio -p 127.0.0.1:5002:3000 mcr.microsoft.com/presidio-analyzer
```

Verify it's running:
```bash
curl http://localhost:5002/health
```

Expected response: `{"status": "healthy"}`

## Setup with docker-compose (alongside n8n)

```yaml
version: "3.8"
services:
  n8n:
    image: n8nio/n8n
    ports:
      - "5678:5678"
    volumes:
      - n8n_data:/home/node/.n8n

  presidio:
    image: mcr.microsoft.com/presidio-analyzer
    ports:
      - "127.0.0.1:5002:3000"
    restart: unless-stopped

volumes:
  n8n_data:
```

Start everything:
```bash
docker-compose up -d
```

In the Redactor node, set Presidio URL to:
- **docker-compose:** `http://presidio:3000` (use the service name)
- **standalone Docker:** `http://localhost:5002`

## How to enable in the Redactor node

1. Open the Redactor node settings
2. Set operation to **Redact**
3. Toggle **"Enhanced NLP Detection (Optional)"** to ON
4. Enter the Presidio URL (default: `http://localhost:5002`)
5. Select the language of your text
6. Run your workflow

The node will:
1. First run all regex patterns (fast, local)
2. Then send remaining text to Presidio for NLP analysis
3. Merge the results — no duplicates
4. If Presidio is unreachable, silently fall back to regex-only (no crash)

## Supported languages

| Language | Presidio Code | Requires |
|----------|--------------|----------|
| English | `en` | Default spaCy model (included) |
| German | `de` | `de_core_news_lg` model |
| French | `fr` | `fr_core_news_lg` model |
| Spanish | `es` | `es_core_news_lg` model |
| Italian | `it` | `it_core_news_lg` model |
| Portuguese | `pt` | `pt_core_news_lg` model |
| Dutch | `nl` | `nl_core_news_lg` model |
| Polish | `pl` | `pl_core_news_lg` model |

For non-English languages, you may need to build a custom Presidio Docker image with the appropriate spaCy model. See: https://microsoft.github.io/presidio/analyzer/languages/

## What Presidio detects

| Entity Type | Description |
|-------------|-------------|
| PERSON | Person names (first, last, full) |
| LOCATION | Addresses, cities, countries |
| ORGANIZATION | Company names, institutions |
| EMAIL_ADDRESS | Email addresses |
| PHONE_NUMBER | Phone numbers |
| CREDIT_CARD | Credit card numbers |
| IBAN_CODE | International bank account numbers |
| US_SSN | US Social Security Numbers |
| US_PASSPORT | US passport numbers |
| US_DRIVER_LICENSE | US driver license numbers |
| UK_NHS | UK NHS numbers |
| DATE_TIME | Dates and times |
| IP_ADDRESS | IP addresses |
| URL | Web URLs |
| NRP | Nationality, religion, political group |
| MEDICAL_LICENSE | Medical license numbers |
| And 20+ more... | Country-specific IDs |

## Performance

- Presidio adds ~100-500ms per text field (depending on text length)
- The Redactor node processes Presidio calls per-field, not per-character
- For large datasets (1000+ items), consider using regex-only mode for speed
- Presidio Docker container uses ~500MB RAM

## Security

- All processing is local — text is sent to `localhost`, never to the cloud
- No authentication required (localhost only)
- No data is stored by Presidio — it's stateless
- The Docker container can be restricted to localhost binding only

## Troubleshooting

| Issue | Solution |
|-------|---------|
| "Enhanced detection not working" | Check if Presidio container is running: `docker ps` |
| "Connection refused" | Verify port mapping: `docker run -p 127.0.0.1:5002:3000 ...` |
| "No entities detected" | Check language setting matches text language |
| "Slow processing" | Presidio adds latency; for speed, use regex-only mode |
| "Node works without Presidio" | Correct! Presidio is optional. Node falls back silently. |
