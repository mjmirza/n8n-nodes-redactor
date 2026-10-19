import {
  IDataObject,
  IExecuteFunctions,
  INodeExecutionData,
  INodeType,
  INodeTypeDescription,
  NodeOperationError,
} from 'n8n-workflow';

import { getPatternOptions } from './patterns';
import { createVault } from './vault';
import { redactValue, restoreValue, buildReport, enhanceWithPresidio } from './engine';
import {
  CustomPattern,
  RedactionContext,
  RedactionHit,
  RedactionMode,
  VaultStorage,
} from './types';
import { classifyData } from './classification';
import { scanForInjection } from './injection';
import { writeAuditLog } from './audit';
import { resetCircuitBreaker } from './presidio';
import { loadProfile } from './profiles';
import { generateRopaRecord } from './ropa';

/**
 * Curated high-precision pattern set. These patterns have low false-positive
 * rates and are safe to enable by default. Excludes broad patterns like
 * bare digit-only matches (postalCodeDE, postalCodeAT, bsnNL, etc.)
 */
const RECOMMENDED_PATTERNS = [
  // Contact
  'email', 'phone', 'phoneDE', 'phoneUK', 'phoneAT', 'phoneCH', 'phoneFR',
  'phoneNL', 'phoneES', 'phoneIT', 'phoneAU', 'phoneIN', 'phoneBR',
  // Identity - high precision
  'personName', 'ssn', 'itinUS', 'sinCA', 'ninoUK', 'passportUS', 'passportEU',
  'passportDE', 'nationalIdDE', 'nhsNumber', 'taxIdUS', 'taxIdDE',
  'sozialversicherungDE', 'ahvCH', 'nationalIdFR', 'codiceFiscaleIT',
  'dniES', 'nieES', 'nifES', 'peselPL', 'bsnNL', 'hetuFI', 'ppsIE',
  'nricSG', 'panIN', 'cpfBR', 'driverLicenseCtx', 'employeeIdCtx',
  'fullNameCtx', 'mothersMaidenName', 'passportCtx',
  // Financial - validated
  'creditCard', 'amex', 'iban', 'bic', 'vatEU', 'abaRouting', 'sortCodeUK',
  'cardExpiry', 'cvvCtx', 'bankAccountCtx', 'insurancePolicyCtx',
  'salaryCtx', 'loyaltyNumberCtx',
  // Network
  'ipv4', 'ipv6', 'macAddress', 'ipv4Port', 'url', 'privateIp',
  // Location - validated formats
  'postalCodeUK', 'postalCodeNL', 'postalCodePL', 'postalCodeCA',
  'postalCodeJP', 'gpsCoordinates',
  'addressDE', 'addressLabeledDE', 'addressLabeledEN', 'addressLabeledFR',
  'addressEUStreetNumber',
  // Dates
  'dateSlash', 'dateDash', 'dateDot', 'dateOfBirth',
  // Medical
  'medicalRecordNumber', 'deaNumber', 'npiNumber', 'rxNumber',
  'healthPlanCtx', 'bloodTypeCtx',
  // Enterprise secrets
  'internalHostname', 'uncPath', 'ldapDN', 'adUsername',
  'dbConnectionString', 'connStringKV',
  'awsAccessKey', 'gcpApiKey', 'stripeKey', 'openaiKey', 'githubToken',
  'slackToken', 'bearerToken', 'jwtToken', 'pemPrivateKey', 'sshPublicKey',
  'genericSecret', 'azureKey', 'slackWebhook',
  'sendgridKey', 'twilioKey', 'anthropicKey', 'gitlabToken',
  'x509Certificate', 'pgpPrivateKey', 'envSecrets',
  // Crypto
  'bitcoinAddress', 'ethereumAddress',
  // Vehicle
  'vin',
  // Biometric
  'uuid', 'imei', 'iccid',
];

export class PiiRedactor implements INodeType {
  description: INodeTypeDescription = {
    displayName: 'Redactor',
    name: 'redactor',
    icon: 'file:redact.png',
    group: ['transform'],
    version: 1,
    subtitle: '={{$parameter["operation"]}}',
    usableAsTool: true,
    description:
      'Redact and remove sensitive data, PII, personal information, emails, phone numbers, addresses, IBAN, credit cards, names before sending to LLM. Anonymize, mask, sanitize, scrub customer data. Restore original values after. GDPR HIPAA CCPA compliant. Data privacy, data protection, data masking, data anonymization.',
    defaults: {
      name: 'Redactor',
    },
    inputs: ['main'],
    // @ts-ignore dynamic outputs using n8n's function pattern (same as Switch node)
    outputs: `={{((parameters) => parameters["includeReport"] ? [{ type: "main", displayName: "Data" }, { type: "main", displayName: "Report" }] : [{ type: "main", displayName: "Data" }])($parameter)}}`,

    properties: [
      // ═══════════════════════════════════════
      // OPERATION
      // ═══════════════════════════════════════
      {
        displayName: 'Operation',
        name: 'operation',
        type: 'options',
        noDataExpression: true,
        options: [
          {
            name: 'Redact',
            value: 'redact',
            description: 'Detect and replace PII with tokens/masks/hashes',
          },
          {
            name: 'Restore',
            value: 'restore',
            description: 'Replace tokens back with original PII values from vault',
          },
          {
            name: 'Detect (Scan Only)',
            value: 'detect',
            description: 'Scan for PII without modifying the data. Returns a report of what was found.',
          },
          {
            name: 'Verify',
            value: 'verify',
            description: 'Re-scan redacted data to confirm no PII leaked through. Returns pass/fail.',
          },
          {
            name: 'Classify',
            value: 'classify',
            description: 'Assign sensitivity labels (PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED) based on PII found.',
          },
          {
            name: 'Purge',
            value: 'purge',
            description: 'Delete vault sessions. Supports GDPR right to erasure.',
          },
          {
            name: 'Stats',
            value: 'stats',
            description: 'List active vault sessions and entry counts',
          },
        ],
        default: 'redact',
      },

      // ═══════════════════════════════════════
      // SESSION ID (shared between Redact & Restore)
      // ═══════════════════════════════════════
      {
        displayName: 'Session ID',
        name: 'sessionId',
        type: 'string',
        default: '={{$execution.id}}',
        description:
          'Unique ID linking a Redact and Restore step. Defaults to the current execution ID. Use the same value in both the Redact and Restore nodes.',
        required: true,
        displayOptions: {
          show: {
            operation: ['redact', 'restore'],
          },
        },
      },
      {
        displayName: 'Session ID to Purge',
        name: 'purgeSessionId',
        type: 'string',
        default: '',
        description: 'The session ID to purge. Leave empty is not needed when purging all.',
        displayOptions: {
          show: {
            operation: ['purge'],
            purgeScope: ['specific'],
          },
        },
      },

      // ═══════════════════════════════════════
      // REDACTION MODE
      // ═══════════════════════════════════════
      {
        displayName: 'Redaction Mode',
        name: 'redactionMode',
        type: 'options',
        displayOptions: {
          show: {
            operation: ['redact'],
          },
        },
        options: [
          {
            name: 'Token (Reversible)',
            value: 'token',
            description:
              'Replace PII with [EMAIL_0], [PHONE_1] etc. Restore via vault later. Best for LLM workflows.',
          },
          {
            name: 'Mask (Partial)',
            value: 'mask',
            description:
              'Show partial values: j***@e***.com, ****-****-****-1234. NOT reversible.',
          },
          {
            name: 'Hash (Deterministic)',
            value: 'hash',
            description:
              'Replace with truncated SHA-256 hash. Deterministic but NOT reversible.',
          },
          {
            name: 'Redact (Full Removal)',
            value: 'redact',
            description: 'Replace with [REDACTED]. NOT reversible.',
          },
          {
            name: 'Pseudonymize (Fake Realistic Data)',
            value: 'pseudonymize',
            description: 'Replace with realistic fake data (names, emails, phones). Preserves format. Reversible via vault. GDPR-compliant pseudonymization.',
          },
          {
            name: 'Blackout (Visual Black Bars)',
            value: 'blackout',
            description: 'Replace with black bars (████████). Same length as original. NOT reversible. Like physical document redaction.',
          },
          {
            name: 'Remove (Complete Deletion)',
            value: 'remove',
            description: 'Completely remove PII, leaving no trace. NOT reversible. The value is replaced with an empty string.',
          },
        ],
        default: 'token',
      },

      // ═══════════════════════════════════════
      // DETECTION SCOPE
      // ═══════════════════════════════════════
      {
        displayName: 'Detection Scope',
        name: 'detectionScope',
        type: 'options',
        displayOptions: {
          show: {
            operation: ['redact'],
          },
        },
        options: [
          {
            name: 'Recommended (High Precision)',
            value: 'recommended',
            description: 'Curated set of high-precision patterns. Best for most workflows. Minimal false positives.',
          },
          {
            name: 'All Patterns (Maximum Coverage)',
            value: 'all',
            description: 'All 200+ patterns including broad ones. May produce false positives on short numbers.',
          },
          {
            name: 'Select Specific Types',
            value: 'select',
            description: 'Choose which specific data types to detect.',
          },
        ],
        default: 'recommended',
        description: 'Detect all sensitive data types automatically, or select specific types to scan for.',
      },

      // ═══════════════════════════════════════
      // PII TYPE SELECTION (only shown when scope is 'select')
      // ═══════════════════════════════════════
      {
        displayName: 'PII Types to Detect',
        name: 'piiTypes',
        type: 'multiOptions',
        displayOptions: {
          show: {
            operation: ['redact'],
            detectionScope: ['select'],
          },
        },
        options: getPatternOptions(),
        default: [
          'email',
          'phone',
          'phoneDE',
          'phoneUK',
          'personName',
          'ssn',
          'ninoUK',
          'creditCard',
          'iban',
          'bic',
          'ipv4',
          'privateIp',
          'addressDE',
          'addressLabeledEN',
          'addressLabeledDE',
          'awsAccessKey',
          'genericSecret',
          'dbConnectionString',
          'jwtToken',
          'pemPrivateKey',
        ],
        description: 'Select which PII types to detect. Each type uses optimized regex with validation where possible.',
      },

      // ═══════════════════════════════════════
      // DEDUPLICATION
      // ═══════════════════════════════════════
      {
        displayName: 'Deduplicate',
        name: 'dedup',
        type: 'boolean',
        displayOptions: {
          show: {
            operation: ['redact'],
            redactionMode: ['token'],
          },
        },
        default: true,
        description:
          'When enabled, the same PII value always gets the same token. This preserves relationships in the data (e.g. if an email appears in 3 fields, all 3 get [EMAIL_0]).',
      },

      // ═══════════════════════════════════════
      // FIELD TARGETING
      // ═══════════════════════════════════════
      {
        displayName: 'Field Targeting',
        name: 'fieldMode',
        type: 'options',
        displayOptions: {
          show: {
            operation: ['redact'],
          },
        },
        options: [
          {
            name: 'All Fields',
            value: 'all',
            description: 'Scan every field in the JSON data',
          },
          {
            name: 'Allowlist -Only These Fields',
            value: 'allowlist',
            description: 'Only scan the fields listed below',
          },
          {
            name: 'Denylist -Skip These Fields',
            value: 'denylist',
            description: 'Scan everything except the fields listed below',
          },
        ],
        default: 'all',
        description:
          'Control which JSON fields get scanned. Use allowlist to target specific fields, or denylist to skip fields like internal IDs.',
      },
      {
        displayName: 'Field Rules',
        name: 'fieldRules',
        type: 'fixedCollection',
        typeOptions: {
          multipleValues: true,
        },
        displayOptions: {
          show: {
            operation: ['redact'],
            fieldMode: ['allowlist', 'denylist'],
          },
        },
        default: {},
        options: [
          {
            name: 'rules',
            displayName: 'Rule',
            values: [
              {
                displayName: 'Field Path',
                name: 'field',
                type: 'string',
                default: '',
                placeholder: 'e.g. user.email, contacts[*].phone, *.address',
                description:
                  'JSON path to target. Supports dot notation and wildcards: "user.email", "*.phone", "items[*].name"',
              },
            ],
          },
        ],
      },

      // ═══════════════════════════════════════
      // CONFIDENCE THRESHOLD
      // ═══════════════════════════════════════
      {
        displayName: 'Confidence Threshold',
        name: 'confidenceThreshold',
        type: 'number',
        displayOptions: {
          show: {
            operation: ['redact'],
          },
        },
        typeOptions: {
          minValue: 0,
          maxValue: 1,
          numberPrecision: 2,
        },
        default: 0,
        description: 'Only redact detections with confidence score above this threshold (0.0 to 1.0). Set to 0 to redact everything. Set to 0.7 to only redact high-confidence matches. Checksum-validated patterns score 0.95, regex-only patterns score 0.60-0.85.',
      },

      // ═══════════════════════════════════════
      // ALLOW LIST (bypass specific values)
      // ═══════════════════════════════════════
      {
        displayName: 'Allow List (Never Redact)',
        name: 'allowList',
        type: 'fixedCollection',
        typeOptions: {
          multipleValues: true,
        },
        displayOptions: {
          show: {
            operation: ['redact'],
          },
        },
        default: {},
        options: [
          {
            name: 'entries',
            displayName: 'Entry',
            values: [
              {
                displayName: 'Value',
                name: 'value',
                type: 'string',
                default: '',
                placeholder: 'e.g. @mycompany.com, +1-800-555-0100, support@acme.com',
                description: 'Value to never redact, even if a pattern matches it',
              },
              {
                displayName: 'Match Type',
                name: 'type',
                type: 'options',
                options: [
                  { name: 'Exact Match', value: 'exact' },
                  { name: 'Contains', value: 'contains' },
                  { name: 'Regex', value: 'regex' },
                ],
                default: 'contains',
                description: 'How to match the value',
              },
            ],
          },
        ],
        description: 'Values that should NEVER be redacted. Use this for company email domains, public phone numbers, or known-safe identifiers.',
      },

      // ═══════════════════════════════════════
      // DENY LIST (always redact specific values)
      // ═══════════════════════════════════════
      {
        displayName: 'Deny List (Always Redact)',
        name: 'denyList',
        type: 'fixedCollection',
        typeOptions: {
          multipleValues: true,
        },
        displayOptions: {
          show: {
            operation: ['redact'],
          },
        },
        default: {},
        options: [
          {
            name: 'entries',
            displayName: 'Entry',
            values: [
              {
                displayName: 'Value',
                name: 'value',
                type: 'string',
                default: '',
                placeholder: 'e.g. Project Falcon, INTERNAL-2024-SECRET',
                description: 'Value to ALWAYS redact, even if no pattern matches it',
              },
              {
                displayName: 'Match Type',
                name: 'type',
                type: 'options',
                options: [
                  { name: 'Exact Match', value: 'exact' },
                  { name: 'Contains', value: 'contains' },
                  { name: 'Regex', value: 'regex' },
                ],
                default: 'exact',
                description: 'How to match the value',
              },
            ],
          },
        ],
        description: 'Values that should ALWAYS be redacted, regardless of whether any pattern matches. Use for project codenames, internal secrets, or business-specific sensitive terms.',
      },

      // ═══════════════════════════════════════
      // CUSTOM PATTERNS
      // ═══════════════════════════════════════
      {
        displayName: 'Custom Patterns',
        name: 'customPatterns',
        type: 'fixedCollection',
        typeOptions: {
          multipleValues: true,
        },
        displayOptions: {
          show: {
            operation: ['redact'],
          },
        },
        default: {},
        options: [
          {
            name: 'patterns',
            displayName: 'Pattern',
            values: [
              {
                displayName: 'Label',
                name: 'label',
                type: 'string',
                default: '',
                placeholder: 'e.g. ORDER_ID, SKU, TICKET',
                description: 'Label for the redacted placeholder',
              },
              {
                displayName: 'Regex',
                name: 'regex',
                type: 'string',
                default: '',
                placeholder: 'e.g. ORD-\\d{6}, SKU-[A-Z0-9]{8}',
                description: 'Regular expression to match this pattern',
              },
              {
                displayName: 'Category',
                name: 'category',
                type: 'options',
                options: [
                  { name: 'Identity', value: 'identity' },
                  { name: 'Financial', value: 'financial' },
                  { name: 'Contact', value: 'contact' },
                  { name: 'Network', value: 'network' },
                  { name: 'Location', value: 'location' },
                  { name: 'Medical', value: 'medical' },
                  { name: 'Other', value: 'other' },
                ],
                default: 'identity',
                description: 'Category for audit reporting',
              },
            ],
          },
        ],
        description: 'Add your own regex patterns for business-specific identifiers (order IDs, SKUs, ticket numbers, etc.)',
      },

      // ═══════════════════════════════════════
      // PROMPT INJECTION DETECTION
      // ═══════════════════════════════════════
      {
        displayName: 'Prompt Injection Detection',
        name: 'promptInjection',
        type: 'boolean',
        displayOptions: {
          show: {
            operation: ['redact'],
          },
        },
        default: false,
        description: 'Scan input data for prompt injection attempts (jailbreaks, instruction overrides, delimiter escapes, encoded payloads) before sending to an LLM. Detected injections are flagged in the output.',
      },

      // ═══════════════════════════════════════
      // AUDIT LOG
      // ═══════════════════════════════════════
      {
        displayName: 'Audit Log',
        name: 'auditLog',
        type: 'boolean',
        displayOptions: {
          show: {
            operation: ['redact', 'detect'],
          },
        },
        default: false,
        description: 'Write a persistent JSONL audit log of all redaction activity. Stored in ~/.n8n/pii-audit/. Compliant with GDPR Art.30, HIPAA, SOX, PCI DSS retention requirements.',
      },

      // ═══════════════════════════════════════
      // ENHANCED NLP DETECTION (Optional Presidio)
      // ═══════════════════════════════════════
      {
        displayName: 'Enhanced NLP Detection (Optional)',
        name: 'enablePresidio',
        type: 'boolean',
        displayOptions: {
          show: {
            operation: ['redact'],
          },
        },
        default: false,
        description: 'Enable NLP-based detection using Microsoft Presidio. Catches person names, locations, and organizations in free text that regex cannot detect. Requires a Presidio Docker container running locally. Setup: docker run -d -p 5002:3000 mcr.microsoft.com/presidio-analyzer',
      },
      {
        displayName: 'Presidio URL',
        name: 'presidioUrl',
        type: 'string',
        displayOptions: {
          show: {
            operation: ['redact'],
            enablePresidio: [true],
          },
        },
        default: 'http://localhost:5002',
        placeholder: 'http://localhost:5002',
        description: 'URL of the Presidio Analyzer service. Default: http://localhost:5002. If using docker-compose, use the service name: http://presidio:3000',
      },
      {
        displayName: 'Presidio Language',
        name: 'presidioLanguage',
        type: 'options',
        displayOptions: {
          show: {
            operation: ['redact'],
            enablePresidio: [true],
          },
        },
        options: [
          { name: 'English', value: 'en' },
          { name: 'German (Deutsch)', value: 'de' },
          { name: 'French (Francais)', value: 'fr' },
          { name: 'Spanish (Espanol)', value: 'es' },
          { name: 'Italian (Italiano)', value: 'it' },
          { name: 'Portuguese (Portugues)', value: 'pt' },
          { name: 'Dutch (Nederlands)', value: 'nl' },
          { name: 'Polish (Polski)', value: 'pl' },
        ],
        default: 'en',
        description: 'Language of the text being analyzed. Presidio uses language-specific NLP models for entity detection.',
      },

      // ═══════════════════════════════════════
      // VAULT SETTINGS
      // ═══════════════════════════════════════
      {
        displayName: 'Vault Storage',
        name: 'vaultStorage',
        type: 'options',
        displayOptions: {
          show: {
            operation: ['redact', 'restore', 'stats', 'purge'],
          },
        },
        options: [
          {
            name: 'File-Based (Recommended, Persistent)',
            value: 'file',
          },
          {
            name: 'In-Memory (Fast, Lost on Restart)',
            value: 'memory',
          },
        ],
        default: 'file',
        description:
          'File-based (recommended): Persists to disk, survives restarts, no memory bloat. Stored in ~/.n8n/pii-vault/. In-memory: Faster but lost on restart, capped at 1000 sessions to prevent memory bloat.',
      },
      {
        displayName: 'Vault Directory',
        name: 'vaultDir',
        type: 'string',
        displayOptions: {
          show: {
            operation: ['redact', 'restore', 'stats', 'purge'],
            vaultStorage: ['file'],
          },
        },
        default: '',
        placeholder: '/path/to/vault (default: ~/.n8n/pii-vault/)',
        description: 'Custom directory for file-based vault storage',
      },
      {
        displayName: 'Vault Encryption Passphrase',
        name: 'vaultPassphrase',
        type: 'string',
        typeOptions: {
          password: true,
        },
        displayOptions: {
          show: {
            operation: ['redact', 'restore', 'stats', 'purge'],
            vaultStorage: ['file'],
          },
        },
        default: '',
        description: 'Encrypt vault files at rest with AES-256-GCM. Leave empty for no encryption. When set, vault files cannot be read without this passphrase. Each tenant should use a different passphrase for complete isolation.',
      },
      {
        displayName: 'Session TTL (minutes)',
        name: 'sessionTtl',
        type: 'number',
        displayOptions: {
          show: {
            operation: ['redact'],
          },
        },
        default: 60,
        description:
          'Auto-expire vault sessions after this many minutes. Set to 0 for no expiry. Prevents vault from growing unbounded.',
      },

      // ═══════════════════════════════════════
      // PURGE OPTIONS
      // ═══════════════════════════════════════
      {
        displayName: 'Purge Scope',
        name: 'purgeScope',
        type: 'options',
        displayOptions: {
          show: {
            operation: ['purge'],
          },
        },
        options: [
          {
            name: 'Purge All Sessions',
            value: 'all',
            description: 'Delete all vault sessions. GDPR right to erasure.',
          },
          {
            name: 'Purge Specific Session',
            value: 'specific',
            description: 'Delete a specific session by ID.',
          },
        ],
        default: 'all',
      },

      // ═══════════════════════════════════════
      // RESTORE OPTIONS
      // ═══════════════════════════════════════
      {
        displayName: 'Delete Vault After Restore',
        name: 'deleteAfterRestore',
        type: 'boolean',
        displayOptions: {
          show: {
            operation: ['restore'],
          },
        },
        default: true,
        description:
          'Delete the vault session after restoring. Disable for multi-step workflows that need multiple restores.',
      },

      // ═══════════════════════════════════════
      // AUDIT REPORT
      // ═══════════════════════════════════════
      {
        displayName: 'Include Audit Report',
        name: 'includeReport',
        type: 'boolean',
        displayOptions: {
          show: {
            operation: ['redact', 'detect'],
          },
        },
        default: false,
        description:
          'When enabled, adds a second output with an audit report listing all PII detected, categories, and counts. Useful for compliance logging.',
      },
    ],
  };

  async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
    const items = this.getInputData();
    // Aggregate outputs (summaries, reports) link back to every input item.
    const allPaired = items.map((_, i) => ({ item: i }));
    const operation = this.getNodeParameter('operation', 0) as string;

    // Reset Presidio circuit breaker at start of each execution
    resetCircuitBreaker();

    // ─── DETECT / VERIFY (zero-config, scans everything) ──
    if (operation === 'detect' || operation === 'verify') {
      // Detect and Verify always scan ALL 216 patterns.
      // No parameters needed. Simple, reliable, no "Could not get parameter".
      const enabledPatterns = getPatternOptions().map((p) => p.value);
      const customPatterns: CustomPattern[] = [];

      const tempVault = createVault('memory');
      const tempSessionId = `${operation}_${Date.now()}`;
      tempVault.getOrCreateSession(tempSessionId, 60000);

      const ctx: RedactionContext = {
        enabledPatterns,
        customPatterns,
        mode: 'token',
        dedup: true,
        fieldRules: [],
        fieldMode: 'all',
        // Verify mode: skip semantic field-name detection.
        // Only check if actual PII VALUES leaked through (regex only).
        skipSemantic: operation === 'verify',
      };

      const allHits: RedactionHit[] = [];
      for (let i = 0; i < items.length; i++) {
        const hits: RedactionHit[] = [];
        redactValue(items[i].json, ctx, tempVault, tempSessionId, hits, i);
        allHits.push(...hits);
      }
      tempVault.deleteSession(tempSessionId);

      if (operation === 'detect') {
        // Always return original data + detection summary as last item
        const returnData: INodeExecutionData[] = items.map((item, i) => ({ json: item.json, pairedItem: { item: i } }));
        const report = buildReport(tempSessionId, allHits);

        // Summary always appended so user sees results
        const summary = {
          _redactorScan: true,
          status: allHits.length === 0 ? 'CLEAN' : 'PII_FOUND',
          totalPiiFound: allHits.length,
          itemsScanned: items.length,
          hitsByCategory: report.hitsByCategory,
          hitsByPattern: report.hitsByPattern,
          timestamp: report.timestamp,
        };

        let includeReport = false;
        try { includeReport = this.getNodeParameter('includeReport', 0, false) as boolean; } catch {}

        if (includeReport) {
          // Full report on second output
          return [returnData, [{ json: { ...summary, hits: report.hits } as unknown as IDataObject, pairedItem: allPaired }]];
        }

        // Append summary as last item in single output
        returnData.push({ json: summary as unknown as IDataObject, pairedItem: allPaired });
        return [returnData];
      }

      // Verify
      const passed = allHits.length === 0;
      const verifyReport = buildReport(tempSessionId, allHits);
      return [[{
        json: {
          verified: passed,
          status: passed ? 'PASS' : 'FAIL',
          leaksFound: allHits.length,
          itemsScanned: items.length,
          message: passed
            ? 'No PII detected in values. Data appears properly redacted.'
            : `Found ${allHits.length} potential PII leak(s). Values contain detectable sensitive data.`,
          hitsByCategory: verifyReport.hitsByCategory,
          hitsByPattern: verifyReport.hitsByPattern,
          leaks: allHits.map((h) => ({
            field: h.field,
            patternLabel: h.patternLabel,
            category: h.category,
            itemIndex: h.itemIndex,
          })),
        } as unknown as IDataObject,
        pairedItem: allPaired,
      }]];
    }

    // ─── CLASSIFY (sensitivity labeling) ──
    if (operation === 'classify') {
      const enabledPatterns = getPatternOptions().map((p) => p.value);
      const tempVault = createVault('memory');
      const tempSessionId = `classify_${Date.now()}`;
      tempVault.getOrCreateSession(tempSessionId, 60000);

      const ctx: RedactionContext = {
        enabledPatterns,
        customPatterns: [],
        mode: 'token',
        dedup: true,
        fieldRules: [],
        fieldMode: 'all',
      };

      const allHits: RedactionHit[] = [];
      for (let i = 0; i < items.length; i++) {
        const hits: RedactionHit[] = [];
        redactValue(items[i].json, ctx, tempVault, tempSessionId, hits, i);
        allHits.push(...hits);
      }
      tempVault.deleteSession(tempSessionId);

      const classification = classifyData(allHits);
      return [[{
        json: {
          ...classification,
          itemsScanned: items.length,
          timestamp: new Date().toISOString(),
        } as unknown as IDataObject,
        pairedItem: allPaired,
      }]];
    }

    // All other operations (redact, restore, stats, purge, classify) use vault
    const vaultStorage = this.getNodeParameter('vaultStorage', 0, 'file') as VaultStorage;
    const vaultDir = this.getNodeParameter('vaultDir', 0, '') as string;
    let vaultPassphrase = '';
    try { vaultPassphrase = this.getNodeParameter('vaultPassphrase', 0, '') as string; } catch { /* not available */ }
    const vault = createVault(vaultStorage, vaultDir || undefined, vaultPassphrase || undefined);

    // ─── STATS ───────────────────────────────
    if (operation === 'stats') {
      vault.cleanup();
      const sessions = vault.listSessions();
      const totalEntries = sessions.reduce((sum, s) => sum + s.entryCount, 0);
      return [[
        {
          json: {
            totalSessions: sessions.length,
            totalEntries,
            vaultStorage: vaultStorage,
            timestamp: new Date().toISOString(),
            sessions: sessions.map((s) => ({
              sessionId: s.sessionId,
              entryCount: s.entryCount,
              createdAt: s.createdAt,
              ttl: s.ttl,
              ttlMinutes: s.ttl > 0 ? Math.round(s.ttl / 60000) : 'no expiry',
            })),
          } as unknown as IDataObject,
          pairedItem: allPaired,
        },
      ]];
    }

    // Only Redact and Restore are bound to a session. Purge and Stats are not.
    let sessionId = '';
    if (operation === 'redact' || operation === 'restore') {
      sessionId = this.getNodeParameter('sessionId', 0) as string;
      if (!sessionId) {
        throw new NodeOperationError(this.getNode(), 'Session ID is required');
      }
    }

    // ─── REDACT ──────────────────────────────
    if (operation === 'redact') {
      const mode = this.getNodeParameter('redactionMode', 0, 'token') as RedactionMode;
      const detectionScope = this.getNodeParameter('detectionScope', 0, 'recommended') as string;
      let enabledPatterns: string[];
      if (detectionScope === 'all') {
        enabledPatterns = getPatternOptions().map((p) => p.value);
      } else if (detectionScope === 'recommended') {
        enabledPatterns = RECOMMENDED_PATTERNS;
      } else {
        enabledPatterns = this.getNodeParameter('piiTypes', 0) as string[];
      }
      const dedup = this.getNodeParameter('dedup', 0, true) as boolean;
      const fieldMode = this.getNodeParameter('fieldMode', 0, 'all') as 'all' | 'allowlist' | 'denylist';
      const sessionTtl = this.getNodeParameter('sessionTtl', 0, 60) as number;
      const includeReport = this.getNodeParameter('includeReport', 0, false) as boolean;

      const customPatternsRaw = this.getNodeParameter('customPatterns', 0, {}) as {
        patterns?: CustomPattern[];
      };
      const customPatterns = customPatternsRaw.patterns ?? [];

      const fieldRulesRaw = this.getNodeParameter('fieldRules', 0, {}) as {
        rules?: Array<{ field: string }>;
      };
      const fieldRules = (fieldRulesRaw.rules ?? []).map((r) => ({
        field: r.field,
        mode: fieldMode === 'allowlist' ? ('include' as const) : ('exclude' as const),
      }));

      // Presidio NLP integration (optional)
      let enablePresidio = false;
      let presidioUrl = '';
      let presidioLanguage = 'en';
      try {
        enablePresidio = this.getNodeParameter('enablePresidio', 0, false) as boolean;
        if (enablePresidio) {
          presidioUrl = this.getNodeParameter('presidioUrl', 0, 'http://localhost:5002') as string;
          presidioLanguage = this.getNodeParameter('presidioLanguage', 0, 'en') as string;
        }
      } catch {
        // Presidio parameters not available
      }

      // Parse allow list
      const allowListRaw = this.getNodeParameter('allowList', 0, {}) as {
        entries?: Array<{ value: string; type: string }>;
      };
      const allowList = (allowListRaw.entries ?? []).map((e) => ({
        value: e.value,
        type: (e.type || 'contains') as 'exact' | 'contains' | 'regex',
      }));

      // Parse deny list
      const denyListRaw = this.getNodeParameter('denyList', 0, {}) as {
        entries?: Array<{ value: string; type: string }>;
      };
      const denyList = (denyListRaw.entries ?? []).map((e) => ({
        value: e.value,
        type: (e.type || 'exact') as 'exact' | 'contains' | 'regex',
      }));

      // Confidence threshold
      const confidenceThreshold = this.getNodeParameter('confidenceThreshold', 0, 0) as number;

      // Initialize vault session
      vault.getOrCreateSession(sessionId, sessionTtl * 60 * 1000);

      const ctx: RedactionContext = {
        enabledPatterns,
        customPatterns,
        mode,
        dedup,
        fieldRules,
        fieldMode,
        allowList,
        denyList,
        confidenceThreshold,
        presidioUrl: enablePresidio ? presidioUrl : undefined,
        presidioLanguage: enablePresidio ? presidioLanguage : undefined,
      };

      const allHits: RedactionHit[] = [];
      const returnData: INodeExecutionData[] = [];

      for (let i = 0; i < items.length; i++) {
        const item = items[i];
        const hits: RedactionHit[] = [];
        let redacted = redactValue(
          item.json,
          ctx,
          vault,
          sessionId,
          hits,
          i,
        ) as IDataObject;

        // Enhanced NLP detection via Presidio (if enabled)
        if (ctx.presidioUrl) {
          try {
            redacted = await enhanceWithPresidio(
              redacted as Record<string, unknown>,
              ctx,
              vault,
              sessionId,
              hits,
              i,
            ) as IDataObject;
          } catch {
            // Presidio unavailable — continue with regex-only results
          }
        }

        returnData.push({ json: redacted, pairedItem: { item: i } });
        allHits.push(...hits);
      }

      // Persist vault
      vault.save(sessionId);

      // Prompt injection detection (if enabled)
      let injectionResult = null;
      try {
        const promptInjection = this.getNodeParameter('promptInjection', 0, false) as boolean;
        if (promptInjection) {
          for (let i = 0; i < items.length; i++) {
            const result = scanForInjection(items[i].json as Record<string, unknown>);
            if (result.detected && (!injectionResult || result.score > injectionResult.score)) {
              injectionResult = result;
            }
          }
        }
      } catch {
        // Prompt injection parameter not available
      }

      // Audit log (if enabled)
      try {
        const auditLog = this.getNodeParameter('auditLog', 0, false) as boolean;
        if (auditLog) {
          const startTime = Date.now();
          const classification = classifyData(allHits);
          writeAuditLog(
            'REDACT', mode, allHits, items.length,
            Date.now() - startTime, enabledPatterns.length,
            !!ctx.presidioUrl, classification, sessionId,
          );
        }
      } catch {
        // Audit log parameter not available or write failed
      }

      // Build output
      if (injectionResult && injectionResult.detected) {
        // Append injection result to output
        returnData.push({
          json: {
            _promptInjection: injectionResult,
          } as unknown as IDataObject,
          pairedItem: allPaired,
        });
      }

      if (includeReport) {
        const report = buildReport(sessionId, allHits);
        return [returnData, [{ json: report as unknown as IDataObject, pairedItem: allPaired }]];
      }
      return [returnData];
    }

    // ─── RESTORE ─────────────────────────────
    if (operation === 'restore') {
      const deleteAfterRestore = this.getNodeParameter('deleteAfterRestore', 0, true) as boolean;

      const session = vault.getSession(sessionId);

      if (!session) {
        throw new NodeOperationError(
          this.getNode(),
          `No vault found for session "${sessionId}". Ensure a Redact node ran first with the same Session ID and vault storage type.`,
        );
      }

      const returnData: INodeExecutionData[] = [];
      for (let i = 0; i < items.length; i++) {
        const item = items[i];
        const restored = restoreValue(item.json, vault, sessionId) as IDataObject;
        returnData.push({ json: restored, pairedItem: { item: i } });
      }

      if (deleteAfterRestore) {
        vault.deleteSession(sessionId);
      }

      return [returnData];
    }

    // ─── PURGE (delete vault sessions) ──
    if (operation === 'purge') {
      const purgeScope = this.getNodeParameter('purgeScope', 0, 'all') as string;

      if (purgeScope === 'specific') {
        const purgeSessionId = this.getNodeParameter('purgeSessionId', 0, '') as string;
        if (!purgeSessionId) {
          throw new NodeOperationError(this.getNode(), 'Session ID is required for purging a specific session.');
        }
        const session = vault.getSession(purgeSessionId);
        if (session) {
          const entryCount = Object.keys(session.entries).length;
          vault.deleteSession(purgeSessionId);
          return [[{
            json: {
              purged: true,
              sessionId: purgeSessionId,
              entriesDeleted: entryCount,
              message: `Session purged successfully.`,
            } as unknown as IDataObject,
            pairedItem: allPaired,
          }]];
        } else {
          return [[{
            json: {
              purged: false,
              sessionId: purgeSessionId,
              message: `No session found with this ID.`,
            } as unknown as IDataObject,
            pairedItem: allPaired,
          }]];
        }
      } else {
        // Purge ALL sessions
        const sessions = vault.listSessions();
        let totalEntries = 0;
        for (const s of sessions) {
          totalEntries += s.entryCount;
          vault.deleteSession(s.sessionId);
        }
        return [[{
          json: {
            purged: true,
            sessionsPurged: sessions.length,
            totalEntriesDeleted: totalEntries,
            message: `All ${sessions.length} session(s) purged successfully.`,
          } as unknown as IDataObject,
          pairedItem: allPaired,
        }]];
      }
    }

    return [[]];
  }
}
