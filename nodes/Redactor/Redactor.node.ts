import {
  ICredentialTestFunctions,
  ICredentialsDecrypted,
  IDataObject,
  IExecuteFunctions,
  INodeCredentialTestResult,
  INodeExecutionData,
  INodeType,
  INodeTypeDescription,
  IHttpRequestMethods,
  NodeConnectionTypes,
  NodeOperationError,
} from 'n8n-workflow';

import { getPatternOptions } from './patterns';
import { createVault } from './vault';
import { redactValue, restoreValue, buildReport, enhanceWithPresidio, collectTokenLike, collectInputText } from './engine';
import {
  CustomPattern,
  RedactionContext,
  RedactionHit,
  RedactionMode,
  VaultStorage,
} from './types';
import { classifyData } from './classification';
import { scanForInjection } from './injection';
import { buildAuditEntry } from './audit';
import { resetCircuitBreaker, PresidioRequester } from './presidio';
import { parseTenantProfile } from './profiles';
import { generateRopaRecord } from './ropa';
import { assertUserRegexes, resolvePassphrase, sanitizeInjection, workflowNamespace } from './runtime';

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

export class Redactor implements INodeType {
  description: INodeTypeDescription = {
    displayName: 'Redactor',
    name: 'redactor',
    icon: { light: 'file:redactor.svg', dark: 'file:redactor.dark.svg' },
    group: ['transform'],
    version: 1,
    subtitle: '={{$parameter["operation"]}}',
    usableAsTool: true,
    description:
      'Redact and remove sensitive data, PII, personal information, emails, phone numbers, addresses, IBAN, credit cards, names before sending to LLM. Anonymize, mask, sanitize, scrub customer data. Restore original values after. Helps GDPR, HIPAA and CCPA workflows. Data privacy, data protection, data masking, data anonymization.',
    defaults: {
      name: 'Redactor',
    },
    inputs: [NodeConnectionTypes.Main],
    credentials: [
      {
        name: 'redactorVaultApi',
        required: false,
        testedBy: 'redactorVaultPassphrase',
        displayOptions: {
          show: {
            operation: ['redact', 'restore', 'stats', 'purge'],
            vaultStorage: ['workflow', 'file'],
          },
        },
      },
    ],
    outputs: `={{((parameters) => (parameters["includeReport"] || parameters["auditLog"]) ? [{ type: "main", displayName: "Data" }, { type: "main", displayName: "Report" }] : [{ type: "main", displayName: "Data" }])($parameter)}}`,

    properties: [
      // ═══════════════════════════════════════
      // OPERATION
      // ═══════════════════════════════════════
      // A single resource keeps saved 1.x workflows valid: its default fills in for them.
      {
        displayName: 'Resource',
        name: 'resource',
        type: 'options',
        noDataExpression: true,
        options: [
          {
            name: 'Data',
            value: 'data',
          },
        ],
        default: 'data',
      },
      {
        displayName: 'Operation',
        name: 'operation',
        type: 'options',
        noDataExpression: true,
        options: [
          {
            name: 'Classify',
            value: 'classify',
            description: 'Assign sensitivity labels (PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED) based on PII found',
												action: 'Assign sensitivity labels public internal confidential restricted based on pii found',
          },
          {
            name: 'Detect (Scan Only)',
            value: 'detect',
            description: 'Scan for PII without modifying the data. Returns a report of what was found.',
												action: 'Scan for pii without modifying the data returns a report of what was found',
          },
          {
            name: 'Purge',
            value: 'purge',
            description: 'Delete vault sessions. Supports GDPR right to erasure.',
												action: 'Delete vault sessions supports gdpr right to erasure',
          },
          {
            name: 'Redact',
            value: 'redact',
            description: 'Detect and replace PII with tokens/masks/hashes',
												action: 'Detect and replace pii with tokens masks hashes',
          },
          {
            name: 'Restore',
            value: 'restore',
            description: 'Replace tokens back with original PII values from vault',
												action: 'Replace tokens back with original PII values from vault',
          },
          {
            name: 'Stats',
            value: 'stats',
            description: 'List active vault sessions and entry counts',
												action: 'List active vault sessions and entry counts',
          },
          {
            name: 'Verify',
            value: 'verify',
            description: 'Re-scan redacted data to confirm no PII leaked through. Returns pass/fail.',
												action: 'Re scan redacted data to confirm no pii leaked through returns pass fail',
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
            name: 'Blackout (Visual Black Bars)',
            value: 'blackout',
            description: 'Replace with black bars (████████). Same length as original. NOT reversible. Like physical document redaction.',
          },
          {
            name: 'Hash (Deterministic)',
            value: 'hash',
            description:
              'Replace with truncated SHA-256 hash. Deterministic but NOT reversible.',
          },
          {
            name: 'Mask (Partial)',
            value: 'mask',
            description:
              'Show partial values: j***@e***.com, ****-****-****-1234. NOT reversible.',
          },
          {
            name: 'Pseudonymize (Fake Realistic Data)',
            value: 'pseudonymize',
            description: 'Replace with realistic fake data (names, emails, phones). Preserves format. Reversible via vault. Pseudonymization in the GDPR Art.4(5) sense.',
          },
          {
            name: 'Redact (Full Removal)',
            value: 'redact',
            description: 'Replace with [REDACTED]. NOT reversible.',
          },
          {
            name: 'Remove (Complete Deletion)',
            value: 'remove',
            description: 'Completely remove PII, leaving no trace. NOT reversible. The value is replaced with an empty string.',
          },
          {
            name: 'Token (Reversible)',
            value: 'token',
            description:
              'Replace PII with [EMAIL_0], [PHONE_1] etc. Restore via vault later. Best for LLM workflows.',
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
            description: 'Choose which specific data types to detect',
          },
        ],
        default: 'recommended',
        description: 'Detect all sensitive data types automatically, or select specific types to scan for',
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
          'Whether the same PII value always gets the same token. This keeps relationships in the data, e.g. an email in 3 fields becomes [EMAIL_0] in all 3.',
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
                description: 'JSON path to target. Supports dot notation and wildcards: "user.email", "*.phone", "items[*].name".',
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
                  { name: 'Contact', value: 'contact' },
                  { name: 'Financial', value: 'financial' },
                  { name: 'Identity', value: 'identity' },
                  { name: 'Location', value: 'location' },
                  { name: 'Medical', value: 'medical' },
                  { name: 'Network', value: 'network' },
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
        description: 'Whether to scan input for prompt injection attempts (jailbreaks, instruction overrides, delimiter escapes, encoded payloads) before it reaches an LLM. Detected injections are flagged in the output.',
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
        description: 'Whether to add an audit record (counts, labels, severity, timing, no PII values) to the Report output. Store it with any node, for example a database or a file. Supports GDPR Art.30, HIPAA, SOX and PCI DSS record-keeping.',
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
        description: 'Whether to add NLP-based detection using Microsoft Presidio. Catches person names, locations, and organizations in free text that regex cannot detect. Requires a Presidio Docker container running locally. Setup: docker run -d -p 5002:3000 mcr.microsoft.com/presidio-analyzer',
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
          { name: 'Dutch (Nederlands)', value: 'nl' },
          { name: 'English', value: 'en' },
          { name: 'French (Francais)', value: 'fr' },
          { name: 'German (Deutsch)', value: 'de' },
          { name: 'Italian (Italiano)', value: 'it' },
          { name: 'Polish (Polski)', value: 'pl' },
          { name: 'Portuguese (Portugues)', value: 'pt' },
          { name: 'Spanish (Espanol)', value: 'es' },
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
            name: 'In-Memory (Fast, Lost on Restart)',
            value: 'memory',
          },
          {
            name: 'Workflow Storage (Recommended, Persistent)',
            value: 'workflow',
          },
        ],
        default: 'workflow',
        description:
          'Workflow storage keeps sessions with the workflow, so Redact and Restore nodes in the same workflow share them and they survive restarts. n8n saves it after production runs of an active workflow. In-memory is faster but lost on restart and capped at 1000 sessions.',
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
            // 'file' is the 1.x value; keeping it visible preserves a saved passphrase.
            vaultStorage: ['workflow', 'file'],
          },
        },
        default: '',
        description: 'Deprecated. This field is saved in plain text inside the workflow. Attach a Redactor Vault credential instead, which n8n stores encrypted and which takes priority. Kept so workflows saved with it still restore.',
      },
      {
        displayName: 'Session TTL (Minutes)',
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
      {
        displayName: 'Use Tenant Profile',
        name: 'useTenantProfile',
        type: 'boolean',
        displayOptions: {
          show: {
            operation: ['redact'],
          },
        },
        default: false,
        description: 'Whether to apply per-client settings from a JSON profile on top of this node',
      },
      {
        displayName: 'Tenant Profile (JSON)',
        name: 'tenantProfile',
        type: 'json',
        required: true,
        displayOptions: {
          show: {
            operation: ['redact'],
            useTenantProfile: [true],
          },
        },
        default: '{}',
        description:
          'Optional per-client settings that override this node: enabledPatterns, customPatterns, confidenceThreshold, redactionMode, dedup, fieldMode, fieldRules, allowList, denyList, retentionMinutes, auditLog. Unknown fields are rejected.',
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
            description: 'Delete a specific session by ID',
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
          'Whether to delete the vault session after restoring. Turn off for multi-step workflows that restore more than once.',
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
          'Whether to add a second output with an audit report listing all PII detected, categories, and counts. Useful for compliance logging.',
      },
      {
        displayName: 'Include GDPR Art.30 ROPA Record',
        name: 'includeRopa',
        type: 'boolean',
        displayOptions: {
          show: {
            operation: ['redact'],
            includeReport: [true],
          },
        },
        default: false,
        description:
          'Whether to add a Records of Processing Activities entry (GDPR Art.30) to the report output, filled from this run plus the details below',
      },
      {
        displayName: 'ROPA Details',
        name: 'ropa',
        type: 'collection',
        placeholder: 'Add Detail',
        displayOptions: {
          show: {
            operation: ['redact'],
            includeReport: [true],
            includeRopa: [true],
          },
        },
        default: {},
        options: [
          { displayName: 'Controller Contact Email', name: 'controllerContact', type: 'string', placeholder: 'name@email.com', default: '' },
          { displayName: 'Controller Name', name: 'controllerName', type: 'string', default: '' },
          { displayName: 'Data Protection Officer', name: 'dpo', type: 'string', default: '' },
          { displayName: 'Data Subject Categories', name: 'dataSubjects', type: 'string', default: '', description: 'Comma-separated, e.g. Customers, Employees' },
          {
            displayName: 'Legal Basis',
            name: 'legalBasis',
            type: 'options',
            options: [
              { name: 'Consent (Art.6(1)(a))', value: 'consent' },
              { name: 'Contract (Art.6(1)(b))', value: 'contract' },
              { name: 'Legal Obligation (Art.6(1)(c))', value: 'legal_obligation' },
              { name: 'Legitimate Interest (Art.6(1)(f))', value: 'legitimate_interest' },
              { name: 'Public Task (Art.6(1)(e))', value: 'public_task' },
              { name: 'Vital Interests (Art.6(1)(d))', value: 'vital_interests' },
            ],
            default: 'legitimate_interest',
          },
          { displayName: 'Processing Purposes', name: 'purposes', type: 'string', default: '', description: 'Comma-separated, e.g. Support ticket triage' },
          { displayName: 'Recipient Categories', name: 'recipients', type: 'string', default: '', description: 'Comma-separated, e.g. OpenAI (processor)' },
        ],
      },
    ],
  };

  methods = {
    credentialTest: {
      async redactorVaultPassphrase(
        this: ICredentialTestFunctions,
        credential: ICredentialsDecrypted,
      ): Promise<INodeCredentialTestResult> {
        const passphrase = String(credential.data?.passphrase ?? '');
        if (passphrase.length < 12) {
          return { status: 'Error', message: 'Use a passphrase of at least 12 characters.' };
        }
        return { status: 'OK', message: 'Passphrase accepted.' };
      },
    },
  };

  async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
    const items = this.getInputData();
    // Aggregate outputs (summaries, reports) link back to every input item.
    const allPaired = items.map((_, i) => ({ item: i }));
    const operation = this.getNodeParameter('operation', 0) as string;
    const startTime = Date.now();

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
        // Numbers reach the LLM as text too, so they are scanned as their string form.
        scanNumbers: true,
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
        try { includeReport = this.getNodeParameter('includeReport', 0, false) as boolean; } catch { /* parameter hidden for this operation */ }
        let auditLog = false;
        try { auditLog = this.getNodeParameter('auditLog', 0, false) as boolean; } catch { /* parameter hidden for this operation */ }

        if (includeReport || auditLog) {
          const reportJson: IDataObject = includeReport
            ? ({ ...summary, hits: report.hits } as unknown as IDataObject)
            : {};
          if (auditLog) {
            reportJson.audit = buildAuditEntry(
              'DETECT', 'token', allHits, items.length, Date.now() - startTime,
              enabledPatterns.length, false, classifyData(allHits),
            ) as unknown as IDataObject;
          }
          if (!includeReport) returnData.push({ json: summary as unknown as IDataObject, pairedItem: allPaired });
          return [returnData, [{ json: reportJson, pairedItem: allPaired }]];
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
    const vaultStorage = this.getNodeParameter('vaultStorage', 0, 'workflow') as VaultStorage;
    const vaultPassphrase = vaultStorage === 'memory' ? '' : await resolvePassphrase(this);
    // Global static data so the Redact and Restore nodes of one workflow share sessions.
    const vault = createVault(
      vaultStorage,
      vaultStorage === 'memory' ? undefined : this.getWorkflowStaticData('global'),
      vaultPassphrase || undefined,
      workflowNamespace(this),
    );

    // ─── STATS ───────────────────────────────
    if (operation === 'stats') {
      // Read only: expired sessions are skipped, never deleted, so no stale static data is written.
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
      let mode = this.getNodeParameter('redactionMode', 0, 'token') as RedactionMode;
      const detectionScope = this.getNodeParameter('detectionScope', 0, 'recommended') as string;
      let enabledPatterns: string[];
      if (detectionScope === 'all') {
        enabledPatterns = getPatternOptions().map((p) => p.value);
      } else if (detectionScope === 'recommended') {
        enabledPatterns = RECOMMENDED_PATTERNS;
      } else {
        enabledPatterns = this.getNodeParameter('piiTypes', 0) as string[];
      }
      let dedup = this.getNodeParameter('dedup', 0, true) as boolean;
      let fieldMode = this.getNodeParameter('fieldMode', 0, 'all') as 'all' | 'allowlist' | 'denylist';
      let sessionTtl = this.getNodeParameter('sessionTtl', 0, 60) as number;
      const includeReport = this.getNodeParameter('includeReport', 0, false) as boolean;

      const customPatternsRaw = this.getNodeParameter('customPatterns', 0, {}) as {
        patterns?: CustomPattern[];
      };
      let customPatterns = customPatternsRaw.patterns ?? [];

      const fieldRulesRaw = this.getNodeParameter('fieldRules', 0, {}) as {
        rules?: Array<{ field: string }>;
      };
      let fieldRules = (fieldRulesRaw.rules ?? []).map((r) => ({
        field: r.field,
        mode: fieldMode === 'allowlist' ? ('include' as const) : ('exclude' as const),
      }));

      // Presidio NLP integration (optional), over n8n's HTTP helper
      const presidioRequester: PresidioRequester = async ({ method, url, body, timeout }) => {
        const response = await this.helpers.httpRequest({
          method: method as IHttpRequestMethods,
          url,
          body,
          json: true,
          timeout,
          returnFullResponse: true,
          ignoreHttpStatusErrors: true,
        });
        return { statusCode: response.statusCode as number, body: response.body as unknown };
      };
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
      let allowList = (allowListRaw.entries ?? []).map((e) => ({
        value: e.value,
        type: (e.type || 'contains') as 'exact' | 'contains' | 'regex',
      }));

      // Parse deny list
      const denyListRaw = this.getNodeParameter('denyList', 0, {}) as {
        entries?: Array<{ value: string; type: string }>;
      };
      let denyList = (denyListRaw.entries ?? []).map((e) => ({
        value: e.value,
        type: (e.type || 'exact') as 'exact' | 'contains' | 'regex',
      }));

      // Confidence threshold
      let confidenceThreshold = this.getNodeParameter('confidenceThreshold', 0, 0) as number;
      // The Report output exists only when the node itself turns it on (see outputs).
      const hasReportOutput = includeReport || (this.getNodeParameter('auditLog', 0, false) as boolean);
      let auditLog = this.getNodeParameter('auditLog', 0, false) as boolean;

      // Tenant profile overrides the node settings it names
      const useTenantProfile = this.getNodeParameter('useTenantProfile', 0, false) as boolean;
      const profileRaw = useTenantProfile ? (this.getNodeParameter('tenantProfile', 0, '') as unknown) : '';
      if (profileRaw !== '' && profileRaw !== undefined && profileRaw !== null) {
        let profile;
        try {
          profile = parseTenantProfile(profileRaw, getPatternOptions().map((o) => o.value));
        } catch (error) {
          throw new NodeOperationError(this.getNode(), (error as Error).message, {
            description: 'Fix the Tenant Profile (JSON) field, or leave it empty to use the node settings.',
          });
        }
        if (profile.enabledPatterns) enabledPatterns = profile.enabledPatterns;
        if (profile.customPatterns) customPatterns = profile.customPatterns;
        if (profile.confidenceThreshold !== undefined) confidenceThreshold = profile.confidenceThreshold;
        if (profile.redactionMode) mode = profile.redactionMode;
        if (profile.dedup !== undefined) dedup = profile.dedup;
        if (profile.fieldMode) fieldMode = profile.fieldMode;
        if (profile.fieldRules) fieldRules = profile.fieldRules;
        if (profile.allowList) allowList = profile.allowList;
        if (profile.denyList) denyList = profile.denyList;
        if (profile.retentionMinutes !== undefined) sessionTtl = profile.retentionMinutes;
        if (profile.auditLog !== undefined) auditLog = profile.auditLog;
      }

      assertUserRegexes(this, customPatterns, [
        { name: 'Allow list', entries: allowList },
        { name: 'Deny list', entries: denyList },
      ]);

      // Initialize vault session
      try {
        vault.getOrCreateSession(sessionId, sessionTtl * 60 * 1000);
      } catch (error) {
        throw new NodeOperationError(this.getNode(), (error as Error).message);
      }

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
        presidioRequest: enablePresidio ? presidioRequester : undefined,
        // Numbers reach the LLM as text, so Redact scans them like Detect and Verify do.
        scanNumbers: true,
        reservedTokens: collectTokenLike(items.map((it) => it.json)),
        keyOrigins: new WeakMap(),
        inputText: collectInputText(items.map((it) => it.json)),
        lockedSpans: new Map(),
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
              injectionResult = sanitizeInjection(result);
            }
          }
        }
      } catch {
        // Prompt injection parameter not available
      }

      const auditEntry = auditLog && hasReportOutput
        ? buildAuditEntry(
            'REDACT', mode, allHits, items.length, Date.now() - startTime,
            enabledPatterns.length, !!ctx.presidioUrl, classifyData(allHits), sessionId,
          )
        : undefined;

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

      if (hasReportOutput) {
        const report: IDataObject = includeReport ? (buildReport(sessionId, allHits) as unknown as IDataObject) : {};
        if (auditEntry) report.audit = auditEntry as unknown as IDataObject;
        if (includeReport && (this.getNodeParameter('includeRopa', 0, false) as boolean)) {
          const d = this.getNodeParameter('ropa', 0, {}) as IDataObject;
          const list = (v: unknown) => String(v ?? '').split(',').map((x) => x.trim()).filter(Boolean);
          report.ropa = generateRopaRecord(
            allHits, classifyData(allHits), items.length, enabledPatterns.length, mode,
            sessionTtl, !!vaultPassphrase, auditLog,
            { name: String(d.controllerName ?? ''), contactEmail: String(d.controllerContact ?? ''), dpo: d.dpo ? String(d.dpo) : undefined },
            list(d.purposes), String(d.legalBasis ?? 'legitimate_interest'), list(d.dataSubjects), list(d.recipients), [],
          ) as unknown as IDataObject;
        }
        return [returnData, [{ json: report, pairedItem: allPaired }]];
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
          `No vault found for session "${sessionId}" that this passphrase can open. Ensure a Redact node ran first with the same Session ID, vault storage type and passphrase.`,
          {
            description:
              'Testing step by step? Each "Execute step" gets a new execution ID, and n8n saves workflow storage only after production runs of an active workflow. Run the whole workflow, or set the same fixed Session ID (for example "test-1") on both nodes. Restore only works in the workflow that ran Redact.',
          },
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
        const purged = vault.purgeSession(purgeSessionId);
        return [[{
          json: {
            purged: purged.found,
            sessionId: purgeSessionId,
            ...(purged.found ? { entriesDeleted: purged.entries } : {}),
            message: purged.found ? 'Session purged successfully.' : 'No session found with this ID.',
          } as unknown as IDataObject,
          pairedItem: allPaired,
        }]];
      }
      // Purge ALL sessions, expired and unreadable records included
      const all = vault.purgeAll();
      return [[{
        json: {
          purged: true,
          sessionsPurged: all.sessions,
          totalEntriesDeleted: all.entries,
          message: `All ${all.sessions} session(s) purged successfully.`,
        } as unknown as IDataObject,
        pairedItem: allPaired,
      }]];
    }

    return [[]];
  }
}
