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
import { redactValue, restoreValue, buildReport } from './engine';
import {
  CustomPattern,
  RedactionContext,
  RedactionHit,
  RedactionMode,
  VaultStorage,
} from './types';

export class PiiRedactor implements INodeType {
  description: INodeTypeDescription = {
    displayName: 'Redactor',
    name: 'redactor',
    icon: 'file:redact.png',
    group: ['transform'],
    version: 1,
    subtitle: '={{$parameter["operation"]}}',
    description:
      'Redact and remove sensitive data, PII, personal information, emails, phone numbers, addresses, IBAN, credit cards, names before sending to LLM. Anonymize, mask, sanitize, scrub customer data. Restore original values after. GDPR HIPAA CCPA compliant. Data privacy, data protection, data masking, data anonymization.',
    defaults: {
      name: 'Redactor',
    },
    inputs: ['main'],
    outputs: ['main'],
    // @ts-ignore -n8n supports outputNames
    outputNames: ['Data', 'Report'],

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
            name: 'Detect All (210+ types)',
            value: 'all',
            description: 'Detect all 210+ sensitive data types across all categories. Maximum coverage.',
          },
          {
            name: 'Select Specific Types',
            value: 'select',
            description: 'Choose which specific data types to detect.',
          },
        ],
        default: 'all',
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
                  { name: 'Other', value: 'identity' },
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
      // VAULT SETTINGS
      // ═══════════════════════════════════════
      {
        displayName: 'Vault Storage',
        name: 'vaultStorage',
        type: 'options',
        displayOptions: {
          show: {
            operation: ['redact', 'restore', 'stats'],
          },
        },
        options: [
          {
            name: 'In-Memory (Fast, Lost on Restart)',
            value: 'memory',
          },
          {
            name: 'File-Based (Persistent Across Restarts)',
            value: 'file',
          },
        ],
        default: 'memory',
        description:
          'Where to store the token-to-original mappings. File-based vault persists to ~/.n8n/pii-vault/',
      },
      {
        displayName: 'Vault Directory',
        name: 'vaultDir',
        type: 'string',
        displayOptions: {
          show: {
            operation: ['redact', 'restore', 'stats'],
            vaultStorage: ['file'],
          },
        },
        default: '',
        placeholder: '/path/to/vault (default: ~/.n8n/pii-vault/)',
        description: 'Custom directory for file-based vault storage',
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
            operation: ['redact'],
          },
        },
        default: false,
        description:
          'Output a second item with an audit report listing all PII detected, categories, and counts. Useful for compliance logging.',
      },
    ],
  };

  async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
    const items = this.getInputData();
    const operation = this.getNodeParameter('operation', 0) as string;
    const vaultStorage = this.getNodeParameter('vaultStorage', 0, 'memory') as VaultStorage;
    const vaultDir = this.getNodeParameter('vaultDir', 0, '') as string;

    const vault = createVault(vaultStorage, vaultDir || undefined);

    // ─── STATS ───────────────────────────────
    if (operation === 'stats') {
      vault.cleanup();
      const sessions = vault.listSessions();
      return [[
        {
          json: {
            totalSessions: sessions.length,
            sessions,
          } as unknown as IDataObject,
        },
      ]];
    }

    const sessionId = this.getNodeParameter('sessionId', 0) as string;
    if (!sessionId) {
      throw new NodeOperationError(this.getNode(), 'Session ID is required');
    }

    // ─── REDACT ──────────────────────────────
    if (operation === 'redact') {
      const mode = this.getNodeParameter('redactionMode', 0, 'token') as RedactionMode;
      const detectionScope = this.getNodeParameter('detectionScope', 0, 'all') as string;
      const enabledPatterns = detectionScope === 'all'
        ? getPatternOptions().map((p) => p.value)
        : this.getNodeParameter('piiTypes', 0) as string[];
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

      // Initialize vault session
      vault.getOrCreateSession(sessionId, sessionTtl * 60 * 1000);

      const ctx: RedactionContext = {
        enabledPatterns,
        customPatterns,
        mode,
        dedup,
        fieldRules,
        fieldMode,
      };

      const allHits: RedactionHit[] = [];
      const returnData: INodeExecutionData[] = [];

      for (let i = 0; i < items.length; i++) {
        const item = items[i];
        const hits: RedactionHit[] = [];
        const redacted = redactValue(
          item.json,
          ctx,
          vault,
          sessionId,
          hits,
          i,
        ) as IDataObject;
        returnData.push({ json: redacted });
        allHits.push(...hits);
      }

      // Persist vault
      vault.save(sessionId);

      // Build output -always return data on first output
      const output: INodeExecutionData[][] = [returnData];

      // If audit report requested, add as second output
      if (includeReport) {
        const report = buildReport(sessionId, allHits);
        output.push([{ json: report as unknown as IDataObject }]);
      }

      return output;
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
        returnData.push({ json: restored });
      }

      if (deleteAfterRestore) {
        vault.deleteSession(sessionId);
      }

      return [returnData];
    }

    return [[]];
  }
}
