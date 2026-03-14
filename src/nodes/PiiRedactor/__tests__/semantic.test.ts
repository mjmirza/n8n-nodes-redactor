import { MemoryVault } from '../vault';
import { redactValue, restoreValue } from '../engine';
import { RedactionContext, RedactionHit } from '../types';

function createContext(overrides: Partial<RedactionContext> = {}): RedactionContext {
  return {
    enabledPatterns: ['email', 'phone', 'personName', 'ssn'],
    customPatterns: [],
    mode: 'token',
    dedup: true,
    fieldRules: [],
    fieldMode: 'all',
    ...overrides,
  };
}

// ═══════════════════════════════════════════════════════
// SEMANTIC FIELD-NAME DETECTION
// ═══════════════════════════════════════════════════════

describe('Semantic detection: Person names', () => {
  let vault: MemoryVault;
  beforeEach(() => { vault = new MemoryVault(); });

  test('redacts "name" field without title prefix', () => {
    vault.getOrCreateSession('s1', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { name: 'Amelia Ramirez' },
      createContext(),
      vault, 's1', hits, 0,
    ) as any;
    expect(result.name).toContain('[PERSON_NAME_');
    expect(result.name).not.toBe('Amelia Ramirez');
  });

  test('redacts "firstName" and "lastName" fields', () => {
    vault.getOrCreateSession('s2', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { firstName: 'Sarah', lastName: 'Johnson' },
      createContext(),
      vault, 's2', hits, 0,
    ) as any;
    expect(result.firstName).toContain('[PERSON_NAME_');
    expect(result.lastName).toContain('[PERSON_NAME_');
  });

  test('redacts German field names: Vorname, Nachname', () => {
    vault.getOrCreateSession('s3', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { Vorname: 'Hans', Nachname: 'Mueller' },
      createContext(),
      vault, 's3', hits, 0,
    ) as any;
    expect(result.Vorname).toContain('[PERSON_NAME_');
    expect(result.Nachname).toContain('[PERSON_NAME_');
  });

  test('redacts nested name fields', () => {
    vault.getOrCreateSession('s4', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { customer: { name: 'Liam Clark' } },
      createContext(),
      vault, 's4', hits, 0,
    ) as any;
    expect(result.customer.name).toContain('[PERSON_NAME_');
  });

  test('redacts displayName, contactName, customerName', () => {
    vault.getOrCreateSession('s5', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { displayName: 'Grace Taylor', contactName: 'Mia Lewis', customerName: 'Ryan Torres' },
      createContext(),
      vault, 's5', hits, 0,
    ) as any;
    expect(result.displayName).toContain('[PERSON_NAME_');
    expect(result.contactName).toContain('[PERSON_NAME_');
    expect(result.customerName).toContain('[PERSON_NAME_');
  });

  test('redacts French/Spanish field names', () => {
    vault.getOrCreateSession('s6', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { nom: 'Dupont', prenom: 'Jean', nombre: 'Carlos', apellido: 'Garcia' },
      createContext(),
      vault, 's6', hits, 0,
    ) as any;
    expect(result.nom).toContain('[PERSON_NAME_');
    expect(result.prenom).toContain('[PERSON_NAME_');
    expect(result.nombre).toContain('[PERSON_NAME_');
    expect(result.apellido).toContain('[PERSON_NAME_');
  });
});

describe('Semantic detection: Employee / HR data', () => {
  let vault: MemoryVault;
  beforeEach(() => { vault = new MemoryVault(); });

  test('redacts employeeId field', () => {
    vault.getOrCreateSession('hr1', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { employeeId: 'D41BRX4M' },
      createContext(),
      vault, 'hr1', hits, 0,
    ) as any;
    expect(result.employeeId).toContain('[EMPLOYEE_ID_');
  });

  test('redacts department field', () => {
    vault.getOrCreateSession('hr2', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { department: 'Finance' },
      createContext(),
      vault, 'hr2', hits, 0,
    ) as any;
    expect(result.department).toContain('[DEPARTMENT_');
  });

  test('redacts position/jobTitle field', () => {
    vault.getOrCreateSession('hr3', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { position: 'Senior Developer', jobTitle: 'CTO' },
      createContext(),
      vault, 'hr3', hits, 0,
    ) as any;
    expect(result.position).toContain('[JOB_TITLE_');
    expect(result.jobTitle).toContain('[JOB_TITLE_');
  });

  test('redacts numeric salary field', () => {
    vault.getOrCreateSession('hr4', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { salary: 110905 },
      createContext(),
      vault, 'hr4', hits, 0,
    ) as any;
    expect(result.salary).toContain('[SALARY_');
  });

  test('redacts hireDate field', () => {
    vault.getOrCreateSession('hr5', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { hireDate: '2024-01-15' },
      createContext(),
      vault, 'hr5', hits, 0,
    ) as any;
    expect(result.hireDate).toContain('[EMPLOYMENT_DATE_');
    // Should NOT be broken into postal code + card expiry
    expect(result.hireDate).not.toContain('POSTCODE');
    expect(result.hireDate).not.toContain('CARD_EXPIRY');
  });

  test('redacts German HR field names', () => {
    vault.getOrCreateSession('hr6', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { Personalnummer: 'EMP-4821', Abteilung: 'Vertrieb', Stelle: 'Teamleiter' },
      createContext(),
      vault, 'hr6', hits, 0,
    ) as any;
    expect(result.Personalnummer).toContain('[EMPLOYEE_ID_');
    expect(result.Abteilung).toContain('[DEPARTMENT_');
    expect(result.Stelle).toContain('[JOB_TITLE_');
  });
});

describe('Semantic detection: Address fields', () => {
  let vault: MemoryVault;
  beforeEach(() => { vault = new MemoryVault(); });

  test('redacts address field', () => {
    vault.getOrCreateSession('addr1', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { address: '123 Main Street, Apt 4B' },
      createContext(),
      vault, 'addr1', hits, 0,
    ) as any;
    expect(result.address).toContain('[ADDRESS_');
  });

  test('redacts city, state, zipCode fields', () => {
    vault.getOrCreateSession('addr2', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { city: 'Munich', state: 'Bavaria', zipCode: '80331' },
      createContext(),
      vault, 'addr2', hits, 0,
    ) as any;
    expect(result.city).toContain('[ADDRESS_');
    expect(result.state).toContain('[ADDRESS_');
    expect(result.zipCode).toContain('[ADDRESS_');
  });

  test('redacts German address fields', () => {
    vault.getOrCreateSession('addr3', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { Anschrift: 'Musterstr. 12', PLZ: '80331', Adresse: 'Berlin' },
      createContext(),
      vault, 'addr3', hits, 0,
    ) as any;
    expect(result.Anschrift).toContain('[ADDRESS_');
    expect(result.PLZ).toContain('[ADDRESS_');
    expect(result.Adresse).toContain('[ADDRESS_');
  });
});

describe('Semantic detection: Financial fields', () => {
  let vault: MemoryVault;
  beforeEach(() => { vault = new MemoryVault(); });

  test('redacts account_number field', () => {
    vault.getOrCreateSession('fin1', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { accountNumber: 'DE89370400440532013000' },
      createContext(),
      vault, 'fin1', hits, 0,
    ) as any;
    expect(result.accountNumber).toContain('[ACCOUNT_NUMBER_');
  });

  test('redacts insurance policy field', () => {
    vault.getOrCreateSession('fin2', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { insurancePolicy: 'POL-2024-XYZ' },
      createContext(),
      vault, 'fin2', hits, 0,
    ) as any;
    expect(result.insurancePolicy).toContain('[INSURANCE_');
  });
});

describe('Semantic detection: Company/Organization', () => {
  let vault: MemoryVault;
  beforeEach(() => { vault = new MemoryVault(); });

  test('redacts company field', () => {
    vault.getOrCreateSession('comp1', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { company: 'Acme Corporation' },
      createContext(),
      vault, 'comp1', hits, 0,
    ) as any;
    expect(result.company).toContain('[COMPANY_');
  });

  test('redacts employer, organization fields', () => {
    vault.getOrCreateSession('comp2', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { employer: 'BigCorp GmbH', organization: 'Red Cross' },
      createContext(),
      vault, 'comp2', hits, 0,
    ) as any;
    expect(result.employer).toContain('[COMPANY_');
    expect(result.organization).toContain('[COMPANY_');
  });

  test('redacts German: Firma, Unternehmen, Arbeitgeber', () => {
    vault.getOrCreateSession('comp3', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { Firma: 'Siemens AG', Arbeitgeber: 'BMW Group' },
      createContext(),
      vault, 'comp3', hits, 0,
    ) as any;
    expect(result.Firma).toContain('[COMPANY_');
    expect(result.Arbeitgeber).toContain('[COMPANY_');
  });
});

describe('Semantic detection: Full round-trip with real-world data', () => {
  let vault: MemoryVault;
  beforeEach(() => { vault = new MemoryVault(); });

  test('complete employee record redaction and restoration', () => {
    vault.getOrCreateSession('rt1', 0);
    const hits: RedactionHit[] = [];
    const original = {
      employeeId: 'D41BRX4M',
      name: 'Amelia Ramirez',
      email: 'amelia.ramirez@company.com',
      department: 'Finance',
      position: 'Senior Analyst',
      hireDate: '2024-01-15',
      salary: 85000,
      company: 'Exacta GmbH',
      address: 'Berliner Str. 45, 10115 Berlin',
    };

    const redacted = redactValue(original, createContext(), vault, 'rt1', hits, 0) as any;

    // Every field should be redacted
    expect(redacted.employeeId).toContain('[');
    expect(redacted.name).toContain('[PERSON_NAME_');
    expect(redacted.email).toContain('['); // caught by regex or semantic
    expect(redacted.department).toContain('[DEPARTMENT_');
    expect(redacted.position).toContain('[JOB_TITLE_');
    expect(redacted.hireDate).toContain('[EMPLOYMENT_DATE_');
    expect(redacted.salary).toContain('[SALARY_');
    expect(redacted.company).toContain('[COMPANY_');
    expect(redacted.address).toContain('[ADDRESS_');

    // None of the original values should be visible
    const json = JSON.stringify(redacted);
    expect(json).not.toContain('Amelia Ramirez');
    expect(json).not.toContain('Finance');
    expect(json).not.toContain('Senior Analyst');
    expect(json).not.toContain('85000');
    expect(json).not.toContain('Exacta GmbH');

    // Restore should bring everything back
    const restored = restoreValue(redacted, vault, 'rt1') as any;
    expect(restored.name).toBe('Amelia Ramirez');
    expect(restored.department).toBe('Finance');
    expect(restored.position).toBe('Senior Analyst');
    expect(restored.salary).toBe('85000'); // restored as string (currency-safe)
    expect(restored.company).toBe('Exacta GmbH');
  });
});

describe('Semantic detection: Language/cultural fields', () => {
  let vault: MemoryVault;
  beforeEach(() => { vault = new MemoryVault(); });

  test('redacts "language" field as GDPR Art.9 sensitive', () => {
    vault.getOrCreateSession('lang1', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { name: 'Adeel', language: 'Sindhi' },
      createContext(),
      vault, 'lang1', hits, 0,
    ) as any;
    expect(result.language).toContain('[LANGUAGE_');
    expect(result.language).not.toBe('Sindhi');
  });

  test('redacts mother tongue fields', () => {
    vault.getOrCreateSession('lang2', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { motherTongue: 'Urdu', Muttersprache: 'Deutsch' },
      createContext(),
      vault, 'lang2', hits, 0,
    ) as any;
    expect(result.motherTongue).toContain('[LANGUAGE_');
    expect(result.Muttersprache).toContain('[LANGUAGE_');
  });
});

describe('Semantic detection: Context-aware ambiguous fields', () => {
  let vault: MemoryVault;
  beforeEach(() => { vault = new MemoryVault(); });

  test('redacts bare "id" when sibling has "name" (PII context)', () => {
    vault.getOrCreateSession('ctx1', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { id: 'D41BRX4M', name: 'Amelia Ramirez', department: 'Finance' },
      createContext(),
      vault, 'ctx1', hits, 0,
    ) as any;
    expect(result.id).toContain('[IDENTIFIER_');
    expect(result.id).not.toBe('D41BRX4M');
  });

  test('does NOT redact bare "id" when no PII sibling fields', () => {
    vault.getOrCreateSession('ctx2', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { id: '12345', status: 'active', type: 'widget' },
      createContext(),
      vault, 'ctx2', hits, 0,
    ) as any;
    // No PII indicator siblings, so id should NOT be redacted
    expect(result.id).toBe('12345');
  });

  test('redacts "code" and "ref" when email sibling exists', () => {
    vault.getOrCreateSession('ctx3', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { code: 'EMP-4821', ref: 'REF-999', email: 'john@test.com' },
      createContext(),
      vault, 'ctx3', hits, 0,
    ) as any;
    expect(result.code).toContain('[IDENTIFIER_');
    expect(result.ref).toContain('[IDENTIFIER_');
  });

  test('redacts "number" when salary sibling exists', () => {
    vault.getOrCreateSession('ctx4', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { number: 'ACC-12345', salary: 85000, name: 'Jane Doe' },
      createContext(),
      vault, 'ctx4', hits, 0,
    ) as any;
    expect(result.number).toContain('[IDENTIFIER_');
  });

  test('does NOT redact "status" in non-PII record', () => {
    vault.getOrCreateSession('ctx5', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { status: 'completed', category: 'urgent', label: 'bug' },
      createContext(),
      vault, 'ctx5', hits, 0,
    ) as any;
    expect(result.status).toBe('completed');
    expect(result.category).toBe('urgent');
    expect(result.label).toBe('bug');
  });

  test('context-aware detection in nested objects', () => {
    vault.getOrCreateSession('ctx6', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { user: { id: 'USR-999', name: 'John Smith', code: 'ABC123' } },
      createContext(),
      vault, 'ctx6', hits, 0,
    ) as any;
    expect(result.user.id).toContain('[IDENTIFIER_');
    expect(result.user.code).toContain('[IDENTIFIER_');
  });

  test('full employee record with ambiguous fields all redacted', () => {
    vault.getOrCreateSession('ctx7', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      {
        id: 'V59OF92YF62',
        name: 'Adeel Solangi',
        language: 'Sindhi',
        code: 'EMP001',
        ref: 'HR-2024-001',
        email: 'adeel@company.com',
      },
      createContext(),
      vault, 'ctx7', hits, 0,
    ) as any;

    const json = JSON.stringify(result);
    expect(json).not.toContain('V59OF92YF62');
    expect(json).not.toContain('Adeel Solangi');
    expect(json).not.toContain('Sindhi');
    expect(json).not.toContain('EMP001');
    expect(json).not.toContain('HR-2024-001');
    expect(json).not.toContain('adeel@company.com');
  });
});

describe('Semantic detection: Notes/text fields fall through to regex', () => {
  let vault: MemoryVault;
  beforeEach(() => { vault = new MemoryVault(); });

  test('notes field is NOT fully redacted but regex runs on it', () => {
    vault.getOrCreateSession('notes1', 0);
    const hits: RedactionHit[] = [];
    const result = redactValue(
      { notes: 'Customer john@test.com called about order' },
      createContext(),
      vault, 'notes1', hits, 0,
    ) as any;
    // The whole field should NOT be a single token
    expect(result.notes).toContain('called about order');
    // But the email inside should be redacted
    expect(result.notes).toContain('[EMAIL_');
    expect(result.notes).not.toContain('john@test.com');
  });
});
