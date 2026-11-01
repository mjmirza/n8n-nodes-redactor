import * as crypto from 'crypto';
import { getPatternsByNames } from './patterns';
import { IVault } from './vault';
import { checkRegex } from './regexSafety';
import {
  AllowDenyEntry,
  PiiCategory,
  PiiPattern,
  RedactionContext,
  RedactionHit,
  RedactionMode,
  RedactionReport,
} from './types';
import {
  calculateConfidence,
  SEMANTIC_CONFIDENCE,
  AMBIGUOUS_FIELD_CONFIDENCE,
  CUSTOM_PATTERN_CONFIDENCE,
  DENY_LIST_CONFIDENCE, hasContextWords 
} from './context';
import { detectNamesInText, NAME_CONTEXT_WORDS } from './names';
import { generatePseudonym } from './pseudonymize';
import {
  analyzeWithPresidio,
  getRedactorLabel,
  getRedactorCategory,
} from './presidio';

/**
 * Check if a value matches any entry in the allow list (should be SKIPPED).
 */
function isAllowListed(value: string, allowList?: AllowDenyEntry[]): boolean {
  if (!allowList || allowList.length === 0) return false;
  return allowList.some((entry) => {
    try {
      switch (entry.type) {
        case 'exact':
          return value === entry.value;
        case 'contains':
          return value.includes(entry.value);
        case 'regex':
          if (!isSafeRegex(entry.value)) return false;
          return new RegExp(entry.value, 'i').test(value);
        default:
          return value === entry.value;
      }
    } catch {
      return false;
    }
  });
}

/**
 * Generate a deterministic token for a given label + index.
 */
function generateToken(label: string, index: number): string {
  return `[${label}_${index}]`;
}

/**
 * Token format regex — used to skip already-redacted regions.
 */
const TOKEN_RE = /^\[[A-Z][A-Z0-9_]*_\d+\]$/;

/**
 * Generate a masked version of a string.
 */
function maskValue(value: string, label: string): string {
  if (value.length <= 2) return '*'.repeat(value.length);

  if (label === 'EMAIL' && value.includes('@')) {
    const [local, domain] = value.split('@');
    const maskedLocal = local[0] + '***';
    const domainParts = domain.split('.');
    const maskedDomain = domainParts[0][0] + '***.' + domainParts.slice(1).join('.');
    return maskedLocal + '@' + maskedDomain;
  }

  if (label.startsWith('PHONE') || label === 'FAX') {
    const digits = value.replace(/\D/g, '');
    if (digits.length >= 4) {
      return '***' + digits.slice(-4);
    }
  }

  if (label === 'CREDIT_CARD' || label === 'AMEX') {
    const digits = value.replace(/\D/g, '');
    return '****-****-****-' + digits.slice(-4);
  }

  return value[0] + '*'.repeat(value.length - 2) + value[value.length - 1];
}

/**
 * Generate a truncated hash of a value.
 */
function hashValue(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex').slice(0, 12);
}

type RedactionPattern = PiiPattern | { label: string; category: PiiCategory };

/** Stores a reversible replacement in the vault, reusing an existing one when dedup is on. */
function storeReversible(
  match: string,
  pattern: RedactionPattern,
  vault: IVault,
  sessionId: string,
  dedup: boolean,
  makeToken: () => string,
): string {
  if (dedup) {
    const existing = vault.findByOriginal(sessionId, match);
    if (existing) return existing.token;
  }
  const token = makeToken();
  vault.addEntry(sessionId, {
    token,
    original: match,
    patternLabel: pattern.label,
    category: ('category' in pattern ? pattern.category : 'identity') as PiiCategory,
    createdAt: new Date().toISOString(),
  });
  return token;
}

const IRREVERSIBLE: Record<string, (match: string, label: string) => string> = {
  mask: (match, label) => maskValue(match, label),
  hash: (match, label) => `[${label}:${hashValue(match)}]`,
  redact: () => '[REDACTED]',
  blackout: (match) => '\u2588'.repeat(match.length), // visual black bars
  remove: () => '', // Complete removal, no trace left
};

/**
 * Apply redaction with proper category on the vault entry.
 */
function applyRedaction(
  match: string,
  pattern: RedactionPattern,
  mode: RedactionMode,
  vault: IVault,
  sessionId: string,
  dedup: boolean,
): string {
  if (mode === 'token') {
    return storeReversible(match, pattern, vault, sessionId, dedup, () => {
      const session = vault.getSession(sessionId);
      return generateToken(pattern.label, session ? Object.keys(session.entries).length : 0);
    });
  }
  if (mode === 'pseudonymize') {
    // The pseudonym is stored as the token so Restore can map it back.
    return storeReversible(match, pattern, vault, sessionId, dedup, () =>
      uniquePseudonym(vault, sessionId, match, pattern.label),
    );
  }
  const irreversible = IRREVERSIBLE[mode];
  return irreversible ? irreversible(match, pattern.label) : match;
}

/** Retries deterministically until the pseudonym is free in this session. */
function uniquePseudonym(vault: IVault, sessionId: string, original: string, label: string): string {
  const entries = vault.getSession(sessionId)?.entries ?? {};
  for (let attempt = 0; attempt < 32; attempt++) {
    const seed = attempt === 0 ? original : `${original}\u0000${attempt}`;
    const candidate = generatePseudonym(sessionId, seed, label);
    const taken = entries[candidate];
    if (!taken || taken.original === original) return candidate;
  }
  return generateToken(label, Object.keys(entries).length);
}

/**
 * Check if a JSON path should be processed given the field rules.
 */
function shouldProcessField(
  fieldPath: string,
  fieldMode: 'all' | 'allowlist' | 'denylist',
  fieldRules: Array<{ field: string; mode: string }>,
): boolean {
  if (fieldMode === 'all') return true;

  if (fieldMode === 'allowlist') {
    return fieldRules.some(
      (r) => r.mode === 'include' && fieldPathMatches(fieldPath, r.field),
    );
  }

  if (fieldMode === 'denylist') {
    return !fieldRules.some(
      (r) => r.mode === 'exclude' && fieldPathMatches(fieldPath, r.field),
    );
  }

  return true;
}

/**
 * Safe wildcard matching for JSON paths.
 * Escapes all regex special chars before applying wildcard transformations.
 * Supports: "user.email", "*.email", "contacts[*].phone"
 */
function fieldPathMatches(actual: string, pattern: string): boolean {
  // Escape ALL regex special characters first
  let regexStr = pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // Now unescape our wildcards
  regexStr = regexStr
    .replace(/\\\[\\*\\]/g, '\\[\\d+\\]')  // [*] -> [\d+]
    .replace(/\\[*]/g, '[^.]+');            // escaped * -> [^.]+
  try {
    return new RegExp(`^${regexStr}$`).test(actual);
  } catch {
    return false;
  }
}

/** Shared with profile parsing so both accept and refuse the same patterns. */
function isSafeRegex(regexStr: string): boolean {
  return checkRegex(regexStr) === null;
}

/**
 * Semantic field-name mapping: when the JSON key name matches,
 * redact the ENTIRE value regardless of regex matches.
 * This catches structured data where the field name IS the context.
 */
const SEMANTIC_FIELD_MAP: Array<{
  keys: RegExp;
  label: string;
  category: PiiCategory;
}> = [
  // ═══════════════════════════════════════════
  // PERSON NAMES (EN/DE/FR/ES/IT/PT/NL/SV/NO/DA/PL/RU/JA/KO/ZH/AR/TR)
  // Covers: camelCase, snake_case, PascalCase, abbreviations, prefixed, suffixed
  // ═══════════════════════════════════════════
  {
    keys: /^(?:name|first_?name|last_?name|full_?name|given_?name|family_?name|middle_?name|surname|maiden_?name|nick_?name|salutation|display_?name|contact_?name|customer_?name|client_?name|patient_?name|user_?name|member_?name|subscriber_?name|account_?name|holder_?name|card_?holder|cardholder_?name|beneficiary_?name|recipient_?name|sender_?name|author_?name|owner_?name|guardian_?name|parent_?name|spouse_?name|partner_?name|emergency_?contact|next_?of_?kin|applicant_?name|candidate_?name|student_?name|teacher_?name|employee_?name|manager_?name|supervisor_?name|guarantor|witness|signatory|cosigner|fname|lname|mname|fn|ln|mn|firstname|lastname|middlename|fullname|givenname|familyname|sur_?name|name_?first|name_?last|name_?full|legal_?name|birth_?name|married_?name|former_?name|known_?as|aka|vorname|nachname|familienname|geburtsname|anzeige_?name|kundenname|prenom|nom|nom_?de_?famille|nom_?complet|nom_?de_?jeune_?fille|nombre|apellido|apellidos|nombre_?completo|nome|cognome|nome_?completo|naam|achternaam|voornaam|volledige_?naam|fornamn|efternamn|fornavn|etternavn|imie|nazwisko|imya|familiya|sei|mei|shimei|seimei|xing|ming|xingming|isim|soyisim|soyad|ism|nasab)$/i,
    label: 'PERSON_NAME',
    category: 'identity',
  },

  // ═══════════════════════════════════════════
  // EMPLOYEE / STAFF / WORKER IDs
  // ═══════════════════════════════════════════
  {
    keys: /^(?:employee_?id|emp_?id|emp_?no|emp_?num|emp_?number|staff_?id|staff_?no|staff_?number|personnel_?(?:id|number|no|nr)|worker_?id|worker_?number|workforce_?id|badge_?(?:id|number|no)|clock_?(?:id|number)|payroll_?(?:id|number|no)|hr_?id|hr_?number|contractor_?id|temp_?id|intern_?id|associate_?id|team_?member_?id|personalnummer|mitarbeiter_?(?:id|nummer|nr|number)|arbeitnehmer_?nr|numero_?employe|matricule|numero_?dipendente|medewerkernummer|personeelsnummer|anstallningsnummer|ansattnummer|numer_?pracownika)$/i,
    label: 'EMPLOYEE_ID',
    category: 'identity',
  },

  // ═══════════════════════════════════════════
  // DEPARTMENT / DIVISION / TEAM / BUSINESS UNIT
  // ═══════════════════════════════════════════
  {
    keys: /^(?:department|dept|department_?name|dept_?name|dept_?code|division|division_?name|business_?unit|bu|cost_?center|cost_?centre|profit_?center|team|team_?name|group|group_?name|unit|unit_?name|section|section_?name|branch|branch_?name|office|office_?name|site|site_?name|location_?name|work_?location|facility|plant|factory|warehouse|abteilung|abteilungsname|bereich|referat|dienststelle|departement|service|direction|dipartimento|reparto|ufficio|afdeling|divisie|avdelning|avdeling|wydzial|dzial|otdel|bu_?name|org_?unit)$/i,
    label: 'DEPARTMENT',
    category: 'identity',
  },

  // ═══════════════════════════════════════════
  // JOB TITLE / POSITION / ROLE / DESIGNATION / OCCUPATION
  // ═══════════════════════════════════════════
  {
    keys: /^(?:position|job_?title|job_?role|job_?function|job_?type|job_?name|job_?description|job_?code|job_?level|job_?grade|job_?band|job_?family|job_?category|designation|occupation|profession|seniority|career_?level|functional_?title|working_?title|official_?title|employment_?type|contract_?type|work_?type|engagement_?type|berufsbezeichnung|stelle|stellenbezeichnung|position_?title|funktion|dienstbezeichnung|beruf|taetigkeit|poste|fonction|intitule_?du_?poste|titulo|cargo|puesto|posizione|ruolo|qualifica|mansione|functie|functietitel|befattning|stilling|stanowisko|zawod|dolzhnost|shokumei|yakushoku|zhiwei|zhicheng|gorev|unvan|pozisyon)$/i,
    label: 'JOB_TITLE',
    category: 'identity',
  },

  // ═══════════════════════════════════════════
  // SALARY / COMPENSATION / PAY / INCOME / WAGES
  // ═══════════════════════════════════════════
  {
    keys: /^(?:salary|compensation|wage|wages|income|pay|pay_?rate|hourly_?rate|daily_?rate|annual_?salary|monthly_?salary|weekly_?salary|yearly_?salary|base_?pay|base_?salary|gross_?pay|gross_?salary|net_?pay|net_?salary|take_?home|total_?comp|total_?compensation|total_?pay|total_?earnings|earnings|remuneration|stipend|allowance|bonus|bonus_?amount|commission|commission_?amount|overtime|overtime_?pay|severance|severance_?pay|pension|pension_?amount|retirement_?contribution|stock_?options|equity|rsu|vesting|deduction|deductions|tax_?withholding|withholding|benefits_?value|ctc|cost_?to_?company|package|comp_?package|offer_?amount|starting_?salary|current_?salary|previous_?salary|expected_?salary|desired_?salary|salary_?range|pay_?grade|pay_?band|pay_?scale|gehalt|brutto_?gehalt|netto_?gehalt|grundgehalt|jahresgehalt|monatsgehalt|lohn|bruttolohn|nettolohn|verguetung|entgelt|bezuege|zuschlag|praemie|provision|salaire|remuneration_?brute|remuneration_?nette|stipendio|retribuzione|salario|sueldo|remuneracao|loon|salaris|lon|lonn|wynagrodzenie|pensja|zarplata|oklad|kyuyo|nenshu|gongzi|xinshui|maas|ucret)$/i,
    label: 'SALARY',
    category: 'financial',
  },

  // ═══════════════════════════════════════════
  // DATES: Hire, Start, End, Termination, Birth, Death, etc.
  // ═══════════════════════════════════════════
  {
    keys: /^(?:hire_?date|start_?date|joining_?date|date_?of_?hire|date_?of_?joining|employment_?date|employment_?start|onboarding_?date|effective_?date|commencement_?date|appointment_?date|probation_?(?:start|end)_?date|termination_?date|end_?date|leaving_?date|resignation_?date|separation_?date|exit_?date|last_?day|last_?working_?day|notice_?date|retirement_?date|contract_?(?:start|end)_?date|trial_?(?:start|end)_?date|review_?date|appraisal_?date|promotion_?date|transfer_?date|anniversary_?date|tenure_?start|eintrittsdatum|einstellungsdatum|austrittsdatum|kuendigungsdatum|probezeitende|vertragsbeginn|vertragsende|date_?embauche|date_?de_?debut|date_?de_?fin|date_?sortie|fecha_?de_?inicio|fecha_?de_?fin|data_?assunzione|data_?cessazione|datum_?indiensttreding|datum_?uitdiensttreding|anstallningsdatum|ansettelsesdato|data_?zatrudnienia)$/i,
    label: 'EMPLOYMENT_DATE',
    category: 'temporal',
  },
  {
    keys: /^(?:dob|date_?of_?birth|birth_?date|birthday|birth_?day|born|born_?on|born_?date|geburtsdatum|geburtstag|date_?de_?naissance|fecha_?de_?nacimiento|data_?di_?nascita|geboortedatum|fodelsedatum|fodselsdato|syntymapaiva|data_?de_?nascimento|data_?urodzenia|den_?rozhdeniya|seinengappi|shengri|dogum_?tarihi)$/i,
    label: 'DOB',
    category: 'temporal',
  },
  {
    keys: /^(?:date_?of_?death|death_?date|deceased_?date|died_?on|died|sterbedatum|todesdatum|date_?de_?deces|fecha_?de_?defuncion|data_?di_?morte)$/i,
    label: 'DATE_OF_DEATH',
    category: 'temporal',
  },
  {
    keys: /^(?:person_?age|patient_?age|customer_?age|employee_?age|age_?years|current_?age|alter|edad|eta|yaş|wiek|vozrast|nenrei|nianling)$/i,
    label: 'AGE',
    category: 'temporal',
  },

  // ═══════════════════════════════════════════
  // ADDRESS / LOCATION (every variation in 15+ languages)
  // ═══════════════════════════════════════════
  {
    keys: /^(?:address|street_?address|home_?address|mailing_?address|shipping_?address|billing_?address|postal_?address|residential_?address|permanent_?address|temporary_?address|current_?address|previous_?address|work_?address|office_?address|business_?address|delivery_?address|correspondence_?address|legal_?address|registered_?address|address_?line_?[123]|addr_?[123]|addr|street|street_?name|street_?line|street_?line_?[12]|house_?number|house_?no|building|apartment|apt|flat|suite|floor|room|unit_?number|block|lot|po_?box|post_?box|city|town|municipality|village|locality|suburb|district|borough|county|state|province|region|territory|country|country_?code|country_?name|nation|zip|zip_?code|zipcode|postal_?code|postcode|post_?code|pin_?code|area_?code|geo_?location|latitude|longitude|lat|lng|coordinates|place|place_?of_?birth|birth_?place|place_?of_?residence|domicile|residence|neighborhood|neighbourhood|quarter|canton|prefecture|commune|departement|land|bundesland|kreis|bezirk|ortsteil|stadtteil|gemeinde|anschrift|adresse|wohnadresse|wohnort|strasse|hausnummer|plz|postleitzahl|ort|stadt|wohnhaft|rue|ville|code_?postal|cedex|calle|direccion|codigo_?postal|localidad|poblacion|provincia|comunidad|via|indirizzo|cap|citta|comune|straat|huisnummer|postbus|plaats|woonplaats|gata|postnummer|sted|ulica|kod_?pocztowy|miasto|adres|gorod|pochta|jyusho|jutaku|dizhi|chengshi|youbian|adres|mahalle|ilce|il|posta_?kodu)$/i,
    label: 'ADDRESS',
    category: 'location',
  },

  // ═══════════════════════════════════════════
  // PHONE / MOBILE / FAX / CONTACT NUMBERS
  // ═══════════════════════════════════════════
  {
    keys: /^(?:phone|phone_?number|phone_?no|mobile|mobile_?number|mobile_?no|cell|cell_?phone|cell_?number|telephone|tel|tel_?number|fax|fax_?number|fax_?no|contact_?number|contact_?phone|home_?phone|work_?phone|office_?phone|business_?phone|direct_?line|direct_?dial|extension|ext|callback|callback_?number|sms_?number|whatsapp|whatsapp_?number|primary_?phone|secondary_?phone|alternate_?phone|emergency_?phone|telefon|telefonnummer|mobilnummer|handy|handynummer|festnetz|rufnummer|durchwahl|faxnummer|telephone_?portable|portable|fixe|numero_?de_?telephone|numero_?de_?portable|telefono|cellulare|numero_?di_?telefono|numero_?de_?telefone|celular|telefoon|mobiel|telefoonnummer|mobilnummer_?2|telefonnr|tlf|telefon_?komorkowy|telefon_?stacjonarny|nomer_?telefona|denwabangou|keitai|dianhua|shouji|telefon_?numarasi|cep_?telefonu)$/i,
    label: 'PHONE',
    category: 'contact',
  },

  // ═══════════════════════════════════════════
  // EMAIL (every variation)
  // ═══════════════════════════════════════════
  {
    keys: /^(?:email|email_?address|e_?mail|mail|mail_?address|primary_?email|secondary_?email|work_?email|personal_?email|business_?email|contact_?email|login_?email|notification_?email|recovery_?email|backup_?email|alternate_?email|alt_?email|reply_?to|from_?email|to_?email|cc|bcc|email_?id|e_?mail_?adresse|elektronische_?post|correo|correo_?electronico|indirizzo_?email|posta_?elettronica|emailadres|epostadress|epost|adres_?email|pochta|mail_?adresi|eposta)$/i,
    label: 'EMAIL',
    category: 'contact',
  },

  // ═══════════════════════════════════════════
  // SSN / NATIONAL ID / TAX ID / GOV ID
  // ═══════════════════════════════════════════
  {
    keys: /^(?:ssn|social_?security|social_?security_?number|social_?insurance|social_?insurance_?number|sin|national_?id|national_?id_?number|national_?identity|identity_?number|identity_?card|id_?number|id_?card|id_?no|id_?document|personal_?id|personal_?number|personal_?code|citizen_?id|resident_?id|registration_?number|civil_?id|civil_?registration|gov_?id|government_?id|tax_?id|tax_?number|tax_?identification|taxpayer_?id|tin|itin|ein|vat_?number|vat_?id|steuer_?id|steuer_?nummer|steueridentifikationsnummer|steuernummer|sozialversicherungsnummer|personalausweisnummer|ausweisnummer|nif|nie|dni|cif|nif_?numero|bsn|burger_?service_?nummer|nino|national_?insurance|national_?insurance_?number|pps|pps_?number|pesel|nip|regon|personnummer|fodselsnummer|cpr|cpr_?nummer|hetu|henkilotunnus|cpf|rg|cnpj|curp|rfc|aadhaar|aadhar|pan|pan_?number|nric|fin|my_?number|rrn|ahv|avs|codice_?fiscale|carta_?identita|carte_?identite|numero_?securite_?sociale|nir|rijksregisternummer|numero_?identite|kimlik|tc_?kimlik|emirates_?id|iqama)$/i,
    label: 'NATIONAL_ID',
    category: 'identity',
  },

  // ═══════════════════════════════════════════
  // BANK ACCOUNT / FINANCIAL ACCOUNTS
  // ═══════════════════════════════════════════
  {
    keys: /^(?:account_?number|account_?no|acct|acct_?number|acct_?no|bank_?account|bank_?account_?number|bank_?acct|checking_?account|savings_?account|current_?account|deposit_?account|iban|bic|swift|swift_?code|routing_?number|routing_?no|aba|sort_?code|bsb|bsb_?number|clabe|transit_?number|branch_?code|branch_?number|kontonummer|bankleitzahl|blz|konto|girokonto|sparkonto|numero_?de_?compte|rib|numero_?conto|numero_?de_?cuenta|rekeningnummer|bankgiro|plusgiro|numer_?konta|schet|kouza_?bangou)$/i,
    label: 'ACCOUNT_NUMBER',
    category: 'financial',
  },

  // ═══════════════════════════════════════════
  // CREDIT / DEBIT CARD
  // ═══════════════════════════════════════════
  {
    keys: /^(?:card_?number|credit_?card|credit_?card_?number|debit_?card|debit_?card_?number|cc_?number|cc_?no|pan|card_?no|card_?num|payment_?card|kartennummer|kreditkarte|kreditkartennummer|numero_?de_?carte|numero_?carta|numero_?de_?tarjeta|kaartnummer|cvv|cvc|cvv2|cvc2|cid|security_?code|card_?verification|card_?expiry|expiry_?date|expiration_?date|exp_?date|valid_?thru|valid_?through|card_?holder|cardholder_?name)$/i,
    label: 'CREDIT_CARD',
    category: 'financial',
  },

  // ═══════════════════════════════════════════
  // INSURANCE (health, life, auto, property, etc.)
  // ═══════════════════════════════════════════
  {
    keys: /^(?:insurance|insurance_?(?:id|number|no|policy|claim|type|provider|company|plan|group)|policy_?(?:number|no|id)|policy_?holder|claim_?(?:number|no|id|ref|reference)|health_?plan|health_?plan_?id|member_?id|member_?number|subscriber_?id|subscriber_?number|beneficiary_?id|beneficiary_?number|group_?number|group_?id|plan_?id|plan_?number|coverage_?id|enrollment_?id|certificate_?number|versicherungsnummer|versicherung|krankenversicherung|krankenkasse|police_?nummer|police_?nr|numero_?assurance|numero_?police|polizza|numero_?polizza|numero_?de_?seguro|verzekeringsnummer|polisnummer)$/i,
    label: 'INSURANCE',
    category: 'financial',
  },

  // ═══════════════════════════════════════════
  // PASSPORT
  // ═══════════════════════════════════════════
  {
    keys: /^(?:passport|passport_?number|passport_?no|passport_?id|passport_?num|travel_?document|travel_?doc_?number|reisepass|reisepassnummer|passnummer|numero_?passeport|passeport|passaporto|numero_?passaporto|numero_?de_?pasaporte|paspoort|paspoortnummer|passnummer_?2|pass_?nr|pasaporte|pasaporte_?numero)$/i,
    label: 'PASSPORT',
    category: 'identity',
  },

  // ═══════════════════════════════════════════
  // DRIVER LICENSE
  // ═══════════════════════════════════════════
  {
    keys: /^(?:driver_?license|drivers_?license|driver_?licence|drivers_?licence|driving_?license|driving_?licence|dl|dl_?number|dl_?no|license_?number|licence_?number|license_?no|licence_?no|permit_?number|learner_?permit|fuehrerschein|fuehrerscheinnummer|permis_?de_?conduire|numero_?permis|patente|patente_?di_?guida|permiso_?de_?conducir|carnet_?de_?conducir|rijbewijs|rijbewijsnummer|koerkort|forerkort|prawo_?jazdy|voditelskoe_?udostoverenie|unten_?menkyo|jiashi_?zheng|ehliyet|surucu_?belgesi)$/i,
    label: 'DRIVER_LICENSE',
    category: 'identity',
  },

  // ═══════════════════════════════════════════
  // MEDICAL / HEALTH / PATIENT
  // ═══════════════════════════════════════════
  {
    keys: /^(?:mrn|medical_?record|medical_?record_?number|patient_?id|patient_?number|patient_?name|health_?id|health_?card|health_?number|hospital_?id|hospital_?number|chart_?number|case_?number|encounter_?id|visit_?id|admission_?id|discharge_?id|diagnosis|diagnosis_?code|icd|icd_?code|icd_?10|procedure_?code|cpt|cpt_?code|ndc|ndc_?code|medication|medications|drug|drug_?name|prescription|prescription_?id|rx|rx_?number|dosage|blood_?type|blood_?group|allergy|allergies|condition|conditions|medical_?condition|disability|disability_?status|disability_?type|disability_?degree|impairment|mental_?health|psychiatric|immunization|vaccination|vaccine|lab_?result|test_?result|vital_?signs|bmi|weight|height|npi|npi_?number|dea|dea_?number|provider_?id|physician_?id|doctor_?name|treating_?physician|primary_?care|attending|referring|insurance_?diagnosis|pre_?existing|chronic|krankenakte|patientennummer|diagnose|medikament|rezept|blutgruppe|behinderung|grad_?der_?behinderung|gdb|schwerbehindertenausweis|dossier_?medical|numero_?patient|groupe_?sanguin|cartella_?clinica|historia_?clinica|prontuario)$/i,
    label: 'MEDICAL',
    category: 'medical',
  },

  // ═══════════════════════════════════════════
  // COMPANY / ORGANIZATION / EMPLOYER / BUSINESS
  // ═══════════════════════════════════════════
  {
    keys: /^(?:company|company_?name|organization|organisation|org|org_?name|employer|employer_?name|business|business_?name|corporation|corp|corp_?name|subsidiary|parent_?company|holding|group_?name|entity|entity_?name|legal_?entity|legal_?name|registered_?name|trading_?name|brand|brand_?name|vendor|vendor_?name|supplier|supplier_?name|partner|partner_?name|client|client_?name|agency|agency_?name|institute|institution|school|school_?name|university|university_?name|college|hospital|hospital_?name|practice|practice_?name|firm|firm_?name|llc|gmbh|ag|inc|ltd|plc|sa|srl|bv|nv|firma|unternehmen|unternehmensname|arbeitgeber|betrieb|handelsname|societe|raison_?sociale|denominazione|ragione_?sociale|empresa|nombre_?empresa|bedrijf|bedrijfsnaam|werkgever|foretag|arbetsgivare|virksomhed|arbejdsgiver|firma_?2|spolka|pracodawca|kompaniya|rabotodatel|kaisha|kigyou|gongsi|guyong_?danwei|sirket|isveren)$/i,
    label: 'COMPANY',
    category: 'identity',
  },

  // ═══════════════════════════════════════════
  // EDUCATION / ACADEMIC
  // ═══════════════════════════════════════════
  {
    keys: /^(?:student_?id|student_?number|student_?name|enrollment_?id|enrollment_?number|matriculation|matriculation_?number|matrikel|matrikelnummer|gpa|grade_?point|test_?score|sat_?score|act_?score|gre_?score|gmat_?score|degree|diploma|qualification|major|minor|field_?of_?study|program|faculty|school_?name|university|college|campus|class_?of|graduation|graduation_?date|grad_?year|transcript|academic_?record|education_?level|highest_?education|studiengang|abschluss|zeugnis|schulname|hochschule|diplome|scolarite|titolo_?di_?studio|expediente)$/i,
    label: 'EDUCATION',
    category: 'identity',
  },

  // ═══════════════════════════════════════════
  // VEHICLE / TRANSPORT
  // ═══════════════════════════════════════════
  {
    keys: /^(?:vin|vehicle_?identification|vehicle_?id|vehicle_?number|chassis_?number|license_?plate|plate_?number|plate_?no|registration|registration_?number|reg_?number|reg_?no|tag_?number|kennzeichen|fahrzeug_?id|fahrgestellnummer|immatriculation|plaque|targa|matricula|kenteken|registreringsnummer|numer_?rejestracyjny)$/i,
    label: 'VEHICLE',
    category: 'vehicle',
  },

  // ═══════════════════════════════════════════
  // CREDENTIALS / AUTH / SECRETS / TOKENS
  // ═══════════════════════════════════════════
  {
    keys: /^(?:password|passwd|pwd|pass_?word|secret|secret_?key|api_?key|api_?secret|api_?token|access_?token|refresh_?token|auth_?token|bearer_?token|session_?token|session_?key|private_?key|encryption_?key|signing_?key|master_?key|client_?secret|consumer_?key|consumer_?secret|oauth_?token|credentials|passwort|kennwort|schluessel|mot_?de_?passe|contrasena|clave|senha|wachtwoord|sleutel|losenord|haslo|parol|mima|sifre)$/i,
    label: 'CREDENTIAL',
    category: 'enterprise',
  },

  // ═══════════════════════════════════════════
  // RACE / ETHNICITY / NATIONALITY / CITIZENSHIP
  // ═══════════════════════════════════════════
  {
    keys: /^(?:race|ethnicity|ethnic|ethnic_?origin|ethnic_?group|nationality|citizenship|national_?origin|heritage|ancestry|background|rasse|herkunft|ethnische_?herkunft|nationalitaet|staatsangehoerigkeit|ethnie|origine|nationalite|citoyennete|raza|etnia|nacionalidad|ciudadania|razza|nazionalita|cittadinanza|nationaliteit|etnicitet|medborgarskap|narodowsc|rasa|natsionalnost|grazhdanstvo|kokuseki|minzu|guoji|milliyet|vatandaslik|uyruk)$/i,
    label: 'ETHNICITY',
    category: 'identity',
  },

  // ═══════════════════════════════════════════
  // RELIGION / BELIEF / POLITICAL
  // ═══════════════════════════════════════════
  {
    keys: /^(?:religion|religious|religious_?affiliation|religious_?belief|faith|creed|denomination|confession|church|mosque|synagogue|temple|spiritual|belief|philosophical_?belief|political_?(?:party|affiliation|opinion|preference|view)|party|party_?membership|union|union_?membership|trade_?union|konfession|religionszugehoerigkeit|glaubensbekenntnis|kirchenzugehoerigkeit|politische_?partei|gewerkschaft|religion_?2|culte|parti_?politique|syndicat|partido_?politico|sindicato|religie|politieke_?partij|vakbond|religion_?3|tro|parti|fagforening|religia|partia|zwiazek_?zawodowy|religiya|partiya|profsoyuz|shukyo|seitou|zongjiao|dangpai|din|mezhep|parti_?2|sendika)$/i,
    label: 'BELIEF_POLITICAL',
    category: 'identity',
  },

  // ═══════════════════════════════════════════
  // GENDER / SEX / MARITAL STATUS / FAMILY
  // ═══════════════════════════════════════════
  {
    keys: /^(?:gender|sex|gender_?identity|sexual_?orientation|sexuality|preferred_?pronouns|pronouns|marital_?status|civil_?status|relationship_?status|marriage|married|single|divorced|widowed|separated|domestic_?partner|spouse|partner|family_?status|number_?of_?(?:children|kids|dependents)|dependents|geschlecht|familienstand|sexuelle_?orientierung|sexe|etat_?civil|orientation_?sexuelle|genero|estado_?civil|orientacion_?sexual|sesso|stato_?civile|geslacht|burgerlijke_?staat|kon|civilstand|plec|stan_?cywilny|pol|semeynoe_?polozhenie|seibetsu|xingbie|hunyin|cinsiyet|medeni_?hal)$/i,
    label: 'PERSONAL_STATUS',
    category: 'identity',
  },

  // ═══════════════════════════════════════════
  // LEGAL / JUDICIAL / CRIMINAL
  // ═══════════════════════════════════════════
  {
    keys: /^(?:case_?number|case_?id|case_?ref|docket|docket_?number|court|court_?name|judge|attorney|lawyer|legal_?representative|legal_?counsel|criminal_?record|conviction|offense|offence|charge|charges|sentence|verdict|probation|parole|arrest|arrest_?date|booking|booking_?number|inmate|prisoner|offender|inmate_?(?:id|number)|mugshot|fingerprint|warrant|bail|bond|aktenzeichen|gerichtsaktenzeichen|strafregister|vorstrafe|verurteilung|anwalt|rechtsanwalt|richter|numero_?affaire|casier_?judiciaire|condamnation|avocat|juge|numero_?expediente|antecedentes_?penales|condena|abogado|juez)$/i,
    label: 'LEGAL',
    category: 'identity',
  },

  // ═══════════════════════════════════════════
  // BIOMETRIC / PHYSICAL CHARACTERISTICS
  // ═══════════════════════════════════════════
  {
    keys: /^(?:biometric|fingerprint|face_?id|facial|facial_?recognition|iris|retina|voiceprint|voice_?id|palm_?print|hand_?geometry|dna|genetic|genome|genotype|karyotype|blood_?type|blood_?group|eye_?color|hair_?color|skin_?color|height|weight|bmi|body_?mass|distinguishing_?marks|tattoo|scar|birthmark|photo|photograph|picture|image|avatar|headshot|portrait|mugshot|selfie|foto|bild|lichtbild|passfoto|passbild)$/i,
    label: 'BIOMETRIC',
    category: 'biometric',
  },

  // ═══════════════════════════════════════════
  // UTILITY / SUBSCRIPTION / LOYALTY / MEMBERSHIP
  // ═══════════════════════════════════════════
  {
    keys: /^(?:utility_?(?:account|number|id)|electricity_?(?:account|number)|gas_?(?:account|number)|water_?(?:account|number)|meter_?(?:number|id)|customer_?(?:number|id|no)|account_?(?:id|ref)|reference_?(?:number|id|no|code)|subscription_?(?:id|number)|membership_?(?:id|number|no)|member_?(?:number|no)|loyalty_?(?:id|number|card)|rewards?_?(?:id|number|card)|frequent_?flyer|frequent_?flyer_?(?:number|id)|mileage_?(?:number|id)|points_?(?:id|number)|library_?(?:card|id|number)|kundennummer|mitgliedsnummer|abonnement|vertragsnummer)$/i,
    label: 'ACCOUNT_REF',
    category: 'financial',
  },

  // ═══════════════════════════════════════════
  // IP / HOSTNAME / SERVER / NETWORK
  // ═══════════════════════════════════════════
  {
    keys: /^(?:ip|ip_?address|ipv4|ipv6|server|server_?name|server_?address|hostname|host|host_?name|domain|domain_?name|mac|mac_?address|subnet|gateway|proxy|vpn|dns|url|uri|endpoint|api_?url|webhook_?url|callback_?url|redirect_?url|origin|referrer|referer|user_?agent|device_?id|device_?name|machine_?name|computer_?name|workstation)$/i,
    label: 'NETWORK',
    category: 'network',
  },

  // ═══════════════════════════════════════════
  // CONTRACTS / INVOICES / LEGAL DOCUMENTS
  // ═══════════════════════════════════════════
  {
    keys: /^(?:contract_?(?:number|no|id|ref)|invoice_?(?:number|no|id|ref)|order_?(?:number|no|id|ref)|purchase_?order|po_?(?:number|no)|quote_?(?:number|no|id)|proposal_?(?:number|no|id)|agreement_?(?:number|no|id)|reference_?(?:number|no)|receipt_?(?:number|no|id)|transaction_?(?:id|ref|number)|payment_?(?:id|ref|reference)|billing_?(?:id|ref|number)|Rechnungsnummer|Vertragsnummer|Auftragsnummer|Bestellnummer|Angebotsnummer|numero_?(?:facture|contrat|commande)|numero_?(?:fattura|contratto|ordine))$/i,
    label: 'DOCUMENT_REF',
    category: 'financial',
  },

  // ═══════════════════════════════════════════
  // FINANCIAL AMOUNTS / REVENUE / SENSITIVE NUMBERS
  // ═══════════════════════════════════════════
  {
    keys: /^(?:amount|total|subtotal|grand_?total|tax_?amount|vat_?amount|discount|balance|outstanding|due|paid|refund|credit|debit|revenue|profit|loss|margin|cost|price|unit_?price|net_?amount|gross_?amount|fee|charge|interest|penalty|fine|deposit|withdrawal|transfer_?amount|Betrag|Gesamtbetrag|Steuerbetrag|Rabatt|Saldo|montant|somme|total_?ttc|total_?ht|importe|monto|importo)$/i,
    label: 'FINANCIAL_AMOUNT',
    category: 'financial',
  },

  // ═══════════════════════════════════════════
  // SIGNATURE / AUTHORIZATION / CONSENT
  // ═══════════════════════════════════════════
  {
    keys: /^(?:signature|signed_?by|authorized_?by|approved_?by|witnessed_?by|notarized_?by|certified_?by|consent|consent_?date|consent_?given|power_?of_?attorney|proxy|delegate|Unterschrift|unterzeichnet_?von|genehmigt_?von|Vollmacht)$/i,
    label: 'SIGNATURE',
    category: 'identity',
  },

  // ═══════════════════════════════════════════
  // BANK / PAYMENT DETAILS IN DOCUMENTS
  // ═══════════════════════════════════════════
  {
    keys: /^(?:bank_?name|bank|branch|branch_?name|beneficiary|beneficiary_?name|beneficiary_?account|payer|payer_?name|payee|payee_?name|remitter|sender_?(?:name|account|bank)|receiver_?(?:name|account|bank)|correspondent_?bank|intermediary_?bank|Bankname|Begünstigter|Zahlungsempfänger|Auftraggeber)$/i,
    label: 'BANK_DETAIL',
    category: 'financial',
  },

  // ═══════════════════════════════════════════
  // TAX / FISCAL DETAILS
  // ═══════════════════════════════════════════
  {
    keys: /^(?:tax_?(?:rate|class|bracket|status|year|period|return|filing)|fiscal_?(?:year|period|code)|withholding|exemption|deductible|taxable_?(?:income|amount)|gross_?income|net_?income|adjusted_?gross|agi|Steuerklasse|Steuerjahr|Steuererklärung|Freibetrag)$/i,
    label: 'TAX_DETAIL',
    category: 'financial',
  },

  // ═══════════════════════════════════════════
  // LANGUAGE / CULTURAL IDENTITY (GDPR Art.9)
  // ═══════════════════════════════════════════
  {
    keys: /^(?:language|mother_?tongue|native_?language|spoken_?language|preferred_?language|first_?language|primary_?language|sprache|muttersprache|langue|langue_?maternelle|idioma|lengua|lingua|taal|moedertaal|sprak|jezyk|yazyk|gengo|yuyan|dil|ana_?dil)$/i,
    label: 'LANGUAGE',
    category: 'identity',
  },

  // ═══════════════════════════════════════════
  // NOTES / FREE TEXT (run regex, don't redact whole value)
  // ═══════════════════════════════════════════
  {
    keys: /^(?:notes|note|comment|comments|description|desc|message|msg|body|text|content|remarks|remark|internal_?notes|agent_?notes|case_?notes|memo|memorandum|narrative|summary|abstract|details|detail|reason|explanation|history|log|changelog|audit|feedback|review|observation|assessment|evaluation|recommendation|instruction|instructions|notizen|bemerkung|kommentar|beschreibung|nachricht|anmerkung|vermerk|remarques|commentaire|observation_?2|nota|commento|descrizione|notas|comentario|descripcion|opmerkingen|beschrijving|anteckningar|kommentar_?2|uwagi|komentarz|opis|zametki|kommentariy|opisanie|bikou|beikou|beizhu|shuoming|not|aciklama|yorum)$/i,
    label: '',
    category: 'identity',
  },
];

/**
 * Ambiguous field names that MIGHT be personal data depending on context.
 * Only redacted when sibling fields suggest this is a person/PII record.
 */
const AMBIGUOUS_FIELDS: RegExp = /^(?:id|code|number|no|num|nr|ref|reference|key|identifier|value|data|info|source|origin|created_?by|updated_?by|modified_?by|assigned_?to|owned_?by|submitted_?by|requested_?by|approved_?by|reviewed_?by|reported_?by|signed_?by|verified_?by|processed_?by|handled_?by|managed_?by|contact|details|record|entry|item|subject|party|counterparty|client_?id|customer_?id|user_?id|member_?id|patient_?id|case_?id|ticket_?id|account_?id|subscriber_?id)$/i;

/**
 * Fields that CONFIRM the parent object is about a person/entity with PII.
 * If any sibling field matches this, ambiguous fields get redacted too.
 */
const PII_INDICATOR_FIELDS: RegExp = /^(?:name|first_?name|last_?name|full_?name|email|phone|mobile|ssn|iban|address|dob|birth|birthday|passport|salary|compensation|national_?id|tax_?id|nino|bsn|pesel|cpf|aadhaar|vorname|nachname|nom|prenom|nombre|apellido|nome|cognome|social_?security|employee_?id|patient_?name|customer_?name|contact_?name)$/i;

/**
 * Check if a field key matches a semantic field and should be fully redacted.
 * Returns the label if the entire value should be redacted, empty string if
 * regex scanning should be used, or null if no semantic match.
 */
function getSemanticLabel(fieldKey: string, siblingKeys?: string[]): { label: string; category: PiiCategory } | null {
  // Extract the last key segment (e.g., "user.profile.name" -> "name")
  const lastKey = fieldKey.includes('.') ? fieldKey.split('.').pop()! : fieldKey;
  // Also try the key without array indices (e.g., "contacts[0].name" -> "name")
  const cleanKey = lastKey.replace(/\[\d+\]/g, '');

  // First check explicit semantic mappings
  for (const mapping of SEMANTIC_FIELD_MAP) {
    if (mapping.keys.test(cleanKey)) {
      return { label: mapping.label, category: mapping.category };
    }
  }

  // Context-aware: if field is ambiguous (like bare "id") AND sibling fields
  // indicate this is a person/PII record, redact the ambiguous field too.
  if (siblingKeys && AMBIGUOUS_FIELDS.test(cleanKey)) {
    const hasPiiSiblings = siblingKeys.some((k) => PII_INDICATOR_FIELDS.test(k));
    if (hasPiiSiblings) {
      return { label: 'IDENTIFIER', category: 'identity' };
    }
  }

  return null;
}

/** Replaces a whole value whose field name says what it is. Returns null when not applicable. */
function redactSemantic(
  raw: string,
  ctx: RedactionContext,
  vault: IVault,
  sessionId: string,
  hits: RedactionHit[],
  itemIndex: number,
  path: string,
  display: string,
  siblingKeys?: string[],
): string | null {
  const semantic = getSemanticLabel(path, siblingKeys);
  if (!semantic || !semantic.label || raw.trim().length === 0) return null;
  if (isAllowListed(raw, ctx.allowList)) return null;
  const semConf = semantic.label === 'IDENTIFIER' ? AMBIGUOUS_FIELD_CONFIDENCE : SEMANTIC_CONFIDENCE;
  if (semConf < (ctx.confidenceThreshold ?? 0)) return null;
  const replacement = applyRedaction(
    raw, { label: semantic.label, category: semantic.category }, ctx.mode, vault, sessionId, ctx.dedup,
  );
  hits.push({
    token: replacement, original: '***',
    patternName: `semantic_${semantic.label}`,
    patternLabel: semantic.label,
    category: semantic.category,
    field: display, itemIndex,
    confidence: semConf,
  });
  return replacement;
}

/** Numbers keep their type unless a semantic field or, when scanning numbers, a pattern claims them. */
function redactNumber(
  value: number,
  ctx: RedactionContext,
  vault: IVault,
  sessionId: string,
  hits: RedactionHit[],
  itemIndex: number,
  path: string,
  display: string,
  siblingKeys?: string[],
): unknown {
  const text = String(value);
  if (!ctx.skipSemantic) {
    const semantic = redactSemantic(text, ctx, vault, sessionId, hits, itemIndex, path, display, siblingKeys);
    if (semantic !== null) return semantic;
  }
  if (!ctx.scanNumbers) return value;
  const scanned = redactText(text, ctx, vault, sessionId, hits, itemIndex, display);
  return scanned === text ? value : scanned;
}

/** Keys can carry PII too, so they are scanned like text and kept unique within the object. */
function redactKey(
  key: string,
  taken: Record<string, unknown>,
  ctx: RedactionContext,
  vault: IVault,
  sessionId: string,
  itemIndex: number,
  keyHits: RedactionHit[],
): string {
  let out = redactText(key, ctx, vault, sessionId, keyHits, itemIndex, '');
  if (out === key) return key;
  const base = out;
  for (let n = 1; out === '' || out in taken; n++) out = `${base}_${n}`;
  return out;
}

function redactObject(
  value: Record<string, unknown>,
  ctx: RedactionContext,
  vault: IVault,
  sessionId: string,
  hits: RedactionHit[],
  itemIndex: number,
  path: string,
  display: string,
): Record<string, unknown> {
  const entries = Object.entries(value);
  const siblingKeys = entries.map(([k]) => k);
  const obj: Record<string, unknown> = {};
  for (const [k, v] of entries) {
    const fieldPath = path ? `${path}.${k}` : k;
    const keyHits: RedactionHit[] = [];
    const outKey = shouldProcessField(fieldPath, ctx.fieldMode, ctx.fieldRules)
      ? redactKey(k, obj, ctx, vault, sessionId, itemIndex, keyHits)
      : k;
    const childDisplay = display ? `${display}.${outKey}` : outKey;
    for (const h of keyHits) hits.push({ ...h, field: childDisplay });
    obj[outKey] = redactValue(v, ctx, vault, sessionId, hits, itemIndex, fieldPath, siblingKeys, childDisplay);
  }
  return obj;
}

/** Walks JSON and redacts with semantic field names and patterns. */
// currentPath keeps original keys for field rules; displayPath is the redacted path for reports.
export function redactValue(
  value: unknown,
  ctx: RedactionContext,
  vault: IVault,
  sessionId: string,
  hits: RedactionHit[],
  itemIndex: number,
  currentPath: string = '',
  siblingKeys?: string[],
  displayPath: string = currentPath,
): unknown {
  const processed = shouldProcessField(currentPath, ctx.fieldMode, ctx.fieldRules);
  if (typeof value === 'string') {
    if (!processed) return value;
    if (!ctx.skipSemantic) {
      const semantic = redactSemantic(value, ctx, vault, sessionId, hits, itemIndex, currentPath, displayPath, siblingKeys);
      if (semantic !== null) return semantic;
    }
    return redactText(value, ctx, vault, sessionId, hits, itemIndex, displayPath);
  }

  if (typeof value === 'number') {
    if (!processed) return value;
    return redactNumber(value, ctx, vault, sessionId, hits, itemIndex, currentPath, displayPath, siblingKeys);
  }

  if (Array.isArray(value)) {
    return value.map((v, i) =>
      redactValue(v, ctx, vault, sessionId, hits, itemIndex, `${currentPath}[${i}]`, undefined, `${displayPath}[${i}]`),
    );
  }

  if (value !== null && typeof value === 'object') {
    return redactObject(value as Record<string, unknown>, ctx, vault, sessionId, hits, itemIndex, currentPath, displayPath);
  }

  return value;
}

/**
 * Redact PII in a text string.
 */
function redactText(
  text: string,
  ctx: RedactionContext,
  vault: IVault,
  sessionId: string,
  hits: RedactionHit[],
  itemIndex: number,
  fieldPath: string,
): string {
  let result = text;
  const threshold = ctx.confidenceThreshold ?? 0;

  // ─── DENY LIST: always redact these values first ───
  if (ctx.denyList && ctx.denyList.length > 0) {
    for (const entry of ctx.denyList) {
      try {
        let re: RegExp;
        switch (entry.type) {
          case 'regex':
            if (!isSafeRegex(entry.value)) continue;
            re = new RegExp(entry.value, 'gi');
            break;
          case 'contains':
            re = new RegExp(entry.value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
            break;
          default: // exact — use escaped string without \b to match #SECRET, @values etc.
            re = new RegExp(entry.value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
        }
        result = result.replace(re, (match) => {
          if (TOKEN_RE.test(match)) return match;
          const replacement = applyRedaction(
            match, { label: 'DENY_LIST', category: 'other' as PiiCategory }, ctx.mode, vault, sessionId, ctx.dedup,
          );
          hits.push({
            token: replacement, original: '***',
            patternName: 'denyList', patternLabel: 'DENY_LIST',
            category: 'other', field: fieldPath, itemIndex,
            confidence: DENY_LIST_CONFIDENCE,
          });
          return replacement;
        });
      } catch { /* skip invalid */ }
    }
  }

  // ─── BUILT-IN PATTERNS with confidence scoring ───
  // Checksum-validated patterns (IBAN, cards) claim their text first, so a loose
  // pattern such as a phone number cannot grab digits from inside them.
  const enabled = getPatternsByNames(ctx.enabledPatterns);
  const activePatterns = [...enabled.filter((p) => p.validate), ...enabled.filter((p) => !p.validate)];
  for (const pattern of activePatterns) {
    const re = new RegExp(pattern.regex.source, pattern.regex.flags);
    result = result.replace(re, (match, ...args) => {
      // Skip already-redacted tokens
      if (TOKEN_RE.test(match) || (match.startsWith('[') && match.endsWith(']'))) return match;

      // Run validator if present
      const validatorPassed = pattern.validate ? pattern.validate(match) : true;
      if (pattern.validate && !validatorPassed) return match;

      // Allow list check: skip if value is allow-listed
      if (isAllowListed(match, ctx.allowList)) return match;

      // Calculate confidence score
      const matchOffset = typeof args[args.length - 2] === 'number' ? args[args.length - 2] : 0;
      const confidence = calculateConfidence(
        pattern.name, !!pattern.validate, validatorPassed,
        text, matchOffset, matchOffset + match.length,
      );

      // Skip if below confidence threshold
      if (confidence < threshold) return match;

      const replacement = applyRedaction(
        match, pattern, ctx.mode, vault, sessionId, ctx.dedup,
      );

      hits.push({
        token: replacement, original: '***',
        patternName: pattern.name, patternLabel: pattern.label,
        category: pattern.category, field: fieldPath, itemIndex,
        confidence,
      });

      return replacement;
    });
  }

  // ─── NAME DICTIONARY detection (free-text names) ───
  if (!ctx.skipSemantic) {
    const nameMatches = detectNamesInText(result);
    for (const nm of nameMatches) {
      // Skip if already redacted (contains token brackets)
      if (nm.name.includes('[') && nm.name.includes(']')) continue;

      // Allow list check
      if (isAllowListed(nm.name, ctx.allowList)) continue;

      // Calculate confidence with context words
      let nameConfidence = 0.65;
      if (hasContextWords(text, nm.start, nm.end, NAME_CONTEXT_WORDS)) {
        nameConfidence = 0.80;
      }

      if (nameConfidence < threshold) continue;

      const replacement = applyRedaction(
        nm.name, { label: 'PERSON_NAME', category: 'identity' as PiiCategory },
        ctx.mode, vault, sessionId, ctx.dedup,
      );

      // Replace in result
      result = result.split(nm.name).join(replacement);

      hits.push({
        token: replacement, original: '***',
        patternName: 'personNameDict', patternLabel: 'PERSON_NAME',
        category: 'identity', field: fieldPath, itemIndex,
        confidence: nameConfidence,
      });
    }
  }

  // ─── CUSTOM PATTERNS with safety validation ───
  for (const cp of ctx.customPatterns) {
    if (!cp.label || !cp.regex) continue;
    if (!isSafeRegex(cp.regex)) continue;
    try {
      const re = new RegExp(cp.regex, 'g');
      result = result.replace(re, (match) => {
        if (TOKEN_RE.test(match)) return match;
        if (isAllowListed(match, ctx.allowList)) return match;

        if (CUSTOM_PATTERN_CONFIDENCE < threshold) return match;

        const pseudoPattern = {
          label: cp.label.toUpperCase(),
          category: (cp.category as PiiCategory) || 'identity',
        };

        const replacement = applyRedaction(
          match, pseudoPattern, ctx.mode, vault, sessionId, ctx.dedup,
        );

        hits.push({
          token: replacement, original: '***',
          patternName: `custom_${cp.label}`, patternLabel: pseudoPattern.label,
          category: pseudoPattern.category, field: fieldPath, itemIndex,
          confidence: CUSTOM_PATTERN_CONFIDENCE,
        });

        return replacement;
      });
    } catch {
      // Skip invalid regex
    }
  }

  return result;
}

/** Single pass over the source string, so an inserted original is never rescanned as a token. */
function makeRestorer(entries: Record<string, { original: string }>): (text: string) => string {
  const tokens = Object.keys(entries).filter((t) => t.length > 0).sort((a, b) => b.length - a.length);
  if (tokens.length === 0) return (text) => text;
  const re = new RegExp(tokens.map((t) => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'), 'g');
  return (text) => text.replace(re, (token) => entries[token].original);
}

function restoreWith(value: unknown, restore: (text: string) => string): unknown {
  if (typeof value === 'string') return restore(value);
  if (Array.isArray(value)) return value.map((v) => restoreWith(v, restore));
  if (value !== null && typeof value === 'object') {
    const obj: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      obj[restore(k)] = restoreWith(v, restore);
    }
    return obj;
  }
  return value;
}

/**
 * Restore redacted tokens back to original values, in values and in keys.
 */
export function restoreValue(value: unknown, vault: IVault, sessionId: string): unknown {
  const session = vault.getSession(sessionId);
  if (!session) return value;
  return restoreWith(value, makeRestorer(session.entries));
}

interface Span {
  start: number;
  end: number;
  score: number;
  entityType: string;
}

/** Presidio reports Python code point offsets. JavaScript strings index UTF-16 units. */
function toUtf16Spans(text: string, entities: Array<{ entity_type: string; start: number; end: number; score: number }>): Span[] {
  const offsets = [0];
  for (const ch of text) offsets.push(offsets[offsets.length - 1] + ch.length);
  return entities
    .filter((e) => Number.isInteger(e.start) && Number.isInteger(e.end) && e.start >= 0 && e.end > e.start && e.end < offsets.length)
    .map((e) => ({ start: offsets[e.start], end: offsets[e.end], score: e.score, entityType: e.entity_type }));
}

/** Keeps the strongest span in each overlapping region: higher score, then longer. */
function resolveOverlaps(spans: Span[]): Span[] {
  const ranked = [...spans].sort((a, b) => b.score - a.score || (b.end - b.start) - (a.end - a.start) || a.start - b.start);
  const kept: Span[] = [];
  for (const span of ranked) {
    if (!kept.some((k) => span.start < k.end && k.start < span.end)) kept.push(span);
  }
  return kept.sort((a, b) => b.start - a.start);
}

async function presidioRedactString(
  value: string,
  ctx: RedactionContext,
  vault: IVault,
  sessionId: string,
  hits: RedactionHit[],
  itemIndex: number,
  path: string,
): Promise<string> {
  if (value.trim().length === 0 || TOKEN_RE.test(value)) return value;
  const entities = await analyzeWithPresidio(
    ctx.presidioUrl!, value, ctx.presidioLanguage || 'en', 0.4, 10000, ctx.presidioRequest,
  );
  const threshold = ctx.confidenceThreshold ?? 0;
  const spans = resolveOverlaps(toUtf16Spans(value, entities).filter((s) => s.score >= threshold));
  let text = value;
  for (const span of spans) {
    const matchedText = value.slice(span.start, span.end);
    if (TOKEN_RE.test(matchedText) || (matchedText.startsWith('[') && matchedText.endsWith(']'))) continue;
    if (isAllowListed(matchedText, ctx.allowList)) continue;
    const label = getRedactorLabel(span.entityType);
    const category = getRedactorCategory(span.entityType) as PiiCategory;
    const replacement = applyRedaction(matchedText, { label, category }, ctx.mode, vault, sessionId, ctx.dedup);
    text = text.slice(0, span.start) + replacement + text.slice(span.end);
    hits.push({
      token: replacement, original: '***',
      patternName: `presidio_${span.entityType}`, patternLabel: label,
      category, field: path, itemIndex, confidence: span.score,
    });
  }
  return text;
}

async function presidioWalk(
  value: unknown,
  ctx: RedactionContext,
  vault: IVault,
  sessionId: string,
  hits: RedactionHit[],
  itemIndex: number,
  path: string,
): Promise<unknown> {
  if (typeof value === 'string') {
    if (!shouldProcessField(path, ctx.fieldMode, ctx.fieldRules)) return value;
    try {
      return await presidioRedactString(value, ctx, vault, sessionId, hits, itemIndex, path);
    } catch {
      return value; // Presidio failed for this field. Regex results stand.
    }
  }
  if (Array.isArray(value)) {
    const out: unknown[] = [];
    for (let i = 0; i < value.length; i++) out.push(await presidioWalk(value[i], ctx, vault, sessionId, hits, itemIndex, `${path}[${i}]`));
    return out;
  }
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = await presidioWalk(v, ctx, vault, sessionId, hits, itemIndex, path ? `${path}.${k}` : k);
    }
    return out;
  }
  return value;
}

/**
 * Run Presidio NLP analysis on every string in an item, in objects and arrays alike,
 * honouring the same field rules as regex redaction. Called AFTER regex-based redaction.
 */
export async function enhanceWithPresidio(
  data: Record<string, unknown>,
  ctx: RedactionContext,
  vault: IVault,
  sessionId: string,
  hits: RedactionHit[],
  itemIndex: number,
): Promise<Record<string, unknown>> {
  if (!ctx.presidioUrl) return data;
  return (await presidioWalk(data, ctx, vault, sessionId, hits, itemIndex, '')) as Record<string, unknown>;
}

/**
 * Build a redaction audit report from collected hits.
 * SECURITY: Original PII values are NEVER included in the report.
 */
export function buildReport(sessionId: string, hits: RedactionHit[]): RedactionReport {
  const hitsByCategory: Record<string, number> = {};
  const hitsByPattern: Record<string, number> = {};

  for (const hit of hits) {
    hitsByCategory[hit.category] = (hitsByCategory[hit.category] || 0) + 1;
    hitsByPattern[hit.patternLabel] = (hitsByPattern[hit.patternLabel] || 0) + 1;
  }

  return {
    sessionId,
    timestamp: new Date().toISOString(),
    totalHits: hits.length,
    hitsByCategory,
    hitsByPattern,
    hits,
  };
}
