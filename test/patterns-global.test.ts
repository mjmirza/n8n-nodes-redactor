import { PII_PATTERNS } from '../nodes/Redactor/patterns';

function matchAll(patternName: string, input: string): string[] {
  const pattern = PII_PATTERNS.find((p) => p.name === patternName);
  if (!pattern) throw new Error(`Pattern not found: ${patternName}`);
  const re = new RegExp(pattern.regex.source, pattern.regex.flags);
  const matches: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(input)) !== null) {
    if (pattern.validate && !pattern.validate(m[0])) continue;
    matches.push(m[0]);
  }
  return matches;
}

// ═══════════════════════════════════════════════════════
// GLOBAL NATIONAL IDs
// ═══════════════════════════════════════════════════════

describe('US ITIN', () => {
  test('matches valid ITIN', () => {
    expect(matchAll('itinUS', 'ITIN: 912-70-1234')).toEqual(['912-70-1234']);
  });
});

describe('Canadian SIN', () => {
  test('matches valid SIN with Luhn', () => {
    // 046 454 286 passes Luhn
    expect(matchAll('sinCA', '046 454 286')).toEqual(['046 454 286']);
  });
  test('rejects invalid Luhn', () => {
    expect(matchAll('sinCA', '123 456 789')).toEqual([]);
  });
});

describe('UK NINO', () => {
  test('matches valid NINO', () => {
    expect(matchAll('ninoUK', 'NINO: AB 12 34 56 C')).toEqual(['AB 12 34 56 C']);
  });
  test('matches without spaces', () => {
    expect(matchAll('ninoUK', 'AB123456C')).toEqual(['AB123456C']);
  });
});

describe('German passport', () => {
  test('matches DE passport format', () => {
    expect(matchAll('passportDE', 'Pass: C01X00T47')).toEqual(['C01X00T47']);
  });
});

describe('Belgian RRN', () => {
  test('matches with dots', () => {
    expect(matchAll('rrnBE', '85.07.15.001.33')).toEqual(['85.07.15.001.33']);
  });
  test('matches with dashes', () => {
    expect(matchAll('rrnBE', '85-07-15-001-33')).toEqual(['85-07-15-001-33']);
  });
});

describe('Swedish Personnummer', () => {
  test('matches 10-digit with dash', () => {
    expect(matchAll('personnummerSE', '850715-1234')).toEqual(['850715-1234']);
  });
  test('matches 12-digit with dash', () => {
    expect(matchAll('personnummerSE', '19850715-1234')).toEqual(['19850715-1234']);
  });
});

describe('Norwegian Fødselsnummer', () => {
  test('matches 11-digit format', () => {
    expect(matchAll('fodselsnummerNO', '15077941012')).toEqual(['15077941012']);
  });
});

describe('Danish CPR', () => {
  test('matches with dash', () => {
    expect(matchAll('cprDK', 'CPR: 150779-4123')).toEqual(['150779-4123']);
  });
});

describe('Finnish HETU', () => {
  test('matches valid HETU', () => {
    expect(matchAll('hetuFI', '150785-123A')).toEqual(['150785-123A']);
  });
  test('matches 2000s format', () => {
    expect(matchAll('hetuFI', '010100A123B')).toEqual(['010100A123B']);
  });
});

describe('Portuguese NIF', () => {
  test('matches valid NIF with checksum', () => {
    // 123456789 — let's check: 1*9+2*8+3*7+4*6+5*5+6*4+7*3+8*2 = 9+16+21+24+25+24+21+16 = 156. 156%11=2. 11-2=9. check=9. Last digit is 9. Valid!
    expect(matchAll('nifPT', 'NIF: 123456789')).toEqual(['123456789']);
  });
});

describe('Irish PPS', () => {
  test('matches 8-char PPS', () => {
    expect(matchAll('ppsIE', 'PPS: 1234567T')).toEqual(['1234567T']);
  });
  test('matches 9-char PPS', () => {
    expect(matchAll('ppsIE', '1234567TW')).toEqual(['1234567TW']);
  });
});

describe('Australian TFN', () => {
  test('matches valid TFN with checksum', () => {
    // 123456782: 1*1+2*4+3*3+4*7+5*5+6*8+7*6+8*9+2*10 = 1+8+9+28+25+48+42+72+20 = 253. 253%11=0. Valid!
    expect(matchAll('tfnAU', '123 456 782')).toEqual(['123 456 782']);
  });
});

describe('Australian Medicare', () => {
  test('matches Medicare format', () => {
    expect(matchAll('medicareAU', '2123 45670 1')).toEqual(['2123 45670 1']);
  });
});

describe('NZ IRD', () => {
  test('matches IRD format', () => {
    expect(matchAll('irdNZ', '12-345-678')).toEqual(['12-345-678']);
  });
});

describe('Singapore NRIC', () => {
  test('matches NRIC format', () => {
    expect(matchAll('nricSG', 'NRIC: S1234567D')).toEqual(['S1234567D']);
  });
  test('matches FIN format', () => {
    expect(matchAll('nricSG', 'FIN: F1234567N')).toEqual(['F1234567N']);
  });
});

describe('Indian PAN', () => {
  test('matches valid PAN', () => {
    expect(matchAll('panIN', 'PAN: ABCPD1234E')).toEqual(['ABCPD1234E']);
  });
});

describe('Brazilian CPF', () => {
  test('matches formatted CPF', () => {
    expect(matchAll('cpfBR', 'CPF: 123.456.789-09')).toEqual(['123.456.789-09']);
  });
  test('matches unformatted CPF', () => {
    expect(matchAll('cpfBR', '12345678909')).toEqual(['12345678909']);
  });
});

describe('Spanish NIF (company)', () => {
  test('matches NIF format', () => {
    expect(matchAll('nifES', 'NIF: B12345678')).toEqual(['B12345678']);
  });
});

describe('Italian Carta d\'Identità', () => {
  test('matches CIE format', () => {
    expect(matchAll('cartaIdIT', 'CIE: CA00000AA')).toEqual(['CA00000AA']);
  });
});

describe('Driver license (contextual)', () => {
  test('matches with label', () => {
    const result = matchAll('driverLicenseCtx', 'Driver License: A1234567');
    expect(result.length).toBeGreaterThanOrEqual(1);
  });
  test('matches DL abbreviation', () => {
    const result = matchAll('driverLicenseCtx', 'DL# B98765432');
    expect(result.length).toBeGreaterThanOrEqual(1);
  });
});

// ═══════════════════════════════════════════════════════
// FINANCIAL — Extended
// ═══════════════════════════════════════════════════════

describe('US ABA routing number', () => {
  test('matches valid ABA with checksum', () => {
    // 021000021: 3*(0+0+0)+7*(2+0+2)+1*(1+0+1) = 0+28+2=30. 30%10=0. Valid!
    expect(matchAll('abaRouting', 'Routing: 021000021')).toEqual(['021000021']);
  });
});

describe('UK Sort Code', () => {
  test('matches sort code', () => {
    expect(matchAll('sortCodeUK', 'Sort: 20-00-00')).toEqual(['20-00-00']);
  });
});

describe('American Express', () => {
  test('matches Amex format', () => {
    // 378282246310005 passes Luhn
    expect(matchAll('amex', '3782 822463 10005')).toEqual(['3782 822463 10005']);
  });
});

// ═══════════════════════════════════════════════════════
// ENTERPRISE — Infrastructure & Secrets
// ═══════════════════════════════════════════════════════

describe('Internal hostnames', () => {
  test('matches .internal domain', () => {
    expect(matchAll('internalHostname', 'server-web-01.internal')).toEqual(['server-web-01.internal']);
  });
  test('matches .corp.local domain', () => {
    expect(matchAll('internalHostname', 'db-prod-03.corp.local')).toEqual(['db-prod-03.corp.local']);
  });
  test('matches .lan domain', () => {
    expect(matchAll('internalHostname', 'nas-backup.lan')).toEqual(['nas-backup.lan']);
  });
});

describe('Windows UNC paths', () => {
  test('matches UNC path', () => {
    const result = matchAll('uncPath', '\\\\fileserver\\shared\\docs');
    expect(result.length).toBeGreaterThanOrEqual(1);
  });
});

describe('LDAP Distinguished Names', () => {
  test('matches LDAP DN', () => {
    const result = matchAll('ldapDN', 'CN=John Smith,OU=Users,DC=corp,DC=local');
    expect(result.length).toBeGreaterThanOrEqual(1);
    expect(result[0]).toContain('CN=John Smith');
  });
});

describe('Active Directory usernames', () => {
  test('matches DOMAIN\\user', () => {
    expect(matchAll('adUsername', 'Login: CORP\\jsmith')).toEqual(['CORP\\jsmith']);
  });
});

describe('Private IP addresses', () => {
  test('matches 10.x range', () => {
    expect(matchAll('privateIp', 'Server: 10.0.1.50')).toEqual(['10.0.1.50']);
  });
  test('matches 172.16.x range', () => {
    expect(matchAll('privateIp', 'Gateway: 172.16.0.1')).toEqual(['172.16.0.1']);
  });
  test('matches 192.168.x range', () => {
    expect(matchAll('privateIp', 'LAN: 192.168.1.1')).toEqual(['192.168.1.1']);
  });
});

describe('Database connection strings', () => {
  test('matches PostgreSQL URI', () => {
    const result = matchAll('dbConnectionString', 'postgresql://user:pass@localhost:5432/db');
    expect(result.length).toBeGreaterThanOrEqual(1);
  });
  test('matches MongoDB URI', () => {
    const result = matchAll('dbConnectionString', 'mongodb+srv://admin:secret@cluster.mongodb.net/mydb');
    expect(result.length).toBeGreaterThanOrEqual(1);
  });
  test('matches JDBC URI', () => {
    const result = matchAll('dbConnectionString', 'jdbc:mysql://db-server:3306/mydb');
    expect(result.length).toBeGreaterThanOrEqual(1);
  });
});

describe('ADO.NET connection strings', () => {
  test('matches Server/Password pattern', () => {
    const result = matchAll('connStringKV', 'Server=myserver;Database=mydb;Password=secret123');
    expect(result.length).toBeGreaterThanOrEqual(1);
  });
});

describe('AWS Access Key', () => {
  test('matches AKIA format', () => {
    expect(matchAll('awsAccessKey', 'AKIAIOSFODNN7EXAMPLE')).toEqual(['AKIAIOSFODNN7EXAMPLE']);
  });
});

describe('GCP API Key', () => {
  test('matches AIza format', () => {
    const result = matchAll('gcpApiKey', 'AIzaSyC1234567890abcdefghijklmnopqrstuv');
    expect(result.length).toBeGreaterThanOrEqual(1);
  });
});

describe('Stripe Key', () => {
  test('matches secret key', () => {
    const result = matchAll('stripeKey', 'sk_live_abc123def456ghi789jkl012');
    expect(result.length).toBeGreaterThanOrEqual(1);
  });
  test('matches test key', () => {
    const result = matchAll('stripeKey', 'sk_test_abc123def456ghi789jkl012');
    expect(result.length).toBeGreaterThanOrEqual(1);
  });
});

describe('OpenAI Key', () => {
  test('matches sk- format', () => {
    const result = matchAll('openaiKey', 'sk-abc123def456ghi789jkl012mno345');
    expect(result.length).toBeGreaterThanOrEqual(1);
  });
});

describe('GitHub Token', () => {
  test('matches ghp_ format', () => {
    const result = matchAll('githubToken', 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234');
    expect(result.length).toBeGreaterThanOrEqual(1);
  });
});

describe('Slack Token', () => {
  test('matches xoxb- format', () => {
    const result = matchAll('slackToken', 'xoxb-123456789012-abcdefghijklmnop');
    expect(result.length).toBeGreaterThanOrEqual(1);
  });
});

describe('Bearer Token', () => {
  test('matches Bearer prefix', () => {
    const result = matchAll('bearerToken', 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.xxx.yyy');
    expect(result.length).toBeGreaterThanOrEqual(1);
  });
});

describe('JWT Token', () => {
  test('matches JWT format', () => {
    const result = matchAll('jwtToken', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N');
    expect(result.length).toBeGreaterThanOrEqual(1);
  });
});

describe('PEM Private Key', () => {
  test('matches RSA private key header', () => {
    const result = matchAll('pemPrivateKey', '-----BEGIN RSA PRIVATE KEY-----');
    expect(result.length).toBeGreaterThanOrEqual(1);
  });
  test('matches generic private key header', () => {
    const result = matchAll('pemPrivateKey', '-----BEGIN PRIVATE KEY-----');
    expect(result.length).toBeGreaterThanOrEqual(1);
  });
});

describe('SSH Public Key', () => {
  test('matches ssh-rsa key', () => {
    const result = matchAll('sshPublicKey', 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCxyz123456789');
    expect(result.length).toBeGreaterThanOrEqual(1);
  });
});

describe('Generic secrets', () => {
  test('matches password= pattern', () => {
    const result = matchAll('genericSecret', 'password=MyS3cretP@ss');
    expect(result.length).toBeGreaterThanOrEqual(1);
  });
  test('matches api_key= pattern', () => {
    const result = matchAll('genericSecret', 'api_key="abcdef123456789"');
    expect(result.length).toBeGreaterThanOrEqual(1);
  });
  test('matches access_token: pattern', () => {
    const result = matchAll('genericSecret', 'access_token: sk_live_abcdefghijklmnop');
    expect(result.length).toBeGreaterThanOrEqual(1);
  });
});

describe('Slack Webhook', () => {
  test('matches webhook URL', () => {
    const result = matchAll('slackWebhook', 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXX');
    expect(result.length).toBeGreaterThanOrEqual(1);
  });
});

// ═══════════════════════════════════════════════════════
// MEDICAL — Extended
// ═══════════════════════════════════════════════════════

describe('DEA Number', () => {
  test('matches DEA format', () => {
    expect(matchAll('deaNumber', 'DEA: AB1234563')).toEqual(['AB1234563']);
  });
});

describe('NPI Number', () => {
  test('matches contextual NPI', () => {
    const result = matchAll('npiNumber', 'NPI: 1234567893');
    expect(result.length).toBeGreaterThanOrEqual(1);
  });
});

describe('Prescription number', () => {
  test('matches Rx format', () => {
    const result = matchAll('rxNumber', 'Rx# 123456789');
    expect(result.length).toBeGreaterThanOrEqual(1);
  });
});

// ═══════════════════════════════════════════════════════
// VEHICLE
// ═══════════════════════════════════════════════════════

describe('VIN', () => {
  test('matches valid VIN', () => {
    expect(matchAll('vin', '1HGBH41JXMN109186')).toEqual(['1HGBH41JXMN109186']);
  });
  test('does NOT match with I, O, Q', () => {
    // VIN excludes I, O, Q
    expect(matchAll('vin', '1HGBHI1JXMN109186')).toEqual([]);
  });
});

describe('German license plate', () => {
  test('matches standard format', () => {
    expect(matchAll('licensePlateDE', 'M AB 1234')).toEqual(['M AB 1234']);
  });
});

describe('UK license plate', () => {
  test('matches standard format', () => {
    expect(matchAll('licensePlateUK', 'AB12 CDE')).toEqual(['AB12 CDE']);
  });
});

describe('French license plate', () => {
  test('matches standard format', () => {
    expect(matchAll('licensePlateFR', 'AB-123-CD')).toEqual(['AB-123-CD']);
  });
});

// ═══════════════════════════════════════════════════════
// BIOMETRIC / DIGITAL
// ═══════════════════════════════════════════════════════

describe('UUID', () => {
  test('matches standard UUID', () => {
    expect(matchAll('uuid', '550e8400-e29b-41d4-a716-446655440000')).toEqual([
      '550e8400-e29b-41d4-a716-446655440000',
    ]);
  });
});

describe('IMEI', () => {
  test('matches formatted IMEI', () => {
    expect(matchAll('imei', '49-015420-323751-8')).toEqual(['49-015420-323751-8']);
  });
});

describe('ICCID', () => {
  test('matches SIM card number', () => {
    expect(matchAll('iccid', '8901260222300457687')).toEqual(['8901260222300457687']);
  });
});

// ═══════════════════════════════════════════════════════
// GLOBAL PHONE NUMBERS
// ═══════════════════════════════════════════════════════

describe('Spanish phone', () => {
  test('matches ES mobile', () => {
    expect(matchAll('phoneES', '612.345.678')).toEqual(['612.345.678']);
  });
});

describe('Italian phone', () => {
  test('matches IT phone', () => {
    const result = matchAll('phoneIT', '+39 06 12345678');
    expect(result.length).toBeGreaterThanOrEqual(1);
  });
});

describe('Australian phone', () => {
  test('matches AU mobile', () => {
    expect(matchAll('phoneAU', '04 1234 5678')).toEqual(['04 1234 5678']);
  });
});

describe('Indian phone', () => {
  test('matches IN mobile', () => {
    expect(matchAll('phoneIN', '98765-43210')).toEqual(['98765-43210']);
  });
});

describe('Fax (contextual)', () => {
  test('matches fax with label', () => {
    const result = matchAll('faxCtx', 'Fax: +1-555-123-4567');
    expect(result.length).toBeGreaterThanOrEqual(1);
  });
});

// ═══════════════════════════════════════════════════════
// PATTERN COUNT VERIFICATION
// ═══════════════════════════════════════════════════════

describe('Total pattern count', () => {
  test('has 90+ patterns for enterprise-grade coverage', () => {
    expect(PII_PATTERNS.length).toBeGreaterThanOrEqual(90);
  });
});
