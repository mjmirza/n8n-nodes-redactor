# Resolved findings

Every finding from the reviews of 6.1.0 (round 0) and of the 7.0.0 branch (rounds 1 to 9, then the final scoped round 10) and of published 7.0.0 (round 11) is fixed and pinned by a
regression test that fails on the code before its fix. Reviewers should not re-raise a finding listed here unless they
show that its pinned test is wrong.

The test column names the `describe` block. Unless the column names another file, it lives in
`test/codex-review-<NN>.test.ts`, where `<NN>` is the number in the block name (round 0 is `61`, rounds 1 to 11 are
`70` to `80`). The location is where the reviewer found the defect, so line numbers refer to the code at that time.

Maintainer decisions that are out of scope for review are listed in [DESIGN-DECISIONS.md](DESIGN-DECISIONS.md).

| ID | Severity | Location | Finding | Pinned by | Commit |
|---|---|---|---|---|---|
| R0-1 | High | engine.ts:258 | wildcard field rules generate unsafe regexes | re-review 61-1: wildcard field rules | eda984d |
| R0-2 | High | engine.ts:217 | composed pseudonyms corrupt Restore | re-review 61-2: composed pseudonyms restore exactly | eda984d |
| R0-3 | High | engine.ts:1255 | overlapping Presidio entities expose detected text | re-review 61-3: overlapping Presidio entities | eda984d |
| R0-4 | High | patterns.ts:45 | built-in detectors still have unbounded quadratic scans | re-review 61-4: built-in detectors scan in linear time | eda984d |
| R0-5 | High | injection.ts:243 | injection detection contains another unbounded slow regex | re-review 61-5: horizontal rule injection regex | eda984d |
| R0-6 | Medium | engine.ts:998 | overlap retries make built-in URL processing quadratic | re-review 61-6: URL overlap retries | eda984d |
| R0-7 | Medium | engine.ts:215 | pseudonym generation repeatedly scans the entire input | re-review 61-7: pseudonym generation | eda984d |
| R0-8 | Medium | engine.ts:1366 | Presidio key traversal remains quadratic | re-review 61-8: Presidio key traversal | eda984d |
| R0-9 | Medium | engine.ts:1318 | Presidio ignores thresholds below 0.4 | re-review 61-9: Presidio threshold below 0.4 | eda984d |
| R0-10 | Medium | presidio.ts:222 | inherited entity-type names silently disable redaction | re-review 61-10: inherited entity type names | eda984d |
| R0-11 | Medium | engine.ts:837 | array elements lose semantic sibling context | re-review 61-11 and 12: semantic context in arrays and booleans | eda984d |
| R0-12 | Medium | engine.ts:846 | sensitive boolean values bypass semantic redaction | re-review 61-11 and 12: semantic context in arrays and booleans | eda984d |
| R0-13 | Medium | Redactor.node.ts:1269 | binary attachments disappear | re-review 61-13: binary attachments survive | eda984d |
| R0-14 | Medium | Redactor.node.ts:1288 | failed injection-setting expressions silently disable scanning | re-review 61-14: injection setting errors | eda984d |
| R0-15 | Medium | names.ts:1692 | five-word names leave their surname exposed | re-review 61-15 to 17: name detection | eda984d |
| R0-16 | Medium | names.ts:1640 | decomposed Unicode accents bypass name detection | re-review 61-15 to 17: name detection | eda984d |
| R0-17 | Medium | names.ts:1641 | lowercase surname particles hide complete names | re-review 61-15 to 17: name detection | eda984d |
| R0-18 | Medium | patterns.ts:1446 | contextual name detectors retain incomplete name grammar | re-review 61-18: contextual name grammar | eda984d |
| R0-19 | Medium | patterns.ts:211 | a preceding card candidate hides an overlapping valid card | re-review 61-19 to 26: detector formats | eda984d |
| R0-20 | Medium | patterns.ts:25 | Unicode email local parts remain unredacted | re-review 61-19 to 26: detector formats | eda984d |
| R0-21 | Medium | patterns.ts:166 | nonbreaking spaces hide valid grouped IBANs | re-review 61-19 to 26: detector formats | eda984d |
| R0-22 | Medium | patterns.ts:251 | colon labels hide valid IPv6 addresses | re-review 61-19 to 26: detector formats | eda984d |
| R0-23 | Medium | patterns.ts:1053 | connection-string length caps expose password tails | re-review 61-19 to 26: detector formats | eda984d |
| R0-24 | Medium | patterns.ts:1025 | LDAP attribute caps expose the remaining DN | re-review 61-19 to 26: detector formats | eda984d |
| R0-25 | Medium | patterns.ts:1622 | AB blood types are only partly redacted | re-review 61-19 to 26: detector formats | eda984d |
| R0-26 | Low | patterns.ts:247 | the valid unspecified IPv6 address is excluded | re-review 61-19 to 26: detector formats | eda984d |
| R0-27 | Low | profiles.ts:117 | NaN passes profile validation and suppresses Presidio hits | re-review 61-27: NaN threshold | eda984d |
| R1-1 | High | Redactor.node.ts:83 | Binary PII passes through unchanged | re-review 70-1: unscanned attachments | df937ce |
| R1-2 | High | engine.ts:412 | Pseudonymization silently restores another field’s original | re-review 70-2: pseudonyms composed across fields | df937ce |
| R1-3 | Medium | engine.ts:206 | New boolean handling corrupts restored types | re-review 70-3: booleans keep their own type | df937ce |
| R1-4 | Medium | engine.ts:224 | Purge leaves plaintext input retained indefinitely | re-review 70-4: no copy of the input outlives the run | df937ce |
| R1-5 | Medium | Redactor.node.ts:1147 | Presidio configuration errors silently disable protection | re-review 70-5: failed Presidio settings | df937ce |
| R1-6 | Medium | README.md:74 | The README’s production chain discards the model response | test/readme-chain.test.ts: re-review 70-6 and 72-8 | df937ce |
| R1-7 | Low | engine.ts:1850 | Presidio entity names corrupt report counters | re-review 70-7: counters for inherited names | df937ce |
| R2-1 | High | engine.ts:1539 | Pseudonymize silently swaps values | re-review 71-1: Restore pairs properties by original key | deccfad |
| R2-2 | High | patterns.ts:1305 | Modern provider credentials escape Redact and Verify | re-review 71-2: current provider credentials | deccfad |
| R2-3 | High | Redactor.node.ts:1129 | Mixed-tenant batches use the first tenant’s settings | re-review 71-3: one run, one set of settings | deccfad |
| R2-4 | Medium | patterns.ts:592 | German identity-card detection requires the wrong length | re-review 71-4: German ID card serial number | deccfad |
| R2-5 | Medium | README.md:74 | The recommended Verify branch cannot guarantee prevention | re-review 71-5: Verify can gate the LLM | deccfad |
| R2-6 | Medium | multi-stage-verify.json:60 | The verification example imports the weaker detector version | re-review 71-6: examples use node version 2 | deccfad |
| R2-7 | Medium | PRESIDIO_SETUP.md:23 | Presidio setup exposes an unauthenticated service beyond localhost | re-review 71-7: Presidio stays on localhost | deccfad |
| R3-1 | High | patterns.ts:1328 | Authentication credentials survive ordinary casing changes | re-review 72-1 and 2: credentials | 8a67eac |
| R3-2 | High | patterns.ts:1359 | Explicit passwords are missed or only partly removed | re-review 72-1 and 2: credentials | 8a67eac |
| R3-3 | Medium | runtime.ts:33 | The mixed-tenant guard omits the encryption passphrase | re-review 72-3: the legacy passphrase is one per run | 8a67eac |
| R3-4 | Medium | patterns.ts:375 | Escaped LDAP commas expose the person’s name | re-review 72-4: escaped LDAP commas | 8a67eac |
| R3-5 | Medium | names.ts:1726 | Five-word names still leak trailing words | re-review 72-5: five-word names with unknown words | 8a67eac |
| R3-6 | Medium | patterns.ts:999 | Valid Bitcoin address formats bypass every detector | re-review 72-6: Bitcoin address formats | 8a67eac |
| R3-7 | Medium | vault.ts:90 | Session expiry during Redact produces unrecoverable successful output | re-review 72-7: a session that expires during Redact | 8a67eac |
| R3-8 | Medium | README.md:74 | The documented production chain rejects its own diagnostic item | test/readme-chain.test.ts: re-review 70-6 and 72-8 | 8a67eac |
| R4-1 | High | patterns.ts:1365 | Quoted secrets escape redaction and Verify | re-review 73-1: quoted secrets | 02d44be |
| R4-2 | High | patterns.ts:554 | Explicitly identified names remain exposed | re-review 73-2: titled and all-capitals names | 02d44be |
| R4-3 | Medium | patterns.ts:521 | Default Redact misses compact international phones | re-review 73-3: compact international phones | 02d44be |
| R4-4 | Medium | names.ts:1670 | Large name runs crash processing | re-review 73-4: very long name runs | 02d44be |
| R4-5 | Medium | Redactor.node.ts:1030 | Detect silently disables requested reporting | re-review 73-5: Detect reporting settings | 02d44be |
| R5-1 | High | engine.ts:160 | Invalid mode silently exposes PII and contaminates reports | re-review 74-1: an unknown redaction mode is refused | 444cd5f |
| R5-2 | High | patterns.ts:2026 | Basic credentials survive Redact and pass Verify | re-review 74-2: Basic credentials outside a raw header line | 444cd5f |
| R5-3 | Medium | presidio.ts:132 | Concurrent executions can disable another workflow’s NLP detection | re-review 74-3: the Presidio breaker belongs to one execution | 444cd5f |
| R5-4 | Medium | Redactor.node.ts:716 | Node UI still instructs users to expose an unauthenticated service | re-review 74-4 and 74-5: Presidio binds to localhost everywhere it is documented | 444cd5f |
| R5-5 | Low | presidio.test.ts:299 | Docker documentation test cannot detect broken documentation | re-review 74-4 and 74-5: Presidio binds to localhost everywhere it is documented | 444cd5f |
| R6-1 | High | patterns.ts:2086 | Quoted environment secrets leak after whitespace | re-review 75-1: quoted environment secrets | 90dfab3 |
| R6-2 | High | patterns.ts:48 | Valid international email addresses bypass Redact and Verify | re-review 75-2: international email addresses | 90dfab3 |
| R6-3 | High | Redactor.node.ts:1194 | A tenant profile can silently disable all field scanning | re-review 75-3: a profile that changes only the field mode | 90dfab3 |
| R6-4 | Medium | Redactor.node.ts:1433 | Restore silently succeeds with unresolved tokens when TTL expires mid-run | re-review 75-4: Restore uses one session for the whole batch | 90dfab3 |
| R6-5 | Medium | Redactor.node.ts:1183 | Negative TTL creates permanently retained vault data | re-review 75-5: a negative Session TTL is refused | 90dfab3 |
| R7-1 | High | engine.ts:43 | A blank allow-list row disables redaction | re-review 76-1: a blank allow-list row | d1f8612 |
| R7-2 | High | presidio.ts:217 | An NLP outage silently passes the privacy gate | re-review 76-2: a Presidio outage | d1f8612 |
| R7-3 | Medium | engine.ts:1517 | Restore silently overwrites colliding properties | re-review 76-3: Restore never merges two keys | d1f8612 |
| R7-4 | Medium | Redactor.node.ts:1242 | Presidio’s default threshold changes saved workflows | re-review 76-4: Presidio keeps its 0.4 floor at the default threshold | d1f8612 |
| R7-5 | Medium | engine.ts:959 | Numeric and boolean deduplication is disabled | re-review 76-5: deduplication keeps equal numbers and booleans equal | d1f8612 |
| R7-6 | Medium | pseudonymize.ts:64 | Demo email pseudonyms use unrelated domains | re-review 76-6: demo email pseudonyms | d1f8612 |
| R7-7 | Medium | engine.ts:1550 | Final pseudonym repair leaves incorrect audit references | re-review 76-7: report hits after a pseudonym repair | d1f8612 |
| R8-1 | High | patterns.ts:1387 | Slack app credentials escape redaction | re-review 77-1: Slack app and refresh tokens | e6cb71e |
| R8-2 | High | Redactor.node.ts:1366 | Invalid Presidio URLs bypass “Stop the Run.” | re-review 77-2: an invalid Presidio URL | e6cb71e |
| R8-3 | High | presidio.ts:222 | Malformed analyzer responses also bypass the stop policy | re-review 77-3: a malformed Presidio answer | e6cb71e |
| R8-4 | Medium | Redactor.node.ts:1269 | An invalid threshold expression silently disables detection | re-review 77-4: a Confidence Threshold outside 0 to 1 | e6cb71e |
| R8-5 | Medium | engine.ts:1560 | Restore leaks decrypted data through errors | re-review 77-5: a Restore key collision never names the key | e6cb71e |
| R8-6 | Medium | audit.ts:84 | Audit-only output conceals NLP outages | re-review 77-6: the audit record shows a Presidio outage | e6cb71e |
| R8-7 | Low | README.md:124 | README promises the wrong outage behavior | re-review 77-7: the docs describe the outage default | e6cb71e |
| R9-1 | High | engine.ts:1651 | Pseudonym repair can corrupt restoration | re-review 78-1: repair tokens reserve every output | fddd578 |
| R9-2 | High | patterns.ts:475 | Quoted connection-string passwords leak their suffix | re-review 78-2: quoted connection-string passwords | fddd578 |
| R9-3 | Medium | patterns.ts:387 | Valid JWTs can pass through unchanged | re-review 78-3: JWT claims may start with whitespace | fddd578 |
| R9-4 | Medium | presidio.ts:171 | Invalid Presidio offsets bypass the stop-on-failure default | re-review 78-4: unusable Presidio offsets are scan failures | fddd578 |
| R9-5 | Medium | Redactor.node.ts:1204 | Unknown pattern names silently disable selected detection | re-review 78-5: direct pattern selection must be valid | fddd578 |
| R9-6 | Medium | Redactor.node.ts:1406 | An invalid Presidio failure policy permits unscanned output | re-review 78-6: Presidio failure policy must be explicit | fddd578 |
| R9-7 | Medium | runtime.ts:121 | Deny-list errors disclose personal values | re-review 78-7: deny-list diagnostics contain no entry values | fddd578 |
| R9-8 | Medium | audit.ts:98 | Personal Session IDs escape into audit records and errors | re-review 78-8: personal session IDs stay out of diagnostics | fddd578 |
| R9-9 | Medium | COMPARISON.md:79 | Documentation promises nonexistent audit retention | re-review 78-9: audit retention belongs to downstream storage | fddd578 |
| R9-10 | Low | README.md:149 | Documented CI coverage exceeds configured coverage | re-review 78-10: CI covers pushes to every branch | fddd578 |
| R10-1 | High | patterns.ts:487 | Braced ODBC passwords leak suffixes | re-review 79-1: braced ODBC passwords | 6b724f7 |
| R10-2 | High | patterns.ts:536 | Whitespace around = bypasses connection-string parsing | re-review 79-2: whitespace around connection-string equals signs | 6b724f7 |
| R10-3 | Medium | patterns.ts:408 | Hyphen-prefixed JWTs regress | re-review 79-3: hyphen-prefixed JWTs | 6b724f7 |
| R10-4 | Medium | patterns.ts:415 | Empty-signature JWTs remain undetected | re-review 79-4: empty-signature unsecured JWTs | 6b724f7 |
| R10-5 | Medium | audit.ts:13 | Numeric personal Session IDs escape through a new error | re-review 79-5: numeric personal Session IDs | 6b724f7 |
| R10-6 | Medium | engine.ts:1670 | The final restoration check falsely rejects valid output | re-review 79-6: restoration ignores object property enumeration order | 6b724f7 |
| R11-1 | High | patterns.ts:616 | Leading Unicode whitespace disables connection-string detection | re-review 80-1: leading Unicode whitespace in connection-string keywords | 181bea8 |
| R11-2 | High | patterns.ts:567 | ODBC brace handling suppresses valid ADO.NET credentials | re-review 80-2: distinguish ADO.NET literal braces from ODBC delimiters | 181bea8 |
| R11-3 | Medium | Redactor.node.ts:1510 | Purge omits the numeric Session ID normalization | re-review 80-3: normalize numeric Session IDs for Purge | 181bea8 |
| R11-P1 | High | patterns.ts | Property test counterexample: credentials missed in other key orders | re-review 80-4: connection-string credentials in arbitrary segment order | 181bea8 |
| R11-P2 | High | patterns.ts | Property test counterexample: AMQP URLs and apostrophes in URL credentials | re-review 80-5: authenticated connection URLs | 181bea8 |
| R11-P | Class | patterns.ts | Connection-string class: ADO.NET, ODBC and URL forms, Unicode whitespace, literal braces, semicolons and equals signs, any key order and casing | test/connstring-property.test.ts, 10,000 runs, seed 7012026 | 181bea8 |
| R11-G | Medium | engine.ts:1476 | Each Redact run matched every token the session had ever stored, so long-lived sessions slowed every run | re-review 80-session-growth: a long-lived session keeps each run cheap | 181bea8 |
| R12-1 | High | patterns.ts:653 | Prose with a key=value pair, such as User=guest., hid a later connection string | re-review 80-6 (codex-review-80) and the generated prose prefix in test/connstring-property.test.ts | 63d316a |
| R12-2 | Medium | engine.ts:1488 | Prior-token filtering built a suffix array, so long inputs cost far more than in 7.0.0 | re-review 80-7 (codex-review-80) | 63d316a |
