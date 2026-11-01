# Design decisions

Deliberate limits, with the reasoning and evidence behind each. A reviewer should read this before reporting one of them again, and report it only when the reasoning is shown to be wrong.

## User regexes run on the JavaScript engine, bounded by an input limit

Custom patterns and deny list regexes run on the ECMAScript `RegExp` engine.

**Why it can be slow.** That engine backtracks and has no timeout. A pattern that begins with a repetition, such as `a+$` or `\w+@\w+`, retries at every start position. Its search time on one value therefore grows with the square of the length.

**Why the node cannot swap engines.** A linear-time engine such as RE2 is a native dependency. The n8n verification guidelines, under "No external dependencies", say "Ensure that your package does not include any external dependencies to keep it lightweight and easy to maintain" (https://docs.n8n.io/integrations/creating-nodes/build/reference/verification-guidelines/). The node also cannot use worker threads or timers, because the verification scanner rejects `setTimeout` and Node built-in modules in `nodes/`.

**How the cost is bounded instead.** Three layers keep it in check.

1. The safety check in `regexSafety.ts` refuses every shape that can backtrack exponentially or polynomially inside one attempt. That covers nested repetition, adjacent overlapping repetitions, repetitions inside lookarounds, and syntax it cannot model.
2. A user regex never scans a value longer than 20,000 characters. A custom or deny list regex stops the run with an error instead. An allow list regex is skipped, so the value stays redacted.
3. What remains is the search-retry cost on at most 20,000 characters. In `test/codex-review-52.test.ts`, `a+$` on a 20,000-character value finishes in about 200 ms.

Built-in patterns are held to a stricter bar. Where a built-in regex would retry the same way, it uses a linear scanner instead, as email does through `scanEmails` in `patterns.ts`.

## Presidio scans free-text keys, not identifier keys

Presidio runs on every string value and on every key that is free text, such as `"Xochitl Quispe"`.

A key that is a single identifier is not sent. That covers keys such as `note`, `customer_id` and `first-name`, matched by `/^[\p{L}_$][\p{L}\p{N}_$-]*$/u`. Such a key is a schema name, not personal data, and NLP entity recognition on a lone token is unreliable. Sending every schema name would also multiply Analyzer requests for no gain.

Regex detection still scans every key, identifier or not.
