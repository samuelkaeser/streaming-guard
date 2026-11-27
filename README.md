# streaming-guard

Redacts Swiss AHV numbers and email addresses from text that arrives in chunks, the way an LLM streams its answer. Python 3.11+, standard library only.

```python
from streaming_guard import StreamingGuard

guard = StreamingGuard()
guard.push("Kontakt: max.mu")           # "Kontakt: "
guard.push("ster@example.com, AHV 75")  # "[REDACTED_EMAIL], AHV "
guard.push("6.1234.5678.97 ok")         # "[REDACTED_AHV] "
guard.finish()                          # "ok"
```

`StreamingGuard(max_output_chars=n)` adds an output budget. Once the redacted output would go past `n` characters, it's cut there and ends with `[TRUNCATED]`.

## Run it

```sh
mise install     # Python 3.13 and uv
uv run pytest    # or: mise run test
```

Without mise, uv and any Python from 3.11 on will do. The code is one file, `streaming_guard.py`; the tests are in `test_streaming_guard.py`.

## How it works

Every character that can be part of an AHV number or an email address comes from one small alphabet: letters, digits and `_ . % + - @`. Everything else (space, comma, colon, newline, brackets) is a delimiter, and no match can reach across one.

So the guard does very little:

1. `push` looks for the last delimiter in the chunk. Everything up to and including it is final. It gets redacted with one regex and goes out.
2. Whatever comes after the last delimiter is an unfinished token. It's held back until a later chunk closes it.
3. `finish` redacts and releases what's still held.

Redaction only ever sees whole tokens, and where the tokens are doesn't depend on where the chunks were cut. That's why the streamed output is the same for every chunking and equals `redact(whole_text)`, the plain non-streaming function in the same module. The tests use that as their oracle.

What's held back is at most the current token. For normal prose that's one word, and a chunk that ends in a space or a comma is forwarded completely.

## What counts as a match

**AHV number.** `756.` followed by four digits, a dot, four digits, a dot, two digits. ASCII digits only. It's matched anywhere, also in the middle of a longer run (`1756.1234.5678.97` becomes `1[REDACTED_AHV]`). The check digit isn't validated. If in doubt the guard redacts too much; I think that's the right way to be wrong here.

**Email.** `local@label.label`, with at least one dot in the domain. The local part is letters, digits and `_ . % + -`; a label is letters, digits, `_` and `-`. Letters means Unicode letters, so `info@müller.ch` is caught. It's a practical definition, not RFC 5322 (no quoted local parts, no IP literals).

Some consequences:

| Input | Output | Why |
|---|---|---|
| `Mail an a@b.ch.` | `Mail an [REDACTED_EMAIL].` | the sentence dot isn't part of the address |
| `a@b.ch+c@d.ch`, `a@b.ch.c@d.ch` | `[REDACTED_EMAIL]` | addresses glued together without a delimiter are one match |
| `756.1234.5678.97@example.com` | `[REDACTED_EMAIL]` | an AHV number as local part is still an email |
| `a@b@c.ch` | `a@[REDACTED_EMAIL]` | `b@c.ch` is the address |
| `a@b..ch`, `a@b` | unchanged | no valid domain |
| `755.1234.5678.97` | unchanged | wrong prefix |

## Budget

- The budget counts output characters, so after redaction. The total is always `redact(text)[:n] + "[TRUNCATED]"`, whatever the chunking.
- `[TRUNCATED]` itself doesn't count against the budget.
- Placeholders count like any other text and can be cut in half by the budget (`[REDACT[TRUNCATED]`). Nothing sensitive is in them, so I left it simple.
- Output that fits exactly isn't truncated and gets no marker.
- After truncation, and after `finish`, further calls return `""`.
- `max_output_chars=0` produces just `[TRUNCATED]` as soon as there's anything to emit. A negative value raises `ValueError`.

## Complexity

Time is O(n) in the total input length. Memory is O(longest token).

The time bound needs some care in the regex. The obvious email pattern (`[\w.%+-]+@...`) is quadratic on long runs that never turn into an address, like `"a" * n` or `"a@" * n`: the engine fails at position 0, then tries again from position 1, and so on. I measured 1.7 s for 40,000 characters. Two things fix it. A lookbehind only lets a match start at the beginning of a local-part run, and possessive quantifiers (`++`, the reason for Python 3.11) stop a failed attempt from backtracking. Each character is then looked at a constant number of times; the same input takes about half a millisecond.

The lookbehind has a side effect: a second address can't start right after the first one without a delimiter in between. So the pattern has to swallow glued addresses in one go: a local part, one or more `@domain` parts, and all of that repeated. Glued addresses therefore collapse into one placeholder. Earlier versions of the regex leaked here twice (`a@b.ch+c@d.ch`, then `a@b.ch.c@d.ch`, where `.c` was read as part of the first domain), and both times it was a fuzzer or a reviewer that found it, not me staring at the pattern. The tests now build inputs from addresses with marker words, glue them with random characters, and check that no marker survives.

Held text is kept as a list and joined once on release, so a token arriving one character at a time doesn't cost quadratic string copying.

## Limits

- **Hold-back is per token, not per pattern.** For ordinary text that's exactly as little as possible. In odd tokens it's a bit more than strictly needed: `a@@b` is held until the next delimiter although it can't become an address any more, and a finished address followed by `_x` waits too.
- **A stream without delimiters is held completely.** A long hex or base64 blob could still turn into the local part of an address, so nothing goes out until a delimiter or `finish`. There's no cap.
- **Patterns must not contain delimiters.** IBANs or phone numbers written with spaces don't fit the token trick.
- **AHV numbers need the dotted format.** `7561234567897` or `756 1234 5678 97` pass through.
- **Unicode.** `\w` covers composed characters. A decomposed accent (a letter plus a combining mark, as in NFD text) is a delimiter and splits the token, so an address containing one isn't recognised and passes through. Normalise to NFC upstream.
- **It finds formats, not meaning.** Names, postal addresses or an email spelled out as "max at example dot com" are out of reach for a regex.

## What I'd do next

1. Cap the held token at the lengths an address can have (64 + 1 + 255 characters) and release the front of anything longer. Bounds memory and latency on blob-like output.
2. Replace the token rule with a small state machine per pattern that knows whether the held text is still a viable prefix. That gives exact minimal hold-back and it's the way in for patterns with spaces (IBAN, phone numbers). It's roughly twice the code, which is why it isn't here.
3. Validate the AHV check digit (EAN-13) as an option, for callers who'd rather not redact product numbers that happen to start with 756.

## Putting it into an LLM gateway

Where I'd place it: in the gateway between model provider and client, as a filter on the response stream. One guard instance per stream, created when the stream opens. Each SSE delta goes through `push`, the end of the stream calls `finish`. Clients see fewer and slightly larger deltas, nothing else changes.

What it needs around it:

- **A flush timeout.** If the model stalls in the middle of a token, the held text should go out after a second or so. That has to be a deliberate decision per deployment, because flushing an unfinished token can leak a prefix. For most uses, closing the stream with an error is the better choice.
- **Tool calls and logs.** The same guard belongs on tool-call arguments and on whatever the gateway writes to logs and traces. Redacting only what the user sees leaves the more durable copies alone.
- **Input side.** Prompts aren't streamed, so there `redact()` is enough.
- **Metrics without the values.** Count redactions per pattern, tenant and model. Never log what was redacted. A sudden jump in the count is a useful signal (a prompt that makes the model dump a customer list, say).
- **Patterns as configuration.** A registry of patterns per tenant, each with its own placeholder. The shared alphabet would then be derived from the registered patterns.
- **Budget.** `max_output_chars` is a cheap backstop against runaway generations, but the real limit belongs on the provider call (`max_tokens`), since truncating in the gateway still pays for the tokens.

And what it won't do: it only catches identifiers with a fixed format. For names and free-text personal data it has to be paired with an NER or classifier pass, which costs latency and usually can't run per token. A sensible split is regex guards inline on the stream, and the heavier model asynchronously on the finished response for audit and alerting.
