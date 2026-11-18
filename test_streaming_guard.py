import random
import re
import time

import pytest

from streaming_guard import StreamingGuard, redact

AHV = "756.1234.5678.97"

CORPUS = [
    "Kontakt: max.muster@example.com, AHV 756.1234.5678.97 ok",
    "a@b.ch+c@d.ch and more",
    "a@b..ch a@b@c.ch a@b.ch.",
    "1756.1234.5678.97 756.1234.5678.97@x.ch",
    "info@müller.ch, 755.1234.5678.97 756.1234.5678.9",
    "x.y+tag@sub.domain.example.org\nnext line 756.9999.0000.11\n",
    "no sensitive data here at all",
    "@@@ ... +++ --- %%% 756. 756.1234 756.1234.5678",
    "line one a@b.ch\r\nline two 756.1234.5678.97\r\n",
    "tab\tseparated\ta@b.ch\t756.1234.5678.97\t",
    "caf\u00e9 e\u0301@exampl\u0065\u0301.ch and x\u0301y@z.ch",
    "\u0667\u0665\u0666.\u0661\u0662\u0663\u0664.\u0665\u0666\u0667\u0668.\u0669\u0667",
    "a@b.ch.c@d.ch a@b.ch-c@d.ch a@b.ch@c.ch a@b.ch+x@y@c.ch",
    "",
]


LINEAR_TEXTS = [
    "a" * 200_000,
    "a@" * 100_000,
    "a@b." * 50_000,
    "756." * 50_000,
    ("7" * 20 + " ") * 10_000,
    "a@b.c" * 40_000,
    "a@b@" * 50_000,
]


def run(chunks, **kw):
    g = StreamingGuard(**kw)
    out = [g.push(c) for c in chunks]
    out.append(g.finish())
    return "".join(out)


def two_way(text):
    return [[text[:i], text[i:]] for i in range(len(text) + 1)]


def random_chunks(text, rng):
    chunks, i = [], 0
    while i < len(text):
        n = rng.randint(0, 6)
        chunks.append(text[i:i + n])
        i += n
    return chunks


def test_reference_example():
    g = StreamingGuard()
    assert g.push("Kontakt: max.mu") == "Kontakt: "
    assert g.push("ster@example.com, AHV 75") == "[REDACTED_EMAIL], AHV "
    assert g.push("6.1234.5678.97 ok") == "[REDACTED_AHV] "
    assert g.finish() == "ok"


@pytest.mark.parametrize("text", CORPUS)
def test_chunk_independence(text):
    expected = redact(text)
    for chunks in two_way(text):
        assert run(chunks) == expected
    assert run(list(text)) == expected
    for seed in range(20):
        assert run(random_chunks(text, random.Random(seed))) == expected


@pytest.mark.parametrize(
    "text, expected",
    [
        ("a@b.ch+c@d.ch", "[REDACTED_EMAIL]"),
        ("a@b.ch.c@d.ch", "[REDACTED_EMAIL]"),
        ("a@b.ch-c@d.ch", "[REDACTED_EMAIL]"),
        ("a@b.ch_c@d.ch", "[REDACTED_EMAIL]"),
        ("a@b.ch@c.ch", "[REDACTED_EMAIL]"),
        ("a@b.ch%c@d.ch", "[REDACTED_EMAIL]"),
        ("a@b.ch..c@d.ch", "[REDACTED_EMAIL]"),
        ("a@b.ch+x@y@c.ch", "[REDACTED_EMAIL]+x@[REDACTED_EMAIL]"),
        ("a@b.ch@", "[REDACTED_EMAIL]@"),
        ("a@b..ch", "a@b..ch"),
        ("a@b", "a@b"),
        ("a@b@c.ch", "a@[REDACTED_EMAIL]"),
        ("a@b.ch.", "[REDACTED_EMAIL]."),
        ("mail max+news@example.com now", "mail [REDACTED_EMAIL] now"),
        ("info@müller.ch", "[REDACTED_EMAIL]"),
        ("756.1234.5678.97@x.ch", "[REDACTED_EMAIL]"),
        (AHV, "[REDACTED_AHV]"),
        ("755.1234.5678.97", "755.1234.5678.97"),
        ("756.1234.5678.9", "756.1234.5678.9"),
        ("1756.1234.5678.97", "1[REDACTED_AHV]"),
        ("\u0667\u0665\u0666.\u0661\u0662\u0663\u0664.\u0665\u0666\u0667\u0668.\u0669\u0667",) * 2,
        ("", ""),
    ],
)
def test_redaction_cases(text, expected):
    assert redact(text) == expected
    assert run([text]) == expected
    assert run(list(text)) == expected


def test_empty_chunks():
    g = StreamingGuard()
    assert g.push("") == ""
    assert g.push("a@b.") == ""
    assert g.push("") == ""
    assert g.push("ch ") == "[REDACTED_EMAIL] "
    assert g.finish() == ""


def test_negative_budget_raises():
    with pytest.raises(ValueError):
        StreamingGuard(max_output_chars=-1)


def test_fuzz_nothing_leaks():
    ahv = re.compile(r"756\.\d{4}\.\d{4}\.\d{2}")
    mail = re.compile(r"[\w.%+-]+@[\w-]+(\.[\w-]+)+")
    pieces = list("a756 5 6.@+- ,") + [AHV, "x@y.ch", "a.b+c@d-e.org"]
    rng = random.Random(1234)
    for _ in range(1500):
        text = "".join(rng.choice(pieces) for _ in range(rng.randint(0, 25)))
        out = run(random_chunks(text, rng))
        assert out == redact(text)
        assert not ahv.search(out), (text, out)
        assert not mail.search(out), (text, out)


def test_delimiter_forwarded_immediately():
    g = StreamingGuard()
    assert g.push("hello world, a@b.ch ") == "hello world, [REDACTED_EMAIL] "
    assert g.finish() == ""


def last_delimiter_end(text):
    for i in range(len(text) - 1, -1, -1):
        if not re.fullmatch(r"[\w.%+\-@]", text[i]):
            return i + 1
    return 0


@pytest.mark.parametrize("text", CORPUS)
def test_only_unfinished_token_is_held(text):
    for seed in [None] + list(range(10)):
        chunks = list(text) if seed is None else random_chunks(text, random.Random(seed))
        g = StreamingGuard()
        out, fed = "", ""
        for c in chunks:
            out += g.push(c)
            fed += c
            assert out == redact(fed[: last_delimiter_end(fed)])
        assert out + g.finish() == redact(text)


def test_budget_exact_cut():
    text = "Mail a@b.ch and AHV 756.1234.5678.97 please"
    for n in range(len(redact(text)) + 3):
        expected = redact(text)
        expected = expected[:n] + "[TRUNCATED]" if len(expected) > n else expected
        assert run([text], max_output_chars=n) == expected
        for chunks in two_way(text):
            assert run(chunks, max_output_chars=n) == expected
        assert run(list(text), max_output_chars=n) == expected


def test_budget_cut_inside_placeholder():
    assert run(["x a@b.ch y"], max_output_chars=5) == "x [RE[TRUNCATED]"


def test_budget_exact_fit_has_no_marker():
    text = "abc a@b.ch"
    n = len(redact(text))
    assert run([text], max_output_chars=n) == redact(text)
    assert run(list(text), max_output_chars=n) == redact(text)


def test_input_after_truncation_ignored():
    g = StreamingGuard(max_output_chars=3)
    assert g.push("abcdef ") == "abc[TRUNCATED]"
    assert g.push("more text ") == ""
    assert g.finish() == ""


def test_finish_after_truncation_returns_empty():
    g = StreamingGuard(max_output_chars=2)
    assert g.push("abc") == ""
    assert g.finish() == "ab[TRUNCATED]"
    assert g.finish() == ""


def test_push_after_finish_ignored():
    g = StreamingGuard()
    assert g.finish() == ""
    assert g.push("late ") == ""
    assert g.finish() == ""


def test_budget_zero():
    assert run(["", "abc "], max_output_chars=0) == "[TRUNCATED]"
    assert run([""], max_output_chars=0) == ""


def test_markers_never_leak():
    items = [
        "geheim1@privat1.ch",
        "geheim2@privat2.ch",
        "geheim3.x+y@sub.privat3.org",
        "756.3141.5926.53",
        "756.2718.2818.28",
    ]
    markers = ["geheim1", "privat1", "geheim2", "privat2", "geheim3", "privat3",
               "3141", "5926", "2718", "2818"]
    joiner_chars = list(".-_+%@ ,ab19")
    rng = random.Random(99)
    for _ in range(1500):
        parts = []
        for item in rng.sample(items, rng.randint(1, len(items))):
            parts.append(item)
            parts.append("".join(rng.choice(joiner_chars) for _ in range(rng.randint(0, 3))))
        text = "".join(parts)
        out = run(random_chunks(text, rng))
        for m in markers:
            if m in text:
                assert m not in out, (text, out)


def test_budget_fuzz():
    rng = random.Random(7)
    for _ in range(400):
        text = rng.choice(CORPUS)
        full = redact(text)
        n = rng.choice([0, 1, 2, 5, len(full) // 2, len(full), len(full) + 1])
        expected = full[:n] + "[TRUNCATED]" if len(full) > n else full
        assert run(random_chunks(text, rng), max_output_chars=n) == expected


@pytest.mark.parametrize("text", LINEAR_TEXTS)
def test_linear_whole_text(text):
    start = time.perf_counter()
    redact(text)
    run([text])
    assert time.perf_counter() - start < 2


@pytest.mark.parametrize("text", LINEAR_TEXTS)
def test_linear_char_by_char(text):
    start = time.perf_counter()
    run(text)
    assert time.perf_counter() - start < 2
