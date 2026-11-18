import re

# Characters that can occur in the local part of an address. Those plus "@" can
# be part of a match, every other character ends one.
# The hyphen goes last so it is never read as a range.
_LOCAL_CHARS = r"\w.%+"
_LOCAL = f"[{_LOCAL_CHARS}-]"
_TOKEN_CHARS = _LOCAL_CHARS + "@-"

# One local part followed by one or more @domain parts, repeated, so addresses
# glued together (a@b.ch+c@d.ch, a@b.ch.c@d.ch) end up as a single match.
# Possessive quantifiers plus the lookbehind keep matching linear.
_PATTERN = re.compile(
    rf"(?P<email>(?<!{_LOCAL})(?:{_LOCAL}++(?:@[\w-]++(?:\.[\w-]++)++)++)++)"
    r"|(?P<ahv>756\.[0-9]{4}\.[0-9]{4}\.[0-9]{2})"
)
# Group 1: everything up to and including the last delimiter. Group 2: the tail.
_SPLIT = re.compile(rf"(?s)(.*[^{_TOKEN_CHARS}])(.*)")

_TRUNCATED = "[TRUNCATED]"


def _placeholder(m: re.Match) -> str:
    return "[REDACTED_EMAIL]" if m.lastgroup == "email" else "[REDACTED_AHV]"


def redact(text: str) -> str:
    return _PATTERN.sub(_placeholder, text)


class StreamingGuard:
    def __init__(self, max_output_chars: int | None = None):
        if max_output_chars is not None and max_output_chars < 0:
            raise ValueError("max_output_chars must be >= 0")
        self._max = max_output_chars
        self._sent = 0
        self._held: list[str] = []
        self._done = False

    def push(self, chunk: str) -> str:
        if self._done:
            return ""
        m = _SPLIT.fullmatch(chunk)
        if m is None:
            self._held.append(chunk)
            return ""
        final, tail = m.groups()
        self._held.append(final)
        text = "".join(self._held)
        self._held = [tail] if tail else []
        return self._emit(redact(text))

    def finish(self) -> str:
        if self._done:
            return ""
        text = "".join(self._held)
        self._done = True
        self._held = []
        return self._emit(redact(text))

    def _emit(self, text: str) -> str:
        if self._max is not None:
            room = self._max - self._sent
            if len(text) > room:
                self._done = True
                self._held = []
                return text[:room] + _TRUNCATED
            self._sent += len(text)
        return text
