"""Password strength analysis: entropy estimate, pattern checks, and
membership in a small common-password list. No cracking of other people's
accounts here — this scores a password the user types in themselves.
"""

import math
import re
from dataclasses import dataclass, field
from pathlib import Path

_COMMON_LIST_PATH = Path(__file__).parent.parent / "wordlists" / "common_passwords.txt"


def _load_common_passwords() -> set:
    if not _COMMON_LIST_PATH.exists():
        return set()
    with open(_COMMON_LIST_PATH, encoding="utf-8") as fh:
        return {line.strip().lower() for line in fh if line.strip()}


COMMON_PASSWORDS = _load_common_passwords()

_SEQUENTIAL_RUNS = ["0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "asdfghjkl", "zxcvbnm"]


def _charset_size(password: str) -> int:
    size = 0
    if re.search(r"[a-z]", password):
        size += 26
    if re.search(r"[A-Z]", password):
        size += 26
    if re.search(r"[0-9]", password):
        size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        size += 33  # common printable symbols
    return size or 1


def _has_sequential_run(password: str, run_len: int = 4) -> bool:
    lower = password.lower()
    for alphabet in _SEQUENTIAL_RUNS:
        for i in range(len(alphabet) - run_len + 1):
            run = alphabet[i:i + run_len]
            if run in lower or run[::-1] in lower:
                return True
    return False


def _has_repeated_chars(password: str, run_len: int = 4) -> bool:
    return bool(re.search(r"(.)\1{" + str(run_len - 1) + r",}", password))


@dataclass
class StrengthReport:
    password_length: int
    entropy_bits: float
    charset_size: int
    is_common_password: bool
    has_sequential_run: bool
    has_repeated_chars: bool
    verdict: str
    suggestions: list = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            f"Length: {self.password_length}",
            f"Estimated entropy: {self.entropy_bits:.1f} bits",
            f"Verdict: {self.verdict}",
        ]
        if self.suggestions:
            lines.append("Suggestions:")
            lines += [f"  - {s}" for s in self.suggestions]
        return "\n".join(lines)


def analyze(password: str) -> StrengthReport:
    length = len(password)
    charset = _charset_size(password)
    entropy = length * math.log2(charset) if length else 0.0

    is_common = password.lower() in COMMON_PASSWORDS
    seq = _has_sequential_run(password)
    repeated = _has_repeated_chars(password)

    suggestions = []
    if length < 12:
        suggestions.append("Use at least 12 characters; length matters more than complexity.")
    if charset < 36:
        suggestions.append("Mix uppercase, lowercase, digits and symbols.")
    if is_common:
        suggestions.append("This appears in common/leaked password lists — do not use it anywhere.")
    if seq:
        suggestions.append("Avoid sequential runs like '1234' or 'qwerty'.")
    if repeated:
        suggestions.append("Avoid repeating the same character many times in a row.")
    if not suggestions:
        suggestions.append("Consider a password manager so you never have to remember this at all.")

    if is_common or length < 8:
        verdict = "Very weak"
    elif entropy < 40 or seq or repeated:
        verdict = "Weak"
    elif entropy < 60:
        verdict = "Moderate"
    elif entropy < 80:
        verdict = "Strong"
    else:
        verdict = "Very strong"

    return StrengthReport(
        password_length=length,
        entropy_bits=entropy,
        charset_size=charset,
        is_common_password=is_common,
        has_sequential_run=seq,
        has_repeated_chars=repeated,
        verdict=verdict,
        suggestions=suggestions,
    )


def estimate_crack_time_seconds(entropy_bits: float, guesses_per_second: float = 1e10) -> float:
    """Rough online/offline brute-force estimate: 2^entropy / 2 guesses on average."""
    return (2 ** entropy_bits) / 2 / guesses_per_second


def human_time(seconds: float) -> str:
    units = [("second", 60), ("minute", 60), ("hour", 24), ("day", 365), ("year", 100)]
    value = seconds
    for name, size in units:
        if value < size:
            return f"{value:,.1f} {name}{'s' if value != 1 else ''}"
        value /= size
    return f"{value:,.1f} centuries"
