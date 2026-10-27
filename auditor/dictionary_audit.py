"""Dictionary-based hash audit: check whether a *hash you already have* (e.g.
exported from your own test database) matches any password in a wordlist.

This is the defensive side of what tools like John the Ripper / Hashcat do,
reimplemented simply for learning. Intended use: auditing accounts you own
or are authorized to test (a personal project, a lab environment, or your
own exported password database) to find weak/reused passwords, NOT for
attacking accounts that are not yours. See README.md "Ethical use" section.
"""

from pathlib import Path

from .hashing import FAST_ALGORITHMS, fast_hash
from .hashing import verify_password as verify_pbkdf2


def audit_fast_hash(target_hash: str, algorithm: str, wordlist_path: str):
    """Try every word in a wordlist against a single fast (unsalted) hash.

    Returns the matching password, or None if the wordlist was exhausted.
    """
    if algorithm not in FAST_ALGORITHMS:
        raise ValueError(f"algorithm must be one of {FAST_ALGORITHMS}")
    target_hash = target_hash.strip().lower()
    with open(wordlist_path, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            candidate = line.strip()
            if not candidate:
                continue
            if fast_hash(candidate, algorithm) == target_hash:
                return candidate
    return None


def audit_salted_hash(stored_hash: str, wordlist_path: str):
    """Try every word in a wordlist against a salted pbkdf2_sha256 hash
    (as produced by hashing.hash_password). Slower by design.
    """
    with open(wordlist_path, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            candidate = line.strip()
            if not candidate:
                continue
            if verify_pbkdf2(candidate, stored_hash):
                return candidate
    return None


def audit_file(hash_list_path: str, algorithm: str, wordlist_path: str, salted: bool = False):
    """Audit many hashes (one per line) at once; returns {hash: cracked_password_or_None}."""
    results = {}
    hashes = [line.strip() for line in Path(hash_list_path).read_text(encoding="utf-8").splitlines() if line.strip()]
    for h in hashes:
        if salted:
            results[h] = audit_salted_hash(h, wordlist_path)
        else:
            results[h] = audit_fast_hash(h, algorithm, wordlist_path)
    return results
