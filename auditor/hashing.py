"""Hashing utilities: fast (unsalted) hashes for comparison, and a proper
salted/slow KDF for anything resembling real password storage.

Teaching point of this whole project: MD5/SHA-1/SHA-256 are FAST, which is
great for file integrity and terrible for password storage, because an
attacker with a stolen hash can try billions of guesses a second. A proper
password hash (PBKDF2/bcrypt/scrypt/Argon2) is deliberately SLOW and salted.
"""

import hashlib
import hmac
import os

# ---------------------------------------------------------------------------
# Fast, unsalted digests — for demonstration and file-integrity use only.
# Never store real passwords with these.
# ---------------------------------------------------------------------------

FAST_ALGORITHMS = ("md5", "sha1", "sha256", "sha512")


def fast_hash(password: str, algorithm: str = "sha256") -> str:
    if algorithm not in FAST_ALGORITHMS:
        raise ValueError(f"algorithm must be one of {FAST_ALGORITHMS}")
    return hashlib.new(algorithm, password.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Proper password storage: salted PBKDF2-HMAC-SHA256 with a configurable,
# high iteration count. Format mirrors how real systems store a hash:
#   pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
# ---------------------------------------------------------------------------

DEFAULT_ITERATIONS = 310_000  # OWASP 2023 recommendation for PBKDF2-SHA256


def hash_password(password: str, iterations: int = DEFAULT_ITERATIONS, salt: bytes = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iterations, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            raise ValueError
        iterations = int(iterations)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except (ValueError, IndexError):
        raise ValueError("malformed stored hash") from None
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(candidate, expected)
