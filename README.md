# Password Hashing & Strength Audit Toolkit

An educational toolkit covering password hashing fundamentals: why fast hashes
(MD5/SHA-1/SHA-256) are unsafe for password storage, how salted/slow KDFs
(PBKDF2) fix that, how to score a password's real-world strength, and how a
dictionary attack actually works against a weak, unsalted hash.

## ⚠️ Ethical use

This project is for **learning** and for auditing **your own** accounts,
test data, or lab environments — e.g. checking whether a password you chose
for a personal project is weak, or exporting your own test-database hashes
to see which ones are crackable. **Do not** point the `audit` command at
hashes, systems, or accounts you do not own or do not have explicit written
authorization to test. Unauthorized access to computer systems is illegal in
most jurisdictions.

## What's implemented

| Module | Purpose |
|--------|---------|
| `auditor/hashing.py` | Fast unsalted hashes (demo only) + a proper **salted PBKDF2-HMAC-SHA256** password hash (310,000 iterations, OWASP 2023 guidance) with constant-time verification |
| `auditor/strength.py` | Entropy estimate, common-password / sequential / repeated-character checks, brute-force time estimate |
| `auditor/dictionary_audit.py` | Dictionary attack against a single hash (fast or salted), for auditing your own hashes |
| `wordlists/common_passwords.txt` | A small sample list of extremely common passwords, used by the strength checker and the audit demo |

## Project structure

```
password-hash-auditor/
├── auditor/
│   ├── hashing.py
│   ├── strength.py
│   ├── dictionary_audit.py
│   └── cli.py
├── tests/              # 21 unit tests
├── wordlists/
│   └── common_passwords.txt
└── README.md
```

## Setup

Python 3.8+, no third-party dependencies.

```bash
git clone <your-repo-url>
cd password-hash-auditor
python -m auditor --help
```

## Usage

### Score a password's strength

```bash
python -m auditor check "password123"
# Verdict: Very weak, entropy ~46.5 bits, flagged as a common password
# Rough offline brute-force estimate (1e10 guesses/sec): 1.4 hours

python -m auditor check              # prompts securely, nothing echoed/stored
```

### Hash a password properly

```bash
python -m auditor hash "my secret" --algorithm secure
# pbkdf2_sha256$310000$<salt>$<hash>

python -m auditor verify "pbkdf2_sha256$310000$...$..." "my secret"
# MATCH
```

### Demonstrate why fast hashes are unsafe (dictionary audit)

```bash
# Hash a weak password the "wrong" way (fast, unsalted) ...
python -m auditor hash "password123" --algorithm sha256

# ... then show it can be recovered instantly from a wordlist:
python -m auditor audit <that-hash> --algorithm sha256
# CRACKED: 'password123'  (0.00s against wordlists/common_passwords.txt)

# A properly chosen password is not in the list and is not found:
python -m auditor hash "xK9#mQ2vZ7pL4" --algorithm sha256
python -m auditor audit <that-hash> --algorithm sha256
# Not found in wordlist -- this does NOT guarantee strength, only that
# it wasn't in this particular list.
```

`audit --salted` runs the same check against a `pbkdf2_sha256$...` string
from `hash --algorithm secure`, and is dramatically slower per guess — which
is the entire point of a proper KDF.

### As a library

```python
from auditor import hashing, strength

stored = hashing.hash_password("correct horse battery staple")
hashing.verify_password("correct horse battery staple", stored)  # True

report = strength.analyze("Tr0ub4dor&3")
print(report.verdict, report.entropy_bits)
```

## Testing

```bash
python -m unittest discover -s tests -t . -v
```

21 tests cover: fast-hash correctness against `hashlib`, PBKDF2 round-trip
and random salting, malformed-hash rejection, strength scoring for common
weak patterns vs. strong random passwords, and dictionary-audit hits/misses
on both fast and salted hashes.

## What I learned

- **Why password storage needs to be slow:** a fast hash (SHA-256) can be
  tried billions of times a second on commodity GPUs; PBKDF2 with 310k
  iterations deliberately costs real time per guess.
- **Why salting matters:** two users with the same password get completely
  different stored hashes, which defeats precomputed rainbow tables and
  stops an attacker from cracking many accounts with one lookup.
- **Entropy vs. "complexity rules":** a long random passphrase beats a short
  password stuffed with symbols — length dominates the entropy formula.
- **Dictionary attacks:** why leaked/common password lists make simple
  passwords trivially crackable even without brute force, and why MFA and
  unique passwords per site matter in practice.
- **Constant-time comparison:** `hmac.compare_digest` avoids leaking timing
  information when checking a submitted password against the stored hash.

## Limitations

- The bundled wordlist is tiny (a learning demo, not a real crack list).
- PBKDF2 is used here for its stdlib availability; production systems
  should prefer **Argon2id** or **bcrypt** where available.
- No GPU acceleration, rate limiting simulation, or account-lockout model —
  this is a conceptual toolkit, not a production authentication system.

## License

MIT
