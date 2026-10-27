"""Command-line interface:  python -m auditor <command> ..."""

import argparse
import getpass
import sys
import time
from pathlib import Path

from . import dictionary_audit, hashing, strength

_DEFAULT_WORDLIST = Path(__file__).parent.parent / "wordlists" / "common_passwords.txt"


def cmd_check(args):
    password = args.password or getpass.getpass("Password to analyze (not stored or shown again): ")
    report = strength.analyze(password)
    print(report.summary())
    seconds = strength.estimate_crack_time_seconds(report.entropy_bits)
    print(f"Rough offline brute-force estimate (1e10 guesses/sec): {strength.human_time(seconds)}")


def cmd_hash(args):
    if args.algorithm == "secure":
        print(hashing.hash_password(args.password or getpass.getpass("Password: ")))
    else:
        pw = args.password or getpass.getpass("Password: ")
        print(hashing.fast_hash(pw, args.algorithm))


def cmd_verify(args):
    pw = args.password or getpass.getpass("Password: ")
    ok = hashing.verify_password(pw, args.stored)
    print("MATCH" if ok else "NO MATCH")
    sys.exit(0 if ok else 1)


def cmd_audit(args):
    wordlist = args.wordlist or str(_DEFAULT_WORDLIST)
    start = time.time()
    if args.salted:
        result = dictionary_audit.audit_salted_hash(args.hash, wordlist)
    else:
        result = dictionary_audit.audit_fast_hash(args.hash, args.algorithm, wordlist)
    elapsed = time.time() - start
    if result is not None:
        print(f"CRACKED: '{result}'  ({elapsed:.2f}s against {wordlist})")
    else:
        print(f"Not found in wordlist ({elapsed:.2f}s against {wordlist}) -- "
              f"this does NOT guarantee the password is strong, only that it "
              f"wasn't in this list.")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="auditor",
        description=(
            "Educational password hashing & strength-audit toolkit. "
            "Use only on accounts/hashes you own or are authorized to test."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("check", help="score a password's strength and estimate crack time")
    p.add_argument("password", nargs="?", help="omit to be prompted securely")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("hash", help="hash a password")
    p.add_argument("password", nargs="?", help="omit to be prompted securely")
    p.add_argument(
        "--algorithm", choices=list(hashing.FAST_ALGORITHMS) + ["secure"], default="secure",
        help="'secure' = salted PBKDF2-SHA256 (recommended); others are fast/unsalted, for demos only",
    )
    p.set_defaults(func=cmd_hash)

    p = sub.add_parser("verify", help="check a password against a stored secure (pbkdf2) hash")
    p.add_argument("stored", help="the pbkdf2_sha256$...$...$... string")
    p.add_argument("password", nargs="?", help="omit to be prompted securely")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser(
        "audit",
        help="dictionary-check ONE hash you already have against a wordlist (your own test data only)",
    )
    p.add_argument("hash", help="the hash to check, or a pbkdf2_sha256$... string with --salted")
    p.add_argument("--algorithm", choices=hashing.FAST_ALGORITHMS, default="sha256")
    p.add_argument("--salted", action="store_true", help="treat `hash` as a pbkdf2_sha256 stored string")
    p.add_argument("--wordlist", help=f"default: {_DEFAULT_WORDLIST}")
    p.set_defaults(func=cmd_audit)

    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
