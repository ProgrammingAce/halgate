#!/usr/bin/env python3
"""Fake `gpg` for tests: symmetric base64 "encryption" bound to FAKE_GPG_KEY.

Supports the subset used by the harness:
  --list-keys --with-colons <fpr>
  --encrypt --recipient <fpr>   (reads stdin, writes armor)
  --decrypt                     (reads armor from stdin)
Fails (rc=2) when the key does not match FAKE_GPG_KEY, modelling a missing
recipient key in the keyring.
"""
import base64
import os
import sys


def main() -> int:
    args = sys.argv[1:]
    key = os.environ.get("FAKE_GPG_KEY", "")
    armor_hdr = "-----BEGIN PGP MESSAGE-----"
    if "--list-keys" in args:
        if len(args) >= 2 and args[-1] and args[-1] not in ("--with-colons",
                                                            "--fixed-list-mode") \
                and len(args[-1]) == 40:
            fpr = args[-1]
        else:
            fpr = ""
        if fpr and fpr.upper() == key.upper():
            sys.stdout.write(
                "pub:u:1:4096:1:1:0:0:0:::0:e+aBC:\n"
                f"fpr:::::::::{key.upper()}:\n"
                "uid:::::::::Test User <test@example.com>:\n")
            return 0
        sys.stderr.write("no public key: %s\n" % fpr)
        return 2
    if "--encrypt" in args:
        if "--recipient" in args:
            fpr = args[args.index("--recipient") + 1]
            if fpr.upper() != key.upper():
                sys.stderr.write("no public key: %s\n" % fpr)
                return 2
        data = sys.stdin.buffer.read()
        body = base64.b64encode(data).decode()
        sys.stdout.write(armor_hdr + "\n" + "\n".join(
            body[i:i + 64] for i in range(0, len(body), 64)) + "\n"
            "-----END PGP MESSAGE-----\n")
        return 0
    if "--decrypt" in args:
        text = sys.stdin.buffer.read().decode()
        if armor_hdr not in text:
            return 2
        body = text.split(armor_hdr, 1)[1].split("-----END PGP MESSAGE-----", 1)[0]
        body = "".join(line.strip() for line in body.strip().splitlines())
        sys.stdout.buffer.write(base64.b64decode(body))
        return 0
    sys.stderr.write("fake-gpg: unsupported args\n")
    return 2


if __name__ == "__main__":
    sys.exit(main())
