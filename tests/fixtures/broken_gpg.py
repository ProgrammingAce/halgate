"""Fake `gpg` that always fails — for fail-closed tests."""
import sys


def main() -> int:
    sys.stderr.write("fake-broken-gpg: always fails\n")
    return 2


if __name__ == "__main__":
    sys.exit(main())
