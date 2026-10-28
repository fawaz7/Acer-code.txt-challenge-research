#!/usr/bin/env python3
"""Decode a `code.txt` and show what it actually is.

A `code.txt` is base64 around a single RSA-4096-OAEP ciphertext. This script
strips the base64, confirms the 512-byte RSA block, and reports its entropy to
make the point concrete: the file is one opaque sealed ciphertext. Without the
vendor's RSA private key there is nothing further to extract from it (see
docs/02-cryptanalysis.md).

Pure standard library. Usage:
    python3 decode_code_txt.py path/to/code.txt
"""
import base64
import math
import sys


def shannon_entropy_bits_per_byte(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def main(path: str) -> int:
    with open(path, "rb") as f:
        raw = f.read()

    b64 = b"".join(raw.split())  # drop all whitespace/newlines
    try:
        ct = base64.b64decode(b64, validate=True)
    except Exception as e:
        print(f"not valid base64: {e}")
        return 1

    bits = len(ct) * 8
    print(f"file bytes            : {len(raw)}")
    print(f"base64 chars          : {len(b64)}")
    print(f"decoded ciphertext    : {len(ct)} bytes ({bits} bits)")
    print(f"looks like RSA modulus: {'RSA-4096' if bits == 4096 else 'RSA-%d?' % bits}")
    print(f"entropy (bits/byte)   : {shannon_entropy_bits_per_byte(ct):.3f}  (≈8.0 ⇒ indistinguishable from random)")
    print(f"first 32 bytes        : {ct[:32].hex()}")
    print()
    print("This is a single RSA-OAEP ciphertext. The 8-digit unlock code is the")
    print("plaintext inside it, sealed to the vendor's RSA public key. Recovering")
    print("it requires the private key (factoring RSA-4096) or predicting both the")
    print("digits and the ~512-bit OAEP seed — see docs/02-cryptanalysis.md.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
