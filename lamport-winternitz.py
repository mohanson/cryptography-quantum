# On the Security of the Winternitz One-Time Signature Scheme
# https://eprint.iacr.org/2011/191.pdf

import hashlib
import secrets


def iterhash(data, n):
    for _ in range(n):
        data = hashlib.sha256(data).digest()
    return data


sk = [None for _ in range(32)]
pk = [None for _ in range(32)]
for i in range(32):
    sk[i] = secrets.token_bytes(32)
    pk[i] = iterhash(sk[i], 256)

raw = b'The quick brown fox jumps over the lazy dog'
msg = hashlib.sha256(raw).digest()
sig = [None for _ in range(32)]
for i in range(32):
    n = msg[i]
    sig[i] = iterhash(sk[i], n)

for i in range(32):
    n = msg[i]
    assert iterhash(sig[i], 256 - n) == pk[i]
