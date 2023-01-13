# L. Lamport, Constructing digital signatures from a one-way function, Technical Report SRI-CSL-98, SRI International
# Computer Science Laboratory, Oct. 1979

import hashlib
import secrets

sk = [[None for _ in range(256)] for _ in range(2)]
pk = [[None for _ in range(256)] for _ in range(2)]
for i in range(0, 256):
    sk[0][i] = secrets.token_bytes(32)
    sk[1][i] = secrets.token_bytes(32)
    pk[0][i] = hashlib.sha256(sk[0][i]).digest()
    pk[1][i] = hashlib.sha256(sk[1][i]).digest()

m = b'The quick brown fox jumps over the lazy dog'
h = int.from_bytes(hashlib.sha256(m).digest(), 'little')
sig = [None for _ in range(256)]
for i in range(0, 256):
    b = h >> i & 1
    sig[i] = sk[b][i]

h = int.from_bytes(hashlib.sha256(m).digest(), 'little')
for i in range(0, 256):
    b = h >> i & 1
    assert hashlib.sha256(sig[i]).digest() == pk[b][i]
