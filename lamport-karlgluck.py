# Hash Ladders for Shorter Lamport Signatures
# https://gist.github.com/karlgluck/8412807

import hashlib
import secrets


class HashList:

    @staticmethod
    def hash(data, n):
        for _ in range(n):
            data = hashlib.sha256(data).digest()
        return data

    @staticmethod
    def goto(data, goal):
        for i in range(256):
            data = hashlib.sha256(data).digest()
            if data == goal:
                return i + 1
        return


sk = [[None for _ in range(32)] for _ in range(2)]
pk = [[None for _ in range(32)] for _ in range(2)]
for i in range(32):
    sk[0][i] = secrets.token_bytes(32)
    sk[1][i] = secrets.token_bytes(32)
    pk[0][i] = HashList.hash(sk[0][i], 258)
    pk[1][i] = HashList.hash(sk[1][i], 258)

assert HashList.hash(HashList.hash(sk[0][0], 129), 129) == pk[0][0]
assert HashList.goto(HashList.hash(sk[0][0], 129), pk[0][0]) == 129

raw = b'The quick brown fox jumps over the lazy dog'
msg = hashlib.sha256(raw).digest()
sig = [[None for _ in range(32)] for _ in range(2)]
for i in range(32):
    n = msg[i]
    sig[0][i] = HashList.hash(sk[0][i], n + 1)
    sig[1][i] = HashList.hash(sk[1][i], 256 - n)

for i in range(32):
    n = msg[i]
    ia = HashList.goto(sig[0][i], pk[0][i])
    assert ia != 257
    ib = HashList.goto(sig[1][i], pk[1][i])
    assert ib != 257
    assert 258 - ia == ib - 1
    assert 257 - ia == n
