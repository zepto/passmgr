from Crypto.Hash import HMAC
from Crypto.Hash import SHA512
from Crypto.Hash import SHA256
from Crypto.Hash import SHA
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2
import sha
import hashlib
s = b'hello world.....'
k = Random.new().read(32)
# k = sha.SHA512(b'hello this is...').digest()
# print(SHA.block_size, SHA.digest_size)
# print(SHA.new(s).digest())
# print(SHA256.digest_size)
# print(sha.SHA1(s).digest())
# print(HMAC.new(k,s, digestmod=SHA512).digest())
# print(sha.HMAC(k,s, hashmod=sha.SHA512).digest())

prf = lambda p, s: HMAC.new(p, s, SHA512).digest()
print(PBKDF2(s, k, dkLen=32, count=1000, prf=prf))
prf = lambda p, s: sha.HMAC(p, s, sha.SHA512).digest()
print(sha.pbkdf2(s, k, 1000, 32, prf=prf))
