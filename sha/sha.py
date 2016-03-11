from binascii import hexlify as ba_hexlify
from binascii import unhexlify as ba_unhexlify
import struct
import math

ROTR = lambda x, n: (x >> n) | (x << (32 - n))
SHR = lambda x, n: x >> n
ROTL = lambda x, n: (x << n) | (x >> (32 - n))
ROTR_512 = lambda x, n: (x >> n) | (x << (64 - n))
SHR_512 = lambda x, n: x >> n
ROTL_512 = lambda x, n: (x << n) | (x >> (64 - n))

Ch = lambda x, y, z: (x & y) ^ (~x & z)
Parity = lambda x, y, z: x ^ y ^ z
Maj = lambda x, y, z: (x & y) ^ (x & z) ^ (y & z)

def sha1_f(t, x, y, z):
    """ Call the correct f function for SHA-1.

    """

    if t >= 0 and t <= 19:
        return Ch(x, y, z)
    elif t >= 20 and t <= 39:
        return Parity(x, y, z)
    elif t >= 40 and t <= 59:
        return Maj(x, y, z)
    elif t >= 60 and t <= 79:
        return Parity(x, y, z)
    else:
        raise ValueError("Invalid value for t must be 0 <= t <= 79")

Sigma0 = lambda x: ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22)
Sigma1 = lambda x: ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25)
sigma0 = lambda x: ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3)
sigma1 = lambda x: ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10)
Sigma0_512 = lambda x: ROTR_512(x, 28) ^ ROTR_512(x, 34) ^ ROTR_512(x, 39)
Sigma1_512 = lambda x: ROTR_512(x, 14) ^ ROTR_512(x, 18) ^ ROTR_512(x, 41)
sigma0_512 = lambda x: ROTR_512(x, 1) ^ ROTR_512(x, 8) ^ SHR_512(x, 7)
sigma1_512 = lambda x: ROTR_512(x, 19) ^ ROTR_512(x, 61) ^ SHR_512(x, 6)

# K constants for sha-1.
K_sha1 = [0x5a827999] * 20
K_sha1.extend([0x6ed9eba1] * 20)
K_sha1.extend([0x8f1bbcdc] * 20)
K_sha1.extend([0xca62c1d6] * 20)

K_sha256 = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

K_sha512 = [0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
            0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
            0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
            0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
            0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
            0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
            0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
            0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
            0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
            0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
            0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
            0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
            0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
            0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
            0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
            0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
            0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
            0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
            0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
            0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
            0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
            0x5fcb6fab3ad6faec, 0x6c44198c4a475817]

# H inital hash values.
H_sha1 = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]
H_sha224 = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31,
            0x68581511, 0x64f98fa7, 0xbefa4fa4]
H_sha256 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f,
            0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
H_sha512 = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b,
            0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b, 0x5be0cd19137e2179]
H_sha384 = [0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17,
            0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511,
            0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4]


def pad(M: bytes, size: int) -> bytes:
    """ Return the sha-1 and sha-256 padded representation of message M.

    """

    len_size = size // 8

    # Zeros to append to message.
    zeros = b'\x00' * ((size - len_size) - (len(M) + 1) % size)

    # Length padding
    len_pad = ba_unhexlify(hex(len(M) * 8)[2:].encode().rjust(len_size * 2, b'0'))

    # Pad M.
    padded_M = M + b'\x80' + zeros + len_pad[-len_size:]

    return padded_M

def parse_padded(M: bytes, size: int) -> list:
    """ Return a list of 512 bit messages from M.

    """

    return [M[i:i + size] for i in range(0, len(M), size)]

class HashBase(object):
    """ Base Hash object.

    """

    def __init__(self, data: bytes):
        """ Provides the basic hash functions.

        """

        self._digest = self._hash(data)

    def update(self, data: bytes):
        """ Hashes data.

        """

        self._digest = self._hash(data)

    def digest(self) -> bytes:
        """ Return the digest.

        """

        return self._digest

    def hexdigest(self) -> bytes:
        """ Return the hexlified digest.

        """

        return ba_hexlify(self._digest)

class SHA1(HashBase):
    """ SHA1 hash object.

    """

    def __init__(self, data: bytes = b''):
        """ Hash data using SHA-1

        """

        super(SHA1, self).__init__(data)

        self.block_size = 64
        self.digest_size = 20

    def _hash(self, message: bytes) -> bytes:
        """ Hash message using SHA-1.

        """

        M = parse_padded(pad(message, 64), 64)
        H = [H_sha1]
        for i, m in enumerate(M):
            # Wt = [int(ba_hexlify(m[j:j+4]), 16) for j in range(0, len(m), 4)]
            W = list(struct.unpack('>%dI' % 16, m))

            for t in range(16, 80):
                W.append(ROTL(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1) % (2 ** 32))

            a = H[i][0]
            b = H[i][1]
            c = H[i][2]
            d = H[i][3]
            e = H[i][4]

            for t in range(0, 80):
                T = (ROTL(a, 5) + sha1_f(t, b, c, d) + e + K_sha1[t] + W[t]) % (2 ** 32)
                e = d
                d = c
                c = ROTL(b, 30)
                b = a
                a = T

            tl = []
            tl.append((a + H[i][0]) % (2 ** 32))
            tl.append((b + H[i][1]) % (2 ** 32))
            tl.append((c + H[i][2]) % (2 ** 32))
            tl.append((d + H[i][3]) % (2 ** 32))
            tl.append((e + H[i][4]) % (2 ** 32))
            H.append(tl)

        return struct.pack('>%dI' % 5, *H[-1])


def sha_1(message: bytes) -> str:
    """ Hash message using SHA-1.

    """

    M = parse_padded(pad(message, 64), 64)
    H = [H_sha1]
    for i, m in enumerate(M):
        # Wt = [int(ba_hexlify(m[j:j+4]), 16) for j in range(0, len(m), 4)]
        W = list(struct.unpack('>%dI' % 16, m))

        for t in range(16, 80):
            W.append(ROTL(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1) % (2 ** 32))

        a = H[i][0]
        b = H[i][1]
        c = H[i][2]
        d = H[i][3]
        e = H[i][4]

        for t in range(0, 80):
            T = (ROTL(a, 5) + sha1_f(t, b, c, d) + e + K_sha1[t] + W[t]) % (2 ** 32)
            e = d
            d = c
            c = ROTL(b, 30)
            b = a
            a = T

        tl = []
        tl.append((a + H[i][0]) % (2 ** 32))
        tl.append((b + H[i][1]) % (2 ** 32))
        tl.append((c + H[i][2]) % (2 ** 32))
        tl.append((d + H[i][3]) % (2 ** 32))
        tl.append((e + H[i][4]) % (2 ** 32))
        H.append(tl)

    return struct.pack('>%dI' % 5, *H[-1])
    # return ''.join(hex(i)[2:].rjust(8, '0') for i in H[-1])

def sha_256(message: bytes) -> str:
    """ Hash message using SHA-256.

    """

    M = parse_padded(pad(message, 64), 64)
    H = [H_sha256]
    for i, m in enumerate(M):
        W = list(struct.unpack('>%dI' % 16, m))

        for t in range(16, 64):
            W.append((sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16]) % (2 ** 32))

        a = H[i][0]
        b = H[i][1]
        c = H[i][2]
        d = H[i][3]
        e = H[i][4]
        f = H[i][5]
        g = H[i][6]
        h = H[i][7]

        for t in range(0, 64):
            T1 = (h + Sigma1(e) + Ch(e, f, g) + K_sha256[t] + W[t]) % (2 ** 32)
            T2 = (Sigma0(a) + Maj(a, b, c)) % (2 ** 32)
            h = g
            g = f
            f = e
            e = (d + T1) % (2 ** 32)
            d = c
            c = b
            b = a
            a = (T1 + T2) % (2 ** 32)

        tl = []
        tl.append((a + H[i][0]) % (2 ** 32))
        tl.append((b + H[i][1]) % (2 ** 32))
        tl.append((c + H[i][2]) % (2 ** 32))
        tl.append((d + H[i][3]) % (2 ** 32))
        tl.append((e + H[i][4]) % (2 ** 32))
        tl.append((f + H[i][5]) % (2 ** 32))
        tl.append((g + H[i][6]) % (2 ** 32))
        tl.append((h + H[i][7]) % (2 ** 32))
        H.append(tl)

    return struct.pack('>%dI' % 8, *H[-1])

def sha_224(message: bytes) -> str:
    """ Hash message using SHA-224.

    """

    M = parse_padded(pad(message, 64), 64)
    H = [H_sha224]
    for i, m in enumerate(M):
        W = list(struct.unpack('>%dI' % 16, m))

        for t in range(16, 64):
            W.append((sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16]) % (2 ** 32))

        a = H[i][0]
        b = H[i][1]
        c = H[i][2]
        d = H[i][3]
        e = H[i][4]
        f = H[i][5]
        g = H[i][6]
        h = H[i][7]

        for t in range(0, 64):
            T1 = (h + Sigma1(e) + Ch(e, f, g) + K_sha256[t] + W[t]) % (2 ** 32)
            T2 = (Sigma0(a) + Maj(a, b, c)) % (2 ** 32)
            h = g
            g = f
            f = e
            e = (d + T1) % (2 ** 32)
            d = c
            c = b
            b = a
            a = (T1 + T2) % (2 ** 32)

        tl = []
        tl.append((a + H[i][0]) % (2 ** 32))
        tl.append((b + H[i][1]) % (2 ** 32))
        tl.append((c + H[i][2]) % (2 ** 32))
        tl.append((d + H[i][3]) % (2 ** 32))
        tl.append((e + H[i][4]) % (2 ** 32))
        tl.append((f + H[i][5]) % (2 ** 32))
        tl.append((g + H[i][6]) % (2 ** 32))
        tl.append((h + H[i][7]) % (2 ** 32))
        H.append(tl)

    return struct.pack('>%dI' % 7, *H[-1][:7])


class SHA512(HashBase):
    """ Hash data using the SHA512 secure hash method.

    """

    def __init__(self, data: bytes = b''):
        """ Hash data.

        """

        super(SHA512, self).__init__(data)

        self.block_size = 128
        self.digest_size = 64

    def _hash(self, message: bytes) -> str:
        """ Hash message using SHA-512.

        """

        M = parse_padded(pad(message, 128), 128)
        H = [H_sha512]
        for i, m in enumerate(M):
            W = list(struct.unpack('>%dQ' % 16, m))

            for t in range(16, 80):
                W.append((sigma1_512(W[t - 2]) + W[t - 7] + sigma0_512(W[t - 15]) + W[t - 16]) % (2 ** 64))


            a = H[i][0]
            b = H[i][1]
            c = H[i][2]
            d = H[i][3]
            e = H[i][4]
            f = H[i][5]
            g = H[i][6]
            h = H[i][7]

            for t in range(0, 80):
                T1 = (h + Sigma1_512(e) + Ch(e, f, g) + K_sha512[t] + W[t]) % (2 ** 64)
                T2 = (Sigma0_512(a) + Maj(a, b, c)) % (2 ** 64)
                h = g
                g = f
                f = e
                e = (d + T1) % (2 ** 64)
                d = c
                c = b
                b = a
                a = (T1 + T2) % (2 ** 64)

            tl = []
            tl.append((a + H[i][0]) % (2 ** 64))
            tl.append((b + H[i][1]) % (2 ** 64))
            tl.append((c + H[i][2]) % (2 ** 64))
            tl.append((d + H[i][3]) % (2 ** 64))
            tl.append((e + H[i][4]) % (2 ** 64))
            tl.append((f + H[i][5]) % (2 ** 64))
            tl.append((g + H[i][6]) % (2 ** 64))
            tl.append((h + H[i][7]) % (2 ** 64))
            H.append(tl)

        return struct.pack('>%dQ' % 8, *H[-1])

def sha_512(message: bytes) -> str:
    """ Hash message using SHA-512.

    """

    M = parse_padded(pad(message, 128), 128)
    H = [H_sha512]
    for i, m in enumerate(M):
        W = list(struct.unpack('>%dQ' % 16, m))

        for t in range(16, 80):
            W.append((sigma1_512(W[t - 2]) + W[t - 7] + sigma0_512(W[t - 15]) + W[t - 16]) % (2 ** 64))


        a = H[i][0]
        b = H[i][1]
        c = H[i][2]
        d = H[i][3]
        e = H[i][4]
        f = H[i][5]
        g = H[i][6]
        h = H[i][7]

        for t in range(0, 80):
            T1 = (h + Sigma1_512(e) + Ch(e, f, g) + K_sha512[t] + W[t]) % (2 ** 64)
            T2 = (Sigma0_512(a) + Maj(a, b, c)) % (2 ** 64)
            h = g
            g = f
            f = e
            e = (d + T1) % (2 ** 64)
            d = c
            c = b
            b = a
            a = (T1 + T2) % (2 ** 64)

        tl = []
        tl.append((a + H[i][0]) % (2 ** 64))
        tl.append((b + H[i][1]) % (2 ** 64))
        tl.append((c + H[i][2]) % (2 ** 64))
        tl.append((d + H[i][3]) % (2 ** 64))
        tl.append((e + H[i][4]) % (2 ** 64))
        tl.append((f + H[i][5]) % (2 ** 64))
        tl.append((g + H[i][6]) % (2 ** 64))
        tl.append((h + H[i][7]) % (2 ** 64))
        H.append(tl)

    return struct.pack('>%dQ' % 8, *H[-1])
sha_512.block_size = 128
sha_512.digest_size = 64
sha_1.block_size = 64
sha_1.digest_size = 20
sha_256.block_size = 64
sha_256.digest_size = 32

def sha_384(message: bytes) -> str:
    """ Hash message using SHA-512.

    """

    M = parse_padded(pad(message, 128), 128)
    H = [H_sha384]
    for i, m in enumerate(M):
        W = list(struct.unpack('>%dQ' % 16, m))

        for t in range(16, 80):
            W.append((sigma1_512(W[t - 2]) + W[t - 7] + sigma0_512(W[t - 15]) + W[t - 16]) % (2 ** 64))


        a = H[i][0]
        b = H[i][1]
        c = H[i][2]
        d = H[i][3]
        e = H[i][4]
        f = H[i][5]
        g = H[i][6]
        h = H[i][7]

        for t in range(0, 80):
            T1 = (h + Sigma1_512(e) + Ch(e, f, g) + K_sha512[t] + W[t]) % (2 ** 64)
            T2 = (Sigma0_512(a) + Maj(a, b, c)) % (2 ** 64)
            h = g
            g = f
            f = e
            e = (d + T1) % (2 ** 64)
            d = c
            c = b
            b = a
            a = (T1 + T2) % (2 ** 64)

        tl = []
        tl.append((a + H[i][0]) % (2 ** 64))
        tl.append((b + H[i][1]) % (2 ** 64))
        tl.append((c + H[i][2]) % (2 ** 64))
        tl.append((d + H[i][3]) % (2 ** 64))
        tl.append((e + H[i][4]) % (2 ** 64))
        tl.append((f + H[i][5]) % (2 ** 64))
        tl.append((g + H[i][6]) % (2 ** 64))
        tl.append((h + H[i][7]) % (2 ** 64))
        H.append(tl)

    return struct.pack('>%dQ' % 6, *H[-1][:6])


def strxor(a: bytes, b: bytes) -> bytes:
    """ strxor (a, b) -> XOR two bytes object together.

    """

    # Use the larger so a digit can be xored to a large number.
    out_len = max(len(a), len(b))

    # Endianness doesn't matter as long as they are all the same.
    xor_val = int.from_bytes(a, 'big') ^ int.from_bytes(b, 'big')
    return xor_val.to_bytes(out_len, 'big')


def hmac(K: bytes, text: bytes) -> bytes:
    """ Returns the hmaced version of text given key K.

    """

    B = 128
    L = 64

    ipad = b'\x36' * B
    opad = b'\x5c' * B

    if len(K) < B:
        K0 = K + b'\x00' * (B - len(K))
    elif len(K) > B:
        K0 = sha_512(K) + b'\x00' * (B - L)
    else:
        K0 = K

    s4 = strxor(K0, ipad)
    s5 = s4 + text
    s6 = sha_512(s5)
    s7 = strxor(K0, opad)
    s8 = s7 + s6
    s9 = sha_512(s8)
    return s9


class HMAC(object):
    """ HMAC object for authentiaction.

    """

    def __init__(self, key: bytes, data: bytes, hashmod: object = SHA1):
        """ HHAC

        """

        self._digest = self._hmac(key, data, H = hashmod)

    def digest(self) -> bytes:
        """ Return the digest.

        """

        return self._digest

    def hexdigest(self) -> bytes:
        """ Return the hexlified digest.

        """

        return ba_hexlify(self._digest)

    def _hmac(self, K: bytes, text: bytes, H: object = SHA1) -> bytes:
        """ Hmac text using key K and hashmod.

        """

        # Input block size of hash function
        B = H().block_size
        # Output block size of hash function
        L = H().digest_size

        # Inner pad
        ipad = b'\x36' * B
        # Outer pad
        opad = b'\x5c' * B

        if len(K) == B:
            K0 = K
        elif len(K) > B:
            K0 = H(K).digest() + ('\x00' * (B - L))
        elif len(K) < B:
            K0 = K + (b'\x00' * (B - len(K)))

        s4 = strxor(K0, ipad)
        s5 = s4 + text
        s6 = H(s5).digest()
        s7 = strxor(K0, opad)
        s8 = s7 + s6
        s9 = H(s8).digest()

        return s9


def _hmac(self, K: bytes, text: bytes, H: object = sha_1) -> bytes:
    """ Hmac text using key K and hashmod.

    """

    # Input block size of hash function
    B = H().block_size
    # Output block size of hash function
    L = H().digest_size

    # Inner pad
    ipad = b'\x36' * B
    # Outer pad
    opad = b'\x5c' * B

    if len(K) == B:
        K0 = K
    elif len(K) > B:
        K0 = H(K) + ('\x00' * (B - L))
    elif len(K) < B:
        K0 = K + (b'\x00' * (B - len(K)))

    s4 = strxor(K0, ipad)
    s5 = s4 + text
    s6 = H(s5)
    s7 = strxor(K0, opad)
    s8 = s7 + s6
    s9 = H(s8)

    return s9

def hkdf(SK: str, size: int, ctx: str) -> bytes:
    """ Return a key of size size from source key SK.

    """

    salt = b'?\x97\xf9\xfb\x1b\xf5\xf6\x91%\xd9v\\c\xb0\xba\xcb\xe4 \xcc\xcb>\x00`bX\xfe\x12\x93\nQ"%fG\x97J\x18\x12\x17jI\xdb\xea\x0f&\x15\xb0D\xcf\xd3d\xb7\\\x04\x84\x82Q\xe6\xd2\x13\xf5\x9a\xd1Wy\x89amq\x1c{\xa6!e-\xa2D\xa1\x96b\xdeG,G\xde\x18}\x9b\x96&\xa0\xeap\xb1R}\xcf\x19-\x848vlQ\xda\x0c\xe6\xba\xd9\xc9\x85{3\xc7\xf7\x1d\xb9\x83}z\xbf7\xd6\xc5\xbd\x19C('

    k = hmac(salt, SK).encode()

    K = ''
    c = 0
    while len(K) < size:
        K += hmac(k, ctx + hex(c)[2:])
        c += 1
    return K[:size].encode()


def pbkdf2(P: bytes, S: bytes, C: int, dkLen: int, prf: object = None) -> bytes:
    """ Generate a key from password pwd.

    """

    if not prf:
        prf = lambda k, s: HMAC(k, s, hashmod=SHA1).digest()

    # Get the prf digest length
    hLen = len(prf(P, S))
    kLen = dkLen

    if kLen > ((2 ** 32) - 1) * hLen:
        raise(Exception("dkLen is too long"))

    nlen = math.ceil(kLen / hLen)
    r = kLen - (nlen - 1) * hLen
    T = []
    for i in range(0, nlen):
        T.append(b'\x00')
        U = [S + struct.pack('>I', i + 1)]
        for j in range(1, C + 1):
            U.append(prf(P, U[j - 1]))
            T[i] = strxor(T[i], U[j])

    return b''.join(T)[:r]
