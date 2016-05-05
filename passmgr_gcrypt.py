#!/usr/bin/env python
# vim: sw=4:ts=4:sts=4:fdm=indent:fdl=0:
# -*- coding: UTF8 -*-
#
# Account manager
# Copyright (C) 2016 Josiah Gordon <josiahg@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


""" Account manager.  Stores account information in a LZMA compressed file.
The account info is put in JSON format and each account name is hashed, and the
data is encrypted using AES-256-CBC encryption.

"""


from pathlib import Path as pathlib_path
from lzma import compress as lzma_compress
from lzma import decompress as lzma_decompress
from json import loads as json_loads
from json import dumps as json_dumps
import codecs
import getpass
from os import environ as os_environ
from ctypes import *
from ctypes.util import find_library

# Disable writing lesshst file so when searching in the less pager the
# search terms won't be recorded.
os_environ['LESSHISTFILE'] = '/dev/null'

# Use less as the pager.
os_environ['PAGER'] = '$(which less)'

gcrypt_name = find_library('gcrypt')
if not gcrypt_name:
    raise Exception("gcrypt could not be found")

_gcrypt_lib = cdll.LoadLibrary(gcrypt_name)

gcry_error_t = c_uint
gcry_err_code_t = c_uint
gcry_err_source_t = c_uint

# /* Perform various operations defined by CMD. */
# gcry_error_t gcry_control (enum gcry_ctl_cmds CMD, ...);
gcry_control = _gcrypt_lib.gcry_control
# gcry_control.argtypes = [gcry_ctl_cmds, *args]
gcry_control.restype = c_uint

# /* A generic context object as used by some functions.  */
# struct gcry_context;
class gcry_context(Structure): pass
# typedef struct gcry_context *gcry_ctx_t;
gcry_ctx_t = POINTER(gcry_context)

gcry_random_bytes_secure = _gcrypt_lib.gcry_random_bytes_secure
gcry_random_bytes_secure.argtypes = [c_size_t, c_int]
gcry_random_bytes_secure.restype = c_void_p

GCRY_KDF_PBKDF2 = 34
GCRY_MD_SHA256  = 8
GCRY_MD_SHA512  = 10
GCRY_MAC_HMAC_SHA512        = 103
GCRY_CIPHER_AES256      = 9
GCRY_CIPHER_MODE_CBC    = 3  # Cipher block chaining. */
GCRY_VERY_STRONG_RANDOM = 2
GCRY_CIPHER_SECURE      = 1  # Allocate in secure memory. */
GCRY_MAC_FLAG_SECURE = 1  # Allocate all buffers in "secure" memory.  */


# /* Derive a key from a passphrase.  */
# gpg_error_t gcry_kdf_derive (const void *passphrase, size_t passphraselen,
#                              int algo, int subalgo,
#                              const void *salt, size_t saltlen,
#                              unsigned long iterations,
#                              size_t keysize, void *keybuffer);
gcry_kdf_derive = _gcrypt_lib.gcry_kdf_derive
gcry_kdf_derive.argtypes = [c_void_p, c_size_t, c_int, c_int, c_void_p,
                            c_size_t, c_ulong, c_size_t, c_void_p]
gcry_kdf_derive.restype = c_int

# /* The data object used to hold a handle to an encryption object.  */
# struct gcry_mac_handle;
class gcry_mac_handle(Structure): pass
# typedef struct gcry_mac_handle *gcry_mac_hd_t;
gcry_mac_hd_t = POINTER(gcry_mac_handle)
# gcry_error_t gcry_mac_open (gcry_mac_hd_t *handle, int algo,
#                             unsigned int flags, gcry_ctx_t ctx);
gcry_mac_open = _gcrypt_lib.gcry_mac_open
gcry_mac_open.argtypes = [POINTER(gcry_mac_hd_t), c_int, c_uint, gcry_ctx_t]
gcry_mac_open.restype = gcry_error_t

# /* Close the MAC handle H and release all resource. */
# void gcry_mac_close (gcry_mac_hd_t h);
gcry_mac_close = _gcrypt_lib.gcry_mac_close
gcry_mac_close.argtypes = [gcry_mac_hd_t]
gcry_mac_close.restype = None

# /* Set KEY of length KEYLEN bytes for the MAC handle HD.  */
# gcry_error_t gcry_mac_setkey (gcry_mac_hd_t hd, const void *key,
#                               size_t keylen);
gcry_mac_setkey = _gcrypt_lib.gcry_mac_setkey
gcry_mac_setkey.argtypes = [gcry_mac_hd_t, c_void_p, c_size_t]
gcry_mac_setkey.restype = gcry_error_t

# /* Set initialization vector IV of length IVLEN for the MAC handle HD. */
# gcry_error_t gcry_mac_setiv (gcry_mac_hd_t hd, const void *iv,
#                              size_t ivlen);
gcry_mac_setiv = _gcrypt_lib.gcry_mac_setiv
gcry_mac_setiv.argtypes = [gcry_mac_hd_t, c_void_p, c_size_t]
gcry_mac_setiv.restype = gcry_error_t

# /* Pass LENGTH bytes of data in BUFFER to the MAC object HD so that
#    it can update the MAC values.  */
# gcry_error_t gcry_mac_write (gcry_mac_hd_t hd, const void *buffer,
#                              size_t length);
gcry_mac_write = _gcrypt_lib.gcry_mac_write
gcry_mac_write.argtypes = [gcry_mac_hd_t, c_void_p, c_size_t]
gcry_mac_write.restype = gcry_error_t

# /* Read out the final authentication code from the MAC object HD to BUFFER. */
# gcry_error_t gcry_mac_read (gcry_mac_hd_t hd, void *buffer, size_t *buflen);
gcry_mac_read = _gcrypt_lib.gcry_mac_read
gcry_mac_read.argtypes = [gcry_mac_hd_t, c_void_p, POINTER(c_size_t)]
gcry_mac_read.restype = gcry_error_t

# /* Verify the final authentication code from the MAC object HD with BUFFER. */
# gcry_error_t gcry_mac_verify (gcry_mac_hd_t hd, const void *buffer,
#                               size_t buflen);
gcry_mac_verify = _gcrypt_lib.gcry_mac_verify
gcry_mac_verify.argtypes = [gcry_mac_hd_t, c_void_p, c_size_t]
gcry_mac_verify.restype = gcry_error_t

# /* Retrieve the length in bytes of the MAC yielded by algorithm ALGO. */
# unsigned int gcry_mac_get_algo_maclen (int algo);
gcry_mac_get_algo_maclen = _gcrypt_lib.gcry_mac_get_algo_maclen
gcry_mac_get_algo_maclen.argtypes = [c_int]
gcry_mac_get_algo_maclen.restype = c_uint

# /* Retrieve the default key length in bytes used with algorithm A. */
# unsigned int gcry_mac_get_algo_keylen (int algo);
gcry_mac_get_algo_keylen = _gcrypt_lib.gcry_mac_get_algo_keylen
gcry_mac_get_algo_keylen.argtypes = [c_int]
gcry_mac_get_algo_keylen.restype = c_uint

# /* The data object used to hold a handle to an encryption object.  */
# struct gcry_cipher_handle;
class gcry_cipher_handle(Structure): pass
# typedef struct gcry_cipher_handle *gcry_cipher_hd_t;
gcry_cipher_hd_t = POINTER(gcry_cipher_handle)

# /* Create a handle for algorithm ALGO to be used in MODE.  FLAGS may
#    be given as an bitwise OR of the gcry_cipher_flags values. */
# gcry_error_t gcry_cipher_open (gcry_cipher_hd_t *handle,
#                               int algo, int mode, unsigned int flags);
gcry_cipher_open = _gcrypt_lib.gcry_cipher_open
gcry_cipher_open.argtypes = [POINTER(gcry_cipher_hd_t), c_int, c_int, c_uint]
gcry_cipher_open.restype = gcry_error_t

# /* Close the cioher handle H and release all resource. */
# void gcry_cipher_close (gcry_cipher_hd_t h);
gcry_cipher_close = _gcrypt_lib.gcry_cipher_close
gcry_cipher_close.argtypes = [gcry_cipher_hd_t]
gcry_cipher_close.restype = None

# /* Encrypt the plaintext of size INLEN in IN using the cipher handle H
#    into the buffer OUT which has an allocated length of OUTSIZE.  For
#    most algorithms it is possible to pass NULL for in and 0 for INLEN
#    and do a in-place decryption of the data provided in OUT.  */
# gcry_error_t gcry_cipher_encrypt (gcry_cipher_hd_t h,
#                                   void *out, size_t outsize,
#                                   const void *in, size_t inlen);
gcry_cipher_encrypt = _gcrypt_lib.gcry_cipher_encrypt
gcry_cipher_encrypt.argtypes = [gcry_cipher_hd_t, c_void_p, c_size_t, c_void_p,
                                c_size_t]
gcry_cipher_encrypt.restype = gcry_error_t

# /* The counterpart to gcry_cipher_encrypt.  */
# gcry_error_t gcry_cipher_decrypt (gcry_cipher_hd_t h,
#                                   void *out, size_t outsize,
#                                   const void *in, size_t inlen);
gcry_cipher_decrypt = _gcrypt_lib.gcry_cipher_decrypt
gcry_cipher_decrypt.argtypes = [gcry_cipher_hd_t, c_void_p, c_size_t, c_void_p,
                                c_size_t]
gcry_cipher_decrypt.restype = gcry_error_t

# /* Set KEY of length KEYLEN bytes for the cipher handle HD.  */
# gcry_error_t gcry_cipher_setkey (gcry_cipher_hd_t hd,
#                                  const void *key, size_t keylen);
gcry_cipher_setkey = _gcrypt_lib.gcry_cipher_setkey
gcry_cipher_setkey.argtypes = [gcry_cipher_hd_t, c_void_p, c_size_t]
gcry_cipher_setkey.restype = gcry_error_t


# /* Set initialization vector IV of length IVLEN for the cipher handle HD. */
# gcry_error_t gcry_cipher_setiv (gcry_cipher_hd_t hd,
#                                 const void *iv, size_t ivlen);
gcry_cipher_setiv = _gcrypt_lib.gcry_cipher_setiv
gcry_cipher_setiv.argtypes = [gcry_cipher_hd_t, c_void_p, c_size_t]
gcry_cipher_setiv.restype = gcry_error_t

# /* Retrieve the key length in bytes used with algorithm A. */
# size_t gcry_cipher_get_algo_keylen (int algo);
gcry_cipher_get_algo_keylen = _gcrypt_lib.gcry_cipher_get_algo_keylen
gcry_cipher_get_algo_keylen.argtypes = [c_int]
gcry_cipher_get_algo_keylen.restype = c_size_t

# /* Retrieve the block length in bytes used with algorithm A. */
# size_t gcry_cipher_get_algo_blklen (int algo);
gcry_cipher_get_algo_blklen = _gcrypt_lib.gcry_cipher_get_algo_blklen
gcry_cipher_get_algo_blklen.argtypes = [c_int]
gcry_cipher_get_algo_blklen.restype = c_size_t

# /* (Forward declaration.)  */
# struct gcry_md_context;
class gcry_md_context(Structure): pass

# /* This object is used to hold a handle to a message digest object.
#    This structure is private - only to be used by the public gcry_md_*
#    macros.  */
# typedef struct gcry_md_handle
class gcry_md_handle(Structure):
    _fields_ = [
            # /* Actual context.  */
            # struct gcry_md_context *ctx;
            ('ctx', POINTER(gcry_md_context)),

            # /* Buffer management.  */
            # int  bufpos;
            ('bufpos', c_int),
            # int  bufsize;
            ('bufsize', c_int),
            # unsigned char buf[1];
            ('buf', c_char_p),
            ]
gcry_md_hd_t = POINTER(gcry_md_handle)

# /* Create a message digest object for algorithm ALGO.  FLAGS may be
#    given as an bitwise OR of the gcry_md_flags values.  ALGO may be
#    given as 0 if the algorithms to be used are later set using
#    gcry_md_enable.  */
# gcry_error_t gcry_md_open (gcry_md_hd_t *h, int algo, unsigned int flags);
gcry_md_open = _gcrypt_lib.gcry_md_open
gcry_md_open.argtypes = [POINTER(gcry_md_hd_t), c_int, c_uint]
gcry_md_open.restype = gcry_error_t

# /* Release the message digest object HD.  */
# void gcry_md_close (gcry_md_hd_t hd);
gcry_md_close = _gcrypt_lib.gcry_md_close
gcry_md_close.argtypes = [gcry_md_hd_t]
gcry_md_close.restype = None

# /* Pass LENGTH bytes of data in BUFFER to the digest object HD so that
#    it can update the digest values.  This is the actual hash
#    function. */
# void gcry_md_write (gcry_md_hd_t hd, const void *buffer, size_t length);
gcry_md_write = _gcrypt_lib.gcry_md_write
gcry_md_write.argtypes = [gcry_md_hd_t, c_void_p, c_size_t]
gcry_md_write.restype = None

# /* Read out the final digest from HD return the digest value for
#    algorithm ALGO. */
# unsigned char *gcry_md_read (gcry_md_hd_t hd, int algo);
gcry_md_read = _gcrypt_lib.gcry_md_read
gcry_md_read.argtypes = [gcry_md_hd_t, c_int]
gcry_md_read.restype = POINTER(c_ubyte)

# /* Convenience function to calculate the hash from the data in BUFFER
#    of size LENGTH using the algorithm ALGO avoiding the creating of a
#    hash object.  The hash is returned in the caller provided buffer
#    DIGEST which must be large enough to hold the digest of the given
#    algorithm. */
# void gcry_md_hash_buffer (int algo, void *digest,
#                           const void *buffer, size_t length);
gcry_md_hash_buffer = _gcrypt_lib.gcry_md_hash_buffer
gcry_md_hash_buffer.argtypes = [c_int, c_void_p, c_void_p, c_size_t]
gcry_md_hash_buffer.restype = None

# /* Retrieve the length in bytes of the digest yielded by algorithm
#    ALGO. */
# unsigned int gcry_md_get_algo_dlen (int algo);
gcry_md_get_algo_dlen = _gcrypt_lib.gcry_md_get_algo_dlen
gcry_md_get_algo_dlen.argtypes = [c_int]
gcry_md_get_algo_dlen.restype = c_uint

# /* Map the digest algorithm id ALGO to a string representation of the
#    algorithm name.  For unknown algorithms this function returns
#    "?". */
# const char *gcry_md_algo_name (int algo) _GCRY_GCC_ATTR_PURE;
gcry_md_algo_name = _gcrypt_lib.gcry_md_algo_name
gcry_md_algo_name.argtypes = [c_int]
gcry_md_algo_name.restype = c_char_p

# /* Map the algorithm NAME to a digest algorithm Id.  Return 0 if
#    the algorithm name is not known. */
# int gcry_md_map_name (const char* name) _GCRY_GCC_ATTR_PURE;
gcry_md_map_name = _gcrypt_lib.gcry_md_map_name
gcry_md_map_name.argtypes = [c_char_p]
gcry_md_map_name.restype = c_int

# /* For use with the HMAC feature, the set MAC key to the KEY of
#    KEYLEN bytes. */
# gcry_error_t gcry_md_setkey (gcry_md_hd_t hd, const void *key, size_t keylen);
gcry_md_setkey = _gcrypt_lib.gcry_md_setkey
gcry_md_setkey.argtypes = [gcry_md_hd_t, c_void_p, c_size_t]
gcry_md_setkey.restype = gcry_error_t

gcry_free = _gcrypt_lib.gcry_free
gcry_free.argtypes = [c_void_p]
gcry_free.restype = None

gcry_ctx_release = _gcrypt_lib.gcry_ctx_release
gcry_ctx_release.argtypes = [gcry_ctx_t]
gcry_ctx_release.restype = None


KEY_LEN = SALT_LEN = gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256)
IV_LEN = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256)

def PKCS7_pad(data: bytes, multiple: int) -> bytes:
    """ Pad the data using the PKCS#7 method.

    """

    # Pads byte pad_len to the end of the plain text to make it a
    # multiple of the multiple.
    pad_len = multiple - (len(data) % multiple)

    return data + bytes([pad_len]) * pad_len


def encrypt_sha256(key: bytes, plaintext: str) -> bytes:
    """ encrypt(key, plaintext) ->  Encrypts plaintext using key.

    """

    block_size = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256)
    digest_len = gcry_md_get_algo_dlen(GCRY_MD_SHA256)
    valid_key = bytes(digest_len)
    gcry_md_hash_buffer(GCRY_MD_SHA256, valid_key, key, len(key))
    # valid_key = valid_key.hex()

    cipher_handle = gcry_cipher_hd_t()
    gcry_cipher_open(cipher_handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC,
                        GCRY_CIPHER_SECURE )
    iv = string_at(gcry_random_bytes_secure(block_size, 2), block_size)
    gcry_cipher_setkey(cipher_handle, valid_key, KEY_LEN)
    gcry_cipher_setiv(cipher_handle, iv, block_size)
    pt_len = len(plaintext)
    ciphertext = bytes(pt_len)
    gcry_cipher_encrypt(cipher_handle, ciphertext, pt_len, plaintext, pt_len)
    gcry_cipher_close(cipher_handle)

    return iv + ciphertext


def decrypt_sha256(key: bytes, ciphertext: bytes) -> str:
    """ decrypt(key, ciphertext) -> Decrypts the cipher text using the key.

    """

    digest_len = gcry_md_get_algo_dlen(GCRY_MD_SHA256)
    valid_key = bytes(digest_len)
    gcry_md_hash_buffer(GCRY_MD_SHA256, valid_key, key.encode(), len(key))

    iv = ciphertext[:IV_LEN]
    real_ciphertext = ciphertext[IV_LEN:]

    block_size = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256)

    cipher_handle = gcry_cipher_hd_t()
    gcry_cipher_open(cipher_handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC,
                     GCRY_CIPHER_SECURE)
    gcry_cipher_setkey(cipher_handle, valid_key, KEY_LEN)
    gcry_cipher_setiv(cipher_handle, iv, block_size)
    ct_len = len(real_ciphertext)
    padded_plaintext = bytes(ct_len)
    gcry_cipher_decrypt(cipher_handle, padded_plaintext, ct_len,
                        real_ciphertext, ct_len)
    gcry_cipher_close(cipher_handle)

    try:
        # Remove the padding from the plain text.
        plaintext = padded_plaintext[:-padded_plaintext[-1]].decode()
    except UnicodeDecodeError:
        print("There was an error.  Maybe the wrong password was given.")
        return ''

    return plaintext


def bytes_to_str_sha256(bytes_obj: bytes) -> str:
    """ Encodes the bytes object using base64, and returns that string value.

    """

    return codecs.encode(bytes_obj, 'base64').decode()


def str_to_bytes_sha256(str_obj: str) -> bytes:
    """ Decodes a base64 string into a bytes object.

    """

    return codecs.decode(str_obj.encode(), 'base64')


def crypt_to_dict_sha256(crypt_data: str, password: str = '',
                  skip_invalid: bool = True) -> dict:
    """ Decrypts crypt_data and returns the json.loads dictionary.
    If skip_invalid is True then skip decryption of data if the password is
    invalid.

    """

    while True:
        # Get the password to decrypt the data.
        if not password:
            password = getpass.getpass('Enter the password for decryption: ')

        # Convert the data to a bytes object and decrypt it.
        json_data = decrypt_sha256(password, str_to_bytes_sha256(crypt_data))

        # Load the decrypted data with json and return the resulting
        # dictionary.
        try:
            return json_loads(json_data)
        except:
            # Don't loop forever unless asked to.
            if skip_invalid:
                print('Skipping, because of invalid password.')
                return {}
            else:
                print('Invalid password.  Please try again.')
                password = ''
                continue


def dict_to_crypt_sha256(data_dict: dict, password: str = '') -> str:
    """ Returns the encrypted json dump of data_dict.

    """


    # Dump the data_dict into json data.
    json_data = json_dumps(data_dict)

    if not password:
        # Get the password to encrypt the data.
        password = get_pass('password for encryption')

    # Return the string encoded encrypted json dump.
    return bytes_to_str_sha256(encrypt_sha256(password, json_data))


def get_pass(question_str: str, verify: bool = True) -> str:
    """ Get a secret optionally ask twice to make sure it was inputted
    correctly.

    """

    if not verify: return getpass.getpass('Enter the %s: ' % question_str)

    a1 = 'a'
    a2 = 'b'

    # Loop until both entries match.
    while a1 != a2:
        a1 = getpass.getpass('Enter the %s: ' % question_str)
        a2 = getpass.getpass('Verify the %s: ' % question_str)
        if a1 != a2:
            print('The %s did not match.  Please try again.' % question_str)

    return a1


class CryptData(object):
    """ Easily encrypt/decrypt data.  The data is authenticated when it is
    decrypted.

    """

    def __init__(self, password: str, encrypted_key: bytes = b''):
        """ Initialize the data.

        """

        if not encrypted_key:
            # Generate the largest key possible.
            self._key = self.create_key(KEY_LEN)
        else:
            self._key = self._decrypt_key(encrypted_key, password)

        self._password = password

    def create_key(self, length: int) -> bytes:
        """ Generates a cryptographic random key of length 'length'.

        """

        k = gcry_random_bytes_secure(length, 2)
        return string_at(k, length)

    @property
    def encrypted_key(self) -> bytes:
        """ Returns the encrypted key.

        """

        return self._encrypt_key(self._key, self._password)

    @property
    def password(self) -> str:
        """ Returns the password.

        """

        return self._password

    @password.setter
    def password(self, new_password: str):
        """ Changes the password used to encrypt the key.

        """

        self._password = new_password

    def _encrypt(self, data: bytes, key: bytes) -> bytes:
        """ Returns the AES_CBC encryption of data using key.
        The return value is the concatenation of iv + cipher text.

        """

        data_len = len(data)

        iv = string_at(gcry_random_bytes_secure(IV_LEN, 2), IV_LEN)

        cipher_handle = gcry_cipher_hd_t()
        gcry_cipher_open(cipher_handle, GCRY_CIPHER_AES256,
                         GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE)
        gcry_cipher_setkey(cipher_handle, key, KEY_LEN)
        gcry_cipher_setiv(cipher_handle, iv, IV_LEN)
        ciphertext = bytes(data_len)
        gcry_cipher_encrypt(cipher_handle, ciphertext, data_len, data,
                            data_len)
        gcry_cipher_close(cipher_handle)

        return iv + ciphertext

    def _decrypt(self, data: bytes, key: bytes) -> bytes:
        """ Decrypts data using key.  The data should be the concatenation of
        iv + cipher text.

        """

        iv = data[:IV_LEN]
        data = data[IV_LEN:]
        data_len = len(data)

        cipher_handle = gcry_cipher_hd_t()
        gcry_cipher_open(cipher_handle, GCRY_CIPHER_AES256,
                         GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE)
        gcry_cipher_setkey(cipher_handle, key, KEY_LEN)
        gcry_cipher_setiv(cipher_handle, iv, IV_LEN)
        decrypted_data = bytes(data_len)
        gcry_cipher_decrypt(cipher_handle, decrypted_data, data_len, data,
                            data_len)
        gcry_cipher_close(cipher_handle)

        return decrypted_data

    def _verify_key(self, encrypted_key: bytes, password: bytes) -> bytes:
        """ Verifies that password can decrypt encrypted_key, and returns the
        key generated from password that will decrypt encrypted_key.

        """

        # Get the salt and iv from the start of the encrypted data.
        salt = encrypted_key[:SALT_LEN]

        # Generate a key and verification key from the password and
        # salt.
        crypt_key, auth_key = self._gen_keys(password, salt,
                                             dkLen = KEY_LEN * 2)

        if auth_key != encrypted_key[-KEY_LEN:]:
            raise(Exception("Invalid password or file was tampered with."))

        return crypt_key

    def _decrypt_key(self, encrypted_key: bytes, password: str) -> bytes:
        """ Decrypt a key encrypted with encrypt_key.

        """

        # Verify that the password is correct and/or the file has not
        # been tampered with.
        crypt_key = self._verify_key(encrypted_key, password)

        # Decrypt the key.
        key = self._decrypt(encrypted_key[SALT_LEN:-KEY_LEN], crypt_key)

        return key

    def _encrypt_key(self, key: bytes, password: str) -> bytes:
        """ Converts password into a valid key and uses that to encrypt a key.
        Returns salt + encrypted_key + auth_key where salt is used to produce
        key material from the password.  That key material is split, and the
        first half is used to encrypt the key and the second is the auth_key to
        verify the password when decrypting.

        """

        # Generate a large salt.
        # salt = Random.new().read(SALT_LEN)
        salt = string_at(gcry_random_bytes_secure(SALT_LEN, 2), SALT_LEN)

        # Generate a key and verification key from the password and
        # salt.
        crypt_key, auth_key = self._gen_keys(password, salt, dkLen = KEY_LEN * 2)

        return salt + self._encrypt(key, crypt_key) + auth_key

    def _gen_keys(self, password: str, salt: bytes, dkLen: int = KEY_LEN,
                  iterations: int = 5000) -> tuple:
        """ Uses a password and PBKDF2 to generate 512-bits of key material.
        Then it splits it, and returns a tuple of the first 256-bit for a key,
        and the second 256-bit block for a verification code.

        """

        key_mat = bytes(dkLen)

        # Use SHA512 as the hash method in hmac.
        gcry_kdf_derive(password.encode(), len(password), GCRY_KDF_PBKDF2,
                        GCRY_MD_SHA512, salt, len(salt), iterations, dkLen,
                        key_mat)
        # The encryption key is the first 256-bits of material.
        crypt_key = key_mat[:KEY_LEN]
        # The second 256-bits is used to verify the key and password.
        auth_key = key_mat[KEY_LEN:]

        return crypt_key, auth_key

    def _verify(self, ciphertext: bytes) -> bytes:
        """ Raises an error if the cipher text isn't valid.

        """

        # Extract the hmac digest and encrypted hmac key from the
        # cipher text
        digest_len = gcry_md_get_algo_dlen(GCRY_MD_SHA512)

        hmac_digest = ciphertext[-digest_len:]
        ciphertext = ciphertext[:-digest_len]
        encrypted_hmac_key = ciphertext[-(IV_LEN + KEY_LEN):]
        ciphertext = ciphertext[:-(IV_LEN + KEY_LEN)]

        # Decrypt hmac key.
        hmac_key = self._decrypt(encrypted_hmac_key, self._key)

        # Test the generated digest against the stored digest and fail if they
        # are different.
        assert(hmac_digest == self._get_hmac_digest(ciphertext, hmac_key))

        # Only return the cipher text to be decrypted if the digests match.
        return ciphertext

    def _get_hmac_digest(self, data: bytes, key: bytes) -> bytes:
        """ Returns the hmac digest of data using key.

        """

        digest_len = gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_SHA512)
        digest = bytes(digest_len)

        # Re-generate the hmac digest of cipher text.
        mac_handle = gcry_mac_hd_t()
        context = gcry_ctx_t()
        gcry_mac_open(mac_handle, GCRY_MAC_HMAC_SHA512, GCRY_MAC_FLAG_SECURE,
                      context)
        gcry_mac_setkey(mac_handle, key, KEY_LEN)
        gcry_mac_write(mac_handle, data, len(data))
        gcry_mac_read(mac_handle, digest, c_ulong(digest_len))
        gcry_mac_close(mac_handle)
        gcry_ctx_release(context)

        return digest

    def encrypt(self, plaintext: str) -> bytes:
        """ encrypt(key, plaintext) ->  Encrypts the plain text using key.

        """

        # Pad the plain text.
        block_size = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256)
        padded_plaintext = PKCS7_pad(plaintext.encode(), block_size)

        # Encrypt it.
        ciphertext = self._encrypt(padded_plaintext, self._key)

        # Generate the largest key we can use.
        hmac_key = string_at(gcry_random_bytes_secure(KEY_LEN, 2), KEY_LEN)

        # Generate an hmac of the cipher text, and put the encrypted key and
        # digest at the end of the cipher text.
        hmac_digest = self._get_hmac_digest(ciphertext, hmac_key)
        return ciphertext + self._encrypt(hmac_key, self._key) + hmac_digest

    def decrypt(self, ciphertext: bytes) -> str:
        """ decrypt(key, ciphertext) -> Decrypts the cipher text using the key.

        """

        try:
            ciphertext = self._verify(ciphertext)
        except AssertionError:
            print("Invalid data.  Can't decrypt.")
            return ''

        padded_plaintext = self._decrypt(ciphertext, self._key)

        # Remove the padding from the plain text, and return the result.
        return padded_plaintext[:-padded_plaintext[-1]].decode()


class PassFile(object):
    """ An encrypted password file.

    The format is a dictionary where the master key is stored under the key
    '\x00master_key\x00' and each account name is hashed and used as the key to
    that accounts encrypted data.  The account data is encrypted with the
    master key and the hmac of that and the iv is stored at the end of each
    account info. So it is like this.
    {
        hashed(\x00master_key\x00): salt+iv+encrypted_master_key,
        hashed(account_name): iv+encrypted_account_dict+encrypted_hmac_key+hmac_digest,
        ...
    }

    """

    # MASTER_KEY_DIGEST = SHA512.new(b'\x00master_key\x00').hexdigest()


    def __init__(self, filename: str, password: str = '',
                 pass_func: object = get_pass):
        """ Open the filename and read out the data.  Decrypt it and allow
        access.

        """

        digest_len = gcry_md_get_algo_dlen(GCRY_MD_SHA512)
        MASTER_KEY_DIGEST = bytes(digest_len)
        _mkey_ = b'\x00master_key\x00'
        gcry_md_hash_buffer(GCRY_MD_SHA512, MASTER_KEY_DIGEST, _mkey_, len(_mkey_))
        self.MASTER_KEY_DIGEST = MASTER_KEY_DIGEST.hex()

        self._filename = filename
        self._ask_pass = pass_func

        cryptdata, accounts_dict = self._read_file(filename, password)
        self._cryptdata, self._accounts_dict = cryptdata, accounts_dict

    def _read_file(self, filename: str, password: str = '') -> dict:
        """ Reads the data from filename and returns the account dictionary,
        the encrypted master key, and the decrypted master key.

        """

        # Read from the file if it exists.
        with pathlib_path(filename) as pass_file:
            lzma_data = pass_file.read_bytes() if pass_file.is_file() else b''

        # Get the json data out of the file data or an empty json dict of
        # the file was empty.
        if lzma_data:
            json_data = lzma_decompress(lzma_data).decode()
        else:
            json_data = '{}'

        accounts_dict = json_loads(json_data)

        # Pop the master key out of the accounts dictionary so it won't be
        # operated on or listed.  Also if no master key is found, create
        # one.
        encrypted_key = bytes.fromhex(accounts_dict.pop(self.MASTER_KEY_DIGEST, ''))

        if not encrypted_key:
            if not password:
                # Get the password to encrypt the master key.
                password = self._ask_pass('password')
        else:
            # Get the password to decrypt the key.
            password = self._ask_pass('password', verify=False)

        return CryptData(password, encrypted_key), accounts_dict

    def _write_file(self, filename: str, accounts_dict: dict, 
                    encrypted_key: bytes):
        """ Compresses and writes the accounts_dict to the file at filename.

        """

        # Put the master key into the accounts dict.
        accounts_dict[self.MASTER_KEY_DIGEST] = encrypted_key.hex()

        json_data = json_dumps(accounts_dict)

        lzma_data = lzma_compress(json_data.encode())

        with pathlib_path(filename) as pass_file:
            pass_file.write_bytes(lzma_data)

    def _hash_name(self, name: str) -> bytes:
        """ Hashes name and returns the result.

        """

        # return SHA512.new(name.encode()).hexdigest()
        digest_len = gcry_md_get_algo_dlen(GCRY_MD_SHA512)
        name_hash = bytes(digest_len)
        gcry_md_hash_buffer(GCRY_MD_SHA512, name_hash, name.encode(), len(name))
        return name_hash.hex()

    def _crypt_to_dict(self, crypt_data: str) -> dict:
        """ Decrypts crypt_data and returns the json.loads dictionary.
        If skip_invalid is True then skip decryption of data if the password is
        invalid.

        """

        # Return an empty dictionary if crypt_data is empty.
        if not crypt_data: return {}

        # Convert the data to a bytes object and decrypt it.
        json_data = self._cryptdata.decrypt(bytes.fromhex(crypt_data))

        # Load the decrypted data with json and return the resulting
        # dictionary.
        return json_loads(json_data)


    def _dict_to_crypt(self, data_dict: dict) -> str:
        """ Returns the encrypted json dump of data_dict.

        """

        # Dump the data_dict into json data.  
        json_data = '{}' if not data_dict else json_dumps(data_dict)

        ciphertext = self._cryptdata.encrypt(json_data)

        # Return the hexadecimal representation of the cipher text.
        return ciphertext.hex()

    def get(self, account: str, default: dict = {}) -> dict:
        """ Return the value from accounts_dict associated with key.

        """

        account_hash = self._hash_name(account)

        if account_hash not in self._accounts_dict:
            return default

        return self._crypt_to_dict(self._accounts_dict[account_hash])

    def set(self, account: str, value: dict):
        """ Set the value associated with key.

        """

        account_hash = self._hash_name(account)
        self._accounts_dict[account_hash] = self._dict_to_crypt(value)

    def accounts(self) -> iter:
        """ Iterate through all the items in _accounts_dict.

        """

        for i in self._accounts_dict.values():
            yield self._crypt_to_dict(i)

    def change_pass(self, new_password: str):
        """ Change the password used to encrypt the master_key.

        """

        self._cryptdata.password = new_password

    def remove(self, item: str):
        """ Remove the entry at item.

        """

        self._accounts_dict.pop(self._hash_name(item))

    def convert(self):
        """ Convert to latest format.

        """

        tmp_accounts_dict = {}
        for account_hash, account_data in self._accounts_dict.items():
            account_dict = crypt_to_dict_sha256(account_data,
                                                password=self._cryptdata.password,
                                                skip_invalid=True)
            if account_dict:
                new_account_data = self._dict_to_crypt(account_dict)
            else:
                raise(Exception("Invalid password.  Can't convert."))
            account_name = account_dict.get('Account Name', '')
            new_account_hash = self._hash_name(account_name)
            tmp_accounts_dict[new_account_hash] = new_account_data
        self._accounts_dict = tmp_accounts_dict

    def __contains__(self, item: str) -> bool:
        """ Checks if accounts_dict has a key of value item.

        """

        return self._hash_name(item) in self._accounts_dict

    def __enter__(self):
        """ Provides the ability to use pythons with statement.

        """

        try:
            return self
        except Exception as err:
            print(err)
            return None

    def __exit__(self, exc_type, exc_value, traceback):
        """ Close the file when finished.

        """

        try:
            self._write_file(self._filename, self._accounts_dict,
                             self._cryptdata.encrypted_key)
            return not bool(exc_type)
        except Exception as err:
            print(err)
            return False


def dict_to_str(data_dict: dict) -> str:
    """ Returns a formatted string of the (key, value) items in the supplied
    dictionary.

    """

    str_list = ['\n']

    max_key_len = max(len(key) for key in data_dict.keys())

    for key, value in data_dict.items():
        if key == 'Account Name':
            str_list.insert(1, "{1:<{0}} -> {2}".format(max_key_len,
                                                        key, value))
            continue

        # Format the info in a list as follows:
        # key (right align by space max_key_len): value
        str_list.append("{1:<{0}} -> {2}".format(max_key_len,
                                            key.lower().capitalize(),
                                            value))

    return '\n'.join(str_list)


def convert(args: object) -> int:
    """ Convert from SHA256 hashed key to using a master key and encrypting the
    master key with a password based key.

    """

    filename = args.filename
    password = get_pass('password', verify=False)

    print("Converting...", end='')
    with PassFile(filename, password) as passfile:
        passfile.convert()
    print("Done.")

    return 0


def search(args: object) -> int:
    """ Search for search_term in filename.

    """

    filename = args.filename
    search_term = args.search_term

    search_str = search_term.lower()

    # String in which to store all matching account information.
    account_str = ''

    with PassFile(filename) as passfile:
        for account_dict in passfile.accounts():
            # The string representation of a dict is good enough for
            # searching in.
            if search_str in str(account_dict):
                account_str += '\n' + dict_to_str(account_dict)

    import pydoc
    pydoc.pager(account_str)

    return 0


def change_password(args: object) -> int:
    """ Change the password that encrypts the master key.

    """

    filename = args.filename

    with PassFile(filename) as passfile:
        # Change the password.
        new_password = get_pass('new password')

        passfile.change_pass(new_password)
    return 0


def remove_account(args: object) -> int:
    """ Remove account from filename.

    """

    filename = args.filename
    account = args.account

    with PassFile(filename) as passfile:
        passfile.remove(account)

    return 0


def add_account(args: object) -> int:
    """ Add an account the file.

    """

    filename = args.filename
    account = args.account

    # Change the password.
    if account == 'PASSWORD':
        return change_password(args)

    # Account names cannot be 'ALL.'
    if account == 'ALL':
        print("Invalid account name: 'ALL'")
        return 0

    with PassFile(filename) as passfile:
        if account in passfile and hasattr(args, 'to'):
            # Trying to add a duplicate account.
            print("Account '%s' exists" % account)
            print("Use 'change' or 'rename' to change it.")
            return 0

        # Put the non-hashed account name in the info dict so it is
        # not lost.
        info_dict = {'Account Name': account}

        account_dict = passfile.get(account)

        if args.set:
            # Add any data to the info dictionary.
            for i in args.data:
                key, value = i.split(args.separator)

                # Don't allow the user to set the account name this way.
                if key.lower() == 'account name': continue

                # Remove empty values from the account dict and continue.
                if not value:
                    account_dict.pop(key, '')
                    continue

                # Get the secret value.
                if value == '{secret}':
                    value = get_pass('{0} {1}'.format(account, key))

                info_dict[key] = value

        account_dict.update(info_dict)
        passfile.set(account, account_dict)

    return 0

# Use the add function to change.
modify_account = add_account


def rehash(args: object) -> int:
    """ List the info in the account or file.

    """

    filename = args.filename

    with PassFile(filename) as passfile:
        accounts_list = list(passfile.accounts())

        # List all accounts.
        for account_dict in accounts_list:
            account = account_dict['Account Name']
            if account in passfile:
                print("Rehashing: ", account)
                passfile.remove(account)
                passfile.set(account_dict['Account Name'], account_dict)

    return 0


def list_info(args: object) -> int:
    """ List the info in the account or file.

    """

    filename = args.filename
    account = args.account

    with PassFile(filename) as passfile:
        account_str = ''

        if account == 'ALL':
            # List all accounts.
            for account_dict in passfile.accounts():
                account_str += '\n' + dict_to_str(account_dict)
        else:
            if account not in passfile:
                print("Account %s not found." % account)
                return 0

            account_str = dict_to_str(passfile.get(account))

        import pydoc
        pydoc.pager(account_str)

    return 0


def rename_account(args: object) -> int:
    """ Rename an account.

    """

    filename = args.filename
    old_account = args.old_account
    new_account = args.new_account

    # Do nothing if the names are the same.
    if old_account == new_account: return 0
    # Account names cannot be 'ALL.'
    if old_account == 'ALL' or new_account == 'ALL':
        print("Invalid account name: 'ALL'")
        return 0

    with PassFile(filename) as passfile:
        if old_account not in passfile:
            print("Account '%s' not found.  Can't rename." % old_account)
            return 0
        if new_account in passfile:
            print("Account '%s' already exists.  Can't rename." % new_account)
            return 0

        account_dict = passfile.get(old_account)
        account_dict['Account Name'] = new_account
        passfile.set(new_account, account_dict)
        passfile.remove(old_account)

    return 0


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser(description="Password manager")
    subparsers = parser.add_subparsers(help="Available actions")

    # Add account options
    add_group = subparsers.add_parser('add', help='Add an account.')
    add_group.add_argument('account', action='store',
                            help='The name of the account to add.')
    add_sub = add_group.add_subparsers(help='Specify the file.', dest='to')
    add_sub.required = True
    add_sub_group = add_sub.add_parser('to',
                                       help='The file where the account \
                                             should be added.')
    add_sub_group.add_argument('filename')
    file_sub = add_sub_group.add_subparsers(help='Set info=data (e.g. set \
                                            username=bif', dest='set')
    file_sub_group = file_sub.add_parser('set', help='Set item info.')
    file_sub_group.add_argument('-s', '--separator', action='store', 
                                default='=',
                                help='Set the info separator (default is "=")')
    file_sub_group.add_argument('data', nargs="+",
                                help='Use {secret} to input secrets e.g. \
                                      (Question={secret})')
    add_group.set_defaults(func=add_account)

    # Change options.
    modify_group = subparsers.add_parser('modify',
                                         help='Change the file password, or \
                                               the info in an account.')
    modify_group.add_argument('account', action='store',
                              help='The name of the account to modify, \
                                    or "PASSWORD" to change the password.')
    modify_sub = modify_group.add_subparsers(help='File to modify.',
                                             dest='in')
    modify_sub.required = True
    modify_sub_group = modify_sub.add_parser('in', help='Specify what file to \
                                                         modify.')
    modify_sub_group.add_argument('filename')
    file_sub = modify_sub_group.add_subparsers(help='Set item info.',
                                               dest='set')
    file_sub_group = file_sub.add_parser('set', help='Set info=data (e.g. set \
                                                     username=bif')
    file_sub_group.add_argument('-s', '--separator', action='store', 
                                default='=',
                                help='Set the info separator (default is "=")')
    file_sub_group.add_argument('data', nargs="+",
                                help='Use {secret} to input secrets e.g. \
                                      (Question={secret})')
    modify_group.set_defaults(func=modify_account)

    # Rename options
    rename_group = subparsers.add_parser('rename',
                                         help='Rename an account.')
    rename_group.add_argument('old_account', action='store',
                              help='The name of the account to rename.')
    rename_sub = rename_group.add_subparsers(help='The file with the account \
                                                   to rename.', dest='in')
    rename_sub.required = True
    rename_sub_group = rename_sub.add_parser('in', help='Specify the file.')
    rename_sub_group.add_argument('filename')
    file_sub = rename_sub_group.add_subparsers(help='The new account name.',
                                               dest='to')
    file_sub_group = file_sub.add_parser('to', help='New account name.')
    file_sub_group.add_argument('new_account',
                                help='The new name for the account.')
    rename_group.set_defaults(func=rename_account)

    # Remove options
    remove_group = subparsers.add_parser('remove', help='Remove an account.')
    remove_group.add_argument('account', action='store',
                              help='The account to remove.')
    remove_sub = remove_group.add_subparsers(dest='from',
                                             help='The file from which the \
                                                   account should be removed.')
    remove_sub.required = True
    remove_sub_group = remove_sub.add_parser('from', help="filename")
    remove_sub_group.add_argument('filename')
    remove_group.set_defaults(func=remove_account)

    convert_group = subparsers.add_parser('convert', help='Convert from old \
                                           SHA256 format the new format.')
    convert_group.add_argument('filename')
    convert_group.set_defaults(func=convert)

    rehash_group = subparsers.add_parser('rehash', help='Convert from old \
                                         SHA256 format the new format.')
    rehash_group.add_argument('filename')
    rehash_group.set_defaults(func=rehash)


    # List options
    list_group = subparsers.add_parser('list', help='List all info for an \
                                                     account')
    list_group.add_argument('account', action='store', help='What account to \
                                                             list the info \
                                                             of.  Use "ALL" \
                                                             to list all the \
                                                             info in the \
                                                             file.')
    list_sub = list_group.add_subparsers(help='Specify the file.', dest='in')
    list_sub.required = True
    list_sub_group = list_sub.add_parser('in', help="filename")
    list_sub_group.add_argument('filename')
    list_group.set_defaults(func=list_info)

    # Find options
    find_group = subparsers.add_parser('find',
                                       help='Search in the file for a string.')
    find_group.add_argument('search_term', action='store',
                            help='What to search for.')
    find_sub = find_group.add_subparsers(help='Specify the file.',
                                         dest='in')
    find_sub.required = True
    find_sub_group = find_sub.add_parser('in', help="filename")
    find_sub_group.add_argument('filename')
    find_group.set_defaults(func=search)

    args, leftovers = parser.parse_known_args()
    try:
        func = args.func
    except AttributeError:
        parser.parse_args(['--help'])

    try:
        func(args)
    except Exception as err:
        print('Error: "{err}" with file {filename}.'.format(**args.__dict__, err=err))
