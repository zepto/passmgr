from ctypes import *
from ctypes.util import find_library
from gpg_error import *

gcrypt_name = find_library('gcrypt')
if not gcrypt_name:
    raise Exception("gcrypt could not be found")

_gcrypt_lib = cdll.LoadLibrary(gcrypt_name)

gcry_error_t = c_uint
gcry_err_code_t = c_uint
gcry_err_source_t = c_uint

# /* A generic context object as used by some functions.  */
# struct gcry_context;
class gcry_context(Structure): pass
# typedef struct gcry_context *gcry_ctx_t;
gcry_ctx_t = POINTER(gcry_context)

# /* The data objects used to hold multi precision integers.  */
# struct gcry_mpi;
class gcry_mpi(Structure): pass
# typedef struct gcry_mpi *gcry_mpi_t;
gcry_mpi_t = POINTER(gcry_mpi)
# struct gcry_mpi_point;
class gcry_mpi_point(Structure): pass
# typedef struct gcry_mpi_point *gcry_mpi_point_t;
gcry_mpi_point_t = POINTER(gcry_mpi_point)

#ifndef GCRYPT_NO_DEPRECATED
# typedef struct gcry_mpi *GCRY_MPI _GCRY_GCC_ATTR_DEPRECATED;
# typedef struct gcry_mpi *GcryMPI _GCRY_GCC_ATTR_DEPRECATED;
#endif

# /* A structure used for scatter gather hashing.  */
class gcry_buffer_t(Structure):
    _fields_ = [
            # size_t size;  /* The allocated size of the buffer or 0.  */
            ('size', c_size_t),
            # size_t off;   /* Offset into the buffer.  */
            ('off', c_size_t),
            # size_t len;   /* The used length of the buffer.  */
            ('len', c_size_t),
            # void *data;   /* The buffer.  */
            ('data', c_void_p),
            ]




# /* Check that the library fulfills the version requirement.  */
# const char *gcry_check_version (const char *req_version);
gcry_check_version = _gcrypt_lib.gcry_check_version
gcry_check_version.argtypes = [c_char_p]
gcry_check_version.restype = c_char_p

# /* Codes for function dispatchers.  */

# /* Codes used with the gcry_control function. */
# enum gcry_ctl_cmds
gcry_ctl_cmds = c_uint
# /* Note: 1 .. 2 are not anymore used. */
GCRYCTL_CFB_SYNC = 3
GCRYCTL_RESET    = 4
GCRYCTL_FINALIZE = 5
GCRYCTL_GET_KEYLEN = 6
GCRYCTL_GET_BLKLEN = 7
GCRYCTL_TEST_ALGO = 8
GCRYCTL_IS_SECURE = 9
GCRYCTL_GET_ASNOID = 10
GCRYCTL_ENABLE_ALGO = 11
GCRYCTL_DISABLE_ALGO = 12
GCRYCTL_DUMP_RANDOM_STATS = 13
GCRYCTL_DUMP_SECMEM_STATS = 14
GCRYCTL_GET_ALGO_NPKEY    = 15
GCRYCTL_GET_ALGO_NSKEY    = 16
GCRYCTL_GET_ALGO_NSIGN    = 17
GCRYCTL_GET_ALGO_NENCR    = 18
GCRYCTL_SET_VERBOSITY     = 19
GCRYCTL_SET_DEBUG_FLAGS   = 20
GCRYCTL_CLEAR_DEBUG_FLAGS = 21
GCRYCTL_USE_SECURE_RNDPOOL= 22
GCRYCTL_DUMP_MEMORY_STATS = 23
GCRYCTL_INIT_SECMEM       = 24
GCRYCTL_TERM_SECMEM       = 25
GCRYCTL_DISABLE_SECMEM_WARN = 27
GCRYCTL_SUSPEND_SECMEM_WARN = 28
GCRYCTL_RESUME_SECMEM_WARN  = 29
GCRYCTL_DROP_PRIVS          = 30
GCRYCTL_ENABLE_M_GUARD      = 31
GCRYCTL_START_DUMP          = 32
GCRYCTL_STOP_DUMP           = 33
GCRYCTL_GET_ALGO_USAGE      = 34
GCRYCTL_IS_ALGO_ENABLED     = 35
GCRYCTL_DISABLE_INTERNAL_LOCKING = 36
GCRYCTL_DISABLE_SECMEM      = 37
GCRYCTL_INITIALIZATION_FINISHED = 38
GCRYCTL_INITIALIZATION_FINISHED_P = 39
GCRYCTL_ANY_INITIALIZATION_P = 40
GCRYCTL_SET_CBC_CTS = 41
GCRYCTL_SET_CBC_MAC = 42
# /* Note: 43 is not anymore used. */
GCRYCTL_ENABLE_QUICK_RANDOM = 44
GCRYCTL_SET_RANDOM_SEED_FILE = 45
GCRYCTL_UPDATE_RANDOM_SEED_FILE = 46
GCRYCTL_SET_THREAD_CBS = 47
GCRYCTL_FAST_POLL = 48
GCRYCTL_SET_RANDOM_DAEMON_SOCKET = 49
GCRYCTL_USE_RANDOM_DAEMON = 50
GCRYCTL_FAKED_RANDOM_P = 51
GCRYCTL_SET_RNDEGD_SOCKET = 52
GCRYCTL_PRINT_CONFIG = 53
GCRYCTL_OPERATIONAL_P = 54
GCRYCTL_FIPS_MODE_P = 55
GCRYCTL_FORCE_FIPS_MODE = 56
GCRYCTL_SELFTEST = 57
# /* Note: 58 .. 62 are used internally.  */
GCRYCTL_DISABLE_HWF = 63
GCRYCTL_SET_ENFORCED_FIPS_FLAG = 64
GCRYCTL_SET_PREFERRED_RNG_TYPE = 65
GCRYCTL_GET_CURRENT_RNG_TYPE = 66
GCRYCTL_DISABLE_LOCKED_SECMEM = 67
GCRYCTL_DISABLE_PRIV_DROP = 68
GCRYCTL_SET_CCM_LENGTHS = 69
GCRYCTL_CLOSE_RANDOM_DEVICE = 70
GCRYCTL_INACTIVATE_FIPS_FLAG = 71
GCRYCTL_REACTIVATE_FIPS_FLAG = 72


# /* Perform various operations defined by CMD. */
# gcry_error_t gcry_control (enum gcry_ctl_cmds CMD, ...);
gcry_control = _gcrypt_lib.gcry_control
# gcry_control.argtypes = [gcry_ctl_cmds, *args]
gcry_control.restype = c_uint

# /************************************
#  *                                  *
#  *   Symmetric Cipher Functions     *
#  *                                  *
#  ************************************/

# /* The data object used to hold a handle to an encryption object.  */
# struct gcry_cipher_handle;
class gcry_cipher_handle(Structure): pass
# typedef struct gcry_cipher_handle *gcry_cipher_hd_t;
gcry_cipher_hd_t = POINTER(gcry_cipher_handle)

#ifndef GCRYPT_NO_DEPRECATED
# typedef struct gcry_cipher_handle *GCRY_CIPHER_HD _GCRY_GCC_ATTR_DEPRECATED;
# typedef struct gcry_cipher_handle *GcryCipherHd _GCRY_GCC_ATTR_DEPRECATED;
#endif

# /* All symmetric encryption algorithms are identified by their IDs.
#    More IDs may be registered at runtime. */
# enum gcry_cipher_algos
gcry_cipher_algos = c_uint
GCRY_CIPHER_NONE        = 0
GCRY_CIPHER_IDEA        = 1
GCRY_CIPHER_3DES        = 2
GCRY_CIPHER_CAST5       = 3
GCRY_CIPHER_BLOWFISH    = 4
GCRY_CIPHER_SAFER_SK128 = 5
GCRY_CIPHER_DES_SK      = 6
GCRY_CIPHER_AES         = 7
GCRY_CIPHER_AES192      = 8
GCRY_CIPHER_AES256      = 9
GCRY_CIPHER_TWOFISH     = 10

# # Other cipher numbers are above 300 for OpenPGP reasons. */
GCRY_CIPHER_ARCFOUR     = 301  # Fully compatible with RSA's RC4 (tm). */
GCRY_CIPHER_DES         = 302  # Yes this is single key 56 bit DES. */
GCRY_CIPHER_TWOFISH128  = 303
GCRY_CIPHER_SERPENT128  = 304
GCRY_CIPHER_SERPENT192  = 305
GCRY_CIPHER_SERPENT256  = 306
GCRY_CIPHER_RFC2268_40  = 307  # Ron's Cipher 2 (40 bit). */
GCRY_CIPHER_RFC2268_128 = 308  # Ron's Cipher 2 (128 bit). */
GCRY_CIPHER_SEED        = 309  # 128 bit cipher described in RFC4269. */
GCRY_CIPHER_CAMELLIA128 = 310
GCRY_CIPHER_CAMELLIA192 = 311
GCRY_CIPHER_CAMELLIA256 = 312
GCRY_CIPHER_SALSA20     = 313
GCRY_CIPHER_SALSA20R12  = 314
GCRY_CIPHER_GOST28147   = 315

# /* The Rijndael algorithm is basically AES, so provide some macros. */
GCRY_CIPHER_AES128      = GCRY_CIPHER_AES
GCRY_CIPHER_RIJNDAEL    = GCRY_CIPHER_AES
GCRY_CIPHER_RIJNDAEL128 = GCRY_CIPHER_AES128
GCRY_CIPHER_RIJNDAEL192 = GCRY_CIPHER_AES192
GCRY_CIPHER_RIJNDAEL256 = GCRY_CIPHER_AES256

# /* The supported encryption modes.  Note that not all of them are
#    supported for each algorithm. */
# enum gcry_cipher_modes
gcry_cipher_mods = c_uint
GCRY_CIPHER_MODE_NONE   = 0  # Not yet specified. */
GCRY_CIPHER_MODE_ECB    = 1  # Electronic codebook. */
GCRY_CIPHER_MODE_CFB    = 2  # Cipher feedback. */
GCRY_CIPHER_MODE_CBC    = 3  # Cipher block chaining. */
GCRY_CIPHER_MODE_STREAM = 4  # Used with stream ciphers. */
GCRY_CIPHER_MODE_OFB    = 5  # Outer feedback. */
GCRY_CIPHER_MODE_CTR    = 6  # Counter. */
GCRY_CIPHER_MODE_AESWRAP= 7  # AES-WRAP algorithm.  */
GCRY_CIPHER_MODE_CCM    = 8  # Counter with CBC-MAC.  */
GCRY_CIPHER_MODE_GCM    = 9   # Galois Counter Mode. */

# /* Flags used with the open function. */
# enum gcry_cipher_flags
gcry_cipher_flags = c_uint
GCRY_CIPHER_SECURE      = 1  # Allocate in secure memory. */
GCRY_CIPHER_ENABLE_SYNC = 2  # Enable CFB sync mode. */
GCRY_CIPHER_CBC_CTS     = 4  # Enable CBC cipher text stealing (CTS). */
GCRY_CIPHER_CBC_MAC     = 8   # Enable CBC message auth. code (MAC). */

# /* GCM works only with blocks of 128 bits */
GCRY_GCM_BLOCK_LEN = (128 / 8)

# /* CCM works only with blocks of 128 bits.  */
GCRY_CCM_BLOCK_LEN = (128 / 8)

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

# /* Perform various operations on the cipher object H. */
# gcry_error_t gcry_cipher_ctl (gcry_cipher_hd_t h, int cmd, void *buffer,
#                              size_t buflen);
gcry_cipher_ctl = _gcrypt_lib.gcry_cipher_ctl
gcry_cipher_ctl.argtypes = [gcry_cipher_hd_t, c_int, c_void_p, c_size_t]
gcry_cipher_ctl.restype = gcry_error_t

# /* Retrieve various information about the cipher object H. */
# gcry_error_t gcry_cipher_info (gcry_cipher_hd_t h, int what, void *buffer,
#                               size_t *nbytes);
gcry_cipher_info = _gcrypt_lib.gcry_cipher_info
gcry_cipher_info.argtypes = [gcry_cipher_hd_t, c_int, c_void_p,
                             POINTER(c_size_t)]
gcry_cipher_info.restype = gcry_error_t

# /* Retrieve various information about the cipher algorithm ALGO. */
# gcry_error_t gcry_cipher_algo_info (int algo, int what, void *buffer,
#                                    size_t *nbytes);
gcry_cipher_algo_info = _gcrypt_lib.gcry_cipher_algo_info
gcry_cipher_algo_info.argtypes = [c_int, c_int, c_void_p, POINTER(c_size_t)]
gcry_cipher_algo_info.restype = gcry_error_t

# /* Map the cipher algorithm whose ID is contained in ALGORITHM to a
#    string representation of the algorithm name.  For unknown algorithm
#    IDs this function returns "?".  */
# const char *gcry_cipher_algo_name (int algorithm) _GCRY_GCC_ATTR_PURE;
gcry_cipher_algo_name = _gcrypt_lib.gcry_cipher_algo_name
gcry_cipher_algo_name.argtypes = [c_int]
gcry_cipher_algo_name.restype = c_char_p

# /* Map the algorithm name NAME to an cipher algorithm ID.  Return 0 if
#    the algorithm name is not known. */
# int gcry_cipher_map_name (const char *name) _GCRY_GCC_ATTR_PURE;
gcry_cipher_map_name = _gcrypt_lib.gcry_cipher_map_name
gcry_cipher_map_name.argtypes = [c_char_p]
gcry_cipher_map_name.restype = c_int

# /* Given an ASN.1 object identifier in standard IETF dotted decimal
#    format in STRING, return the encryption mode associated with that
#    OID or 0 if not known or applicable. */
# int gcry_cipher_mode_from_oid (const char *string) _GCRY_GCC_ATTR_PURE;
gcry_cipher_mode_from_oid = _gcrypt_lib.gcry_cipher_mode_from_oid
gcry_cipher_mode_from_oid.argtypes = [c_char_p]
gcry_cipher_mode_from_oid.restype = c_int

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

# /* Provide additional authentication data for AEAD modes/ciphers.  */
# gcry_error_t gcry_cipher_authenticate (gcry_cipher_hd_t hd, const void *abuf,
#                                        size_t abuflen);
gcry_cipher_authenticate = _gcrypt_lib.gcry_cipher_authenticate
gcry_cipher_authenticate.argtypes = [gcry_cipher_hd_t, c_void_p, c_size_t]
gcry_cipher_authenticate.restype = gcry_error_t

# /* Get authentication tag for AEAD modes/ciphers.  */
# gcry_error_t gcry_cipher_gettag (gcry_cipher_hd_t hd, void *outtag,
#                                  size_t taglen);
gcry_cipher_gettag = _gcrypt_lib.gcry_cipher_gettag
gcry_cipher_gettag.argtypes = [gcry_cipher_hd_t, c_void_p, c_size_t]
gcry_cipher_gettag.restype = gcry_error_t

# /* Check authentication tag for AEAD modes/ciphers.  */
# gcry_error_t gcry_cipher_checktag (gcry_cipher_hd_t hd, const void *intag,
#                                    size_t taglen);
gcry_cipher_checktag = _gcrypt_lib.gcry_cipher_checktag
gcry_cipher_checktag.argtypes = [gcry_cipher_hd_t, c_void_p, c_size_t]
gcry_cipher_checktag.restype = gcry_error_t

# /* Reset the handle to the state after open.  */
#define gcry_cipher_reset(h)  gcry_cipher_ctl ((h), GCRYCTL_RESET, NULL, 0)
gcry_cipher_reset = lambda h: gcry_cipher_ctl (h, GCRYCTL_RESET, None, 0)

# /* Perform the OpenPGP sync operation if this is enabled for the
#    cipher handle H. */
#define gcry_cipher_sync(h)  gcry_cipher_ctl( (h), GCRYCTL_CFB_SYNC, NULL, 0)
gcry_cipher_sync = lambda h: gcry_cipher_ctl(h, GCRYCTL_CFB_SYNC, None, 0)

# /* Enable or disable CTS in future calls to gcry_encrypt(). CBC mode only. */
#define gcry_cipher_cts(h,on)  gcry_cipher_ctl( (h), GCRYCTL_SET_CBC_CTS, \
                                                                   # NULL, on )
gcry_cipher_cts = lambda h, on: gcry_cipher_ctl(h, GCRYCTL_SET_CBC_CTS, None,
                                                None, on)

# /* Set counter for CTR mode.  (CTR,CTRLEN) must denote a buffer of
#    block size length, or (NULL,0) to set the CTR to the all-zero block. */
# gpg_error_t gcry_cipher_setctr (gcry_cipher_hd_t hd,
#                                 const void *ctr, size_t ctrlen);
gcry_cipher_setctr = _gcrypt_lib.gcry_cipher_setctr
gcry_cipher_setctr.argtypes = [gcry_cipher_hd_t, c_void_p, c_size_t]
gcry_cipher_setctr.restype = gpg_error_t

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

# /* Return 0 if the algorithm A is available for use. */
#define gcry_cipher_test_algo(a) \
            # gcry_cipher_algo_info( (a), GCRYCTL_TEST_ALGO, NULL, NULL )
gcry_cipher_test_algo = lambda a: gcry_cipher_algo_info(a, GCRYCTL_TEST_ALGO,
                                                        None, None)

# /************************************
#  *                                  *
#  *   Cryptograhic Hash Functions    *
#  *                                  *
#  ************************************/

# /* Algorithm IDs for the hash functions we know about. Not all of them
#    are implemnted. */
# enum gcry_md_algos
gcry_md_algos = c_uint
GCRY_MD_NONE    = 0
GCRY_MD_MD5     = 1
GCRY_MD_SHA1    = 2
GCRY_MD_RMD160  = 3
GCRY_MD_MD2     = 5
GCRY_MD_TIGER   = 6   # TIGER/192 as used by gpg <= 1.3.2. */
GCRY_MD_HAVAL   = 7   # HAVAL 5 pass 160 bit. */
GCRY_MD_SHA256  = 8
GCRY_MD_SHA384  = 9
GCRY_MD_SHA512  = 10
GCRY_MD_SHA224  = 11
GCRY_MD_MD4     = 301
GCRY_MD_CRC32         = 302
GCRY_MD_CRC32_RFC1510 = 303
GCRY_MD_CRC24_RFC2440 = 304
GCRY_MD_WHIRLPOOL     = 305
GCRY_MD_TIGER1        = 306 # TIGER fixed.  */
GCRY_MD_TIGER2        = 307 # TIGER2 variant.   */
GCRY_MD_GOSTR3411_94  = 308 # GOST R 34.11-94.  */
GCRY_MD_STRIBOG256    = 309 # GOST R 34.11-2012 256 bit.  */
GCRY_MD_STRIBOG512    = 310  # GOST R 34.11-2012 512 bit.  */

# /* Flags used with the open function.  */
# enum gcry_md_flags
gcry_md_flags = c_uint
GCRY_MD_FLAG_SECURE = 1  # Allocate all buffers in "secure" memory.  */
GCRY_MD_FLAG_HMAC   = 2  # Make an HMAC out of this algorithm.  */
GCRY_MD_FLAG_BUGEMU1 = 0x0100

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
# } *gcry_md_hd_t;
gcry_md_hd_t = POINTER(gcry_md_handle)

# /* Compatibility types, do not use them.  */
#ifndef GCRYPT_NO_DEPRECATED
# typedef struct gcry_md_handle *GCRY_MD_HD _GCRY_GCC_ATTR_DEPRECATED;
# typedef struct gcry_md_handle *GcryMDHd _GCRY_GCC_ATTR_DEPRECATED;
#endif

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

# /* Add the message digest algorithm ALGO to the digest object HD.  */
# gcry_error_t gcry_md_enable (gcry_md_hd_t hd, int algo);
gcry_md_enable = _gcrypt_lib.gcry_md_enable
gcry_md_enable.argtypes = [gcry_md_hd_t, c_int]
gcry_md_enable.restype = gcry_error_t

# /* Create a new digest object as an exact copy of the object HD.  */
# gcry_error_t gcry_md_copy (gcry_md_hd_t *bhd, gcry_md_hd_t ahd);
gcry_md_copy = _gcrypt_lib.gcry_md_copy
gcry_md_copy.argtypes = [POINTER(gcry_md_hd_t), gcry_md_hd_t]
gcry_md_copy.restype = gcry_error_t

# /* Reset the digest object HD to its initial state.  */
# void gcry_md_reset (gcry_md_hd_t hd);
gcry_md_reset = _gcrypt_lib.gcry_md_reset
gcry_md_reset.argtypes = [gcry_md_hd_t]
gcry_md_reset.restype = None

# /* Perform various operations on the digest object HD. */
# gcry_error_t gcry_md_ctl (gcry_md_hd_t hd, int cmd,
#                           void *buffer, size_t buflen);
gcry_md_ctl = _gcrypt_lib.gcry_md_ctl
gcry_md_ctl.argtypes = [gcry_md_hd_t, c_int, c_void_p, c_size_t]
gcry_md_ctl.restype = gcry_error_t

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

# /* Convenience function to hash multiple buffers.  */
# gpg_error_t gcry_md_hash_buffers (int algo, unsigned int flags, void *digest,
#                                   const gcry_buffer_t *iov, int iovcnt);
gcry_md_hash_buffers = _gcrypt_lib.gcry_md_hash_buffers
gcry_md_hash_buffers.argtypes = [c_int, c_uint, c_void_p,
                                POINTER(gcry_buffer_t), c_int]
gcry_md_hash_buffers.restype = gpg_error_t


# /* Retrieve the algorithm used with HD.  This does not work reliable
#    if more than one algorithm is enabled in HD. */
# int gcry_md_get_algo (gcry_md_hd_t hd);
gcry_md_get_algo = _gcrypt_lib.gcry_md_get_algo
gcry_md_get_algo.argtypes = [gcry_md_hd_t]
gcry_md_get_algo.restype = c_int

# /* Retrieve the length in bytes of the digest yielded by algorithm
#    ALGO. */
# unsigned int gcry_md_get_algo_dlen (int algo);
gcry_md_get_algo_dlen = _gcrypt_lib.gcry_md_get_algo_dlen
gcry_md_get_algo_dlen.argtypes = [c_int]
gcry_md_get_algo_dlen.restype = c_uint

# /* Return true if the the algorithm ALGO is enabled in the digest
#    object A. */
# int gcry_md_is_enabled (gcry_md_hd_t a, int algo);
gcry_md_is_enabled = _gcrypt_lib.gcry_md_is_enabled
gcry_md_is_enabled.argtypes = [gcry_md_hd_t, c_int]
gcry_md_is_enabled.restype = c_int

# /* Return true if the digest object A is allocated in "secure" memory. */
# int gcry_md_is_secure (gcry_md_hd_t a);
gcry_md_is_secure = _gcrypt_lib.gcry_md_is_secure
gcry_md_is_secure.argtypes = [gcry_md_hd_t]
gcry_md_is_secure.restype = c_int

# /* Retrieve various information about the object H.  */
# gcry_error_t gcry_md_info (gcry_md_hd_t h, int what, void *buffer,
#                           size_t *nbytes);
gcry_md_info = _gcrypt_lib.gcry_md_info
gcry_md_info.argtypes = [gcry_md_hd_t, c_int, c_void_p, POINTER(c_size_t)]
gcry_md_info.restype = gcry_error_t

# /* Retrieve various information about the algorithm ALGO.  */
# gcry_error_t gcry_md_algo_info (int algo, int what, void *buffer,
#                                size_t *nbytes);
gcry_md_algo_info = _gcrypt_lib.gcry_md_algo_info
gcry_md_algo_info.argtypes = [c_int, c_int, c_void_p, POINTER(c_size_t)]
gcry_md_algo_info.restype = gcry_error_t

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

# /* Start or stop debugging for digest handle HD; i.e. create a file
#    named dbgmd-<n>.<suffix> while hashing.  If SUFFIX is NULL,
#    debugging stops and the file will be closed. */
# void gcry_md_debug (gcry_md_hd_t hd, const char *suffix);
gcry_md_debug = _gcrypt_lib.gcry_md_debug
gcry_md_debug.argtypes = [gcry_md_hd_t, c_char_p]
gcry_md_debug.restype = None


# /* Update the hash(s) of H with the character C.  This is a buffered
#    version of the gcry_md_write function. */
#define gcry_md_putc(h,c)  \
            # do {                                          \
            #     gcry_md_hd_t h__ = (h);                   \
            #     if( (h__)->bufpos == (h__)->bufsize )     \
            #         gcry_md_write( (h__), NULL, 0 );      \
            #     (h__)->buf[(h__)->bufpos++] = (c) & 0xff; \
            # } while(0)

# /* Finalize the digest calculation.  This is not really needed because
#    gcry_md_read() does this implicitly. */
# #define gcry_md_final(a) \
#             gcry_md_ctl ((a), GCRYCTL_FINALIZE, NULL, 0)
gcry_md_final = lambda a: gcry_md_ctl(a, GCRYCTL_FINALIZE, None, 0)

# /* Return 0 if the algorithm A is available for use. */
#define gcry_md_test_algo(a) \
            # gcry_md_algo_info( (a), GCRYCTL_TEST_ALGO, NULL, NULL )
gcry_md_test_algo = lambda a: gcry_md_algo_info(a, GCRYCTL_TEST_ALGO, None,
                                                None)

# /* Return an DER encoded ASN.1 OID for the algorithm A in buffer B. N
#    must point to size_t variable with the available size of buffer B.
#    After return it will receive the actual size of the returned
#    OID. */
# #define gcry_md_get_asnoid(a,b,n) \
#             gcry_md_algo_info((a), GCRYCTL_GET_ASNOID, (b), (n))
gcry_md_get_asnoid = lambda a, b, n: gcry_md_algo_info(a, GCRYCTL_GET_ASNOID,
                                                       b, n)



# /**********************************************
#  *                                            *
#  *   Message Authentication Code Functions    *
#  *                                            *
#  **********************************************/

# /* The data object used to hold a handle to an encryption object.  */
# struct gcry_mac_handle;
class gcry_mac_handle(Structure): pass
# typedef struct gcry_mac_handle *gcry_mac_hd_t;
gcry_mac_hd_t = POINTER(gcry_mac_handle)

# /* Algorithm IDs for the hash functions we know about. Not all of them
#    are implemented. */
# enum gcry_mac_algos
gcry_mac_algos = c_int
GCRY_MAC_NONE               = 0

GCRY_MAC_HMAC_SHA256        = 101
GCRY_MAC_HMAC_SHA224        = 102
GCRY_MAC_HMAC_SHA512        = 103
GCRY_MAC_HMAC_SHA384        = 104
GCRY_MAC_HMAC_SHA1          = 105
GCRY_MAC_HMAC_MD5           = 106
GCRY_MAC_HMAC_MD4           = 107
GCRY_MAC_HMAC_RMD160        = 108
GCRY_MAC_HMAC_TIGER1        = 109
GCRY_MAC_HMAC_WHIRLPOOL     = 110
GCRY_MAC_HMAC_GOSTR3411_94  = 111
GCRY_MAC_HMAC_STRIBOG256    = 112
GCRY_MAC_HMAC_STRIBOG512    = 113

GCRY_MAC_CMAC_AES           = 201
GCRY_MAC_CMAC_3DES          = 202
GCRY_MAC_CMAC_CAMELLIA      = 203
GCRY_MAC_CMAC_CAST5         = 204
GCRY_MAC_CMAC_BLOWFISH      = 205
GCRY_MAC_CMAC_TWOFISH       = 206
GCRY_MAC_CMAC_SERPENT       = 207
GCRY_MAC_CMAC_SEED          = 208
GCRY_MAC_CMAC_RFC2268       = 209
GCRY_MAC_CMAC_IDEA          = 210
GCRY_MAC_CMAC_GOST28147     = 211

GCRY_MAC_GMAC_AES           = 401
GCRY_MAC_GMAC_CAMELLIA      = 402
GCRY_MAC_GMAC_TWOFISH       = 403
GCRY_MAC_GMAC_SERPENT       = 404
GCRY_MAC_GMAC_SEED          = 405

# /* Flags used with the open function.  */
# enum gcry_mac_flags
gcry_mac_flags = c_int
GCRY_MAC_FLAG_SECURE = 1

# /* Create a MAC handle for algorithm ALGO.  FLAGS may be given as an bitwise OR
#    of the gcry_mac_flags values.  CTX maybe NULL or gcry_ctx_t object to be
#    associated with HANDLE.  */
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

# /* Perform various operations on the MAC object H. */
# gcry_error_t gcry_mac_ctl (gcry_mac_hd_t h, int cmd, void *buffer,
#                            size_t buflen);
gcry_mac_ctl = _gcrypt_lib.gcry_mac_ctl
gcry_mac_ctl.argtypes = [gcry_mac_hd_t, c_int, c_void_p, c_size_t]
gcry_mac_ctl.restype = gcry_error_t

# /* Retrieve various information about the MAC algorithm ALGO. */
# gcry_error_t gcry_mac_algo_info (int algo, int what, void *buffer,
#                                  size_t *nbytes);
gcry_mac_algo_info = _gcrypt_lib.gcry_mac_algo_info
gcry_mac_algo_info.argtypes = [c_int, c_int, c_void_p, POINTER(c_size_t)]
gcry_mac_algo_info.restype = gcry_error_t

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

# /* Map the MAC algorithm whose ID is contained in ALGORITHM to a
#    string representation of the algorithm name.  For unknown algorithm
#    IDs this function returns "?".  */
# const char *gcry_mac_algo_name (int algorithm) _GCRY_GCC_ATTR_PURE;
gcry_mac_algo_name = _gcrypt_lib.gcry_mac_algo_name
gcry_mac_algo_name.argtypes = [c_int]
gcry_mac_algo_name.restype = c_char_p

# /* Map the algorithm name NAME to an MAC algorithm ID.  Return 0 if
#    the algorithm name is not known. */
# int gcry_mac_map_name (const char *name) _GCRY_GCC_ATTR_PURE;
gcry_mac_map_name = _gcrypt_lib.gcry_mac_map_name
gcry_mac_map_name.argtypes = [c_char_p]
gcry_mac_map_name.restype = c_int

# /* Reset the handle to the state after open/setkey.  */
#define gcry_mac_reset(h)  gcry_mac_ctl ((h), GCRYCTL_RESET, NULL, 0)

# /* Return 0 if the algorithm A is available for use. */
#define gcry_mac_test_algo(a) \
            # gcry_mac_algo_info( (a), GCRYCTL_TEST_ALGO, NULL, NULL )

# /******************************
#  *                            *
#  *  Key Derivation Functions  *
#  *                            *
#  ******************************/
#
# /* Algorithm IDs for the KDFs.  */
# enum gcry_kdf_algos
GCRY_KDF_NONE = 0
GCRY_KDF_SIMPLE_S2K = 16
GCRY_KDF_SALTED_S2K = 17
GCRY_KDF_ITERSALTED_S2K = 19
GCRY_KDF_PBKDF1 = 33
GCRY_KDF_PBKDF2 = 34
GCRY_KDF_SCRYPT = 48

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


# /************************************
#  *                                  *
#  *   Random Generating Functions    *
#  *                                  *
#  ************************************/

GCRY_WEAK_RANDOM = 0
GCRY_STRONG_RANDOM = 1
GCRY_VERY_STRONG_RANDOM = 2
gcry_random_level_t = c_int

# Fill BUFFER with LENGTH bytes of random, using random numbers of
# quality LEVEL.
# void gcry_randomize (void *buffer, size_t length,
#                      enum gcry_random_level level);
gcry_randomize = _gcrypt_lib.gcry_randomize
gcry_randomize.argtypes = [c_void_p, c_size_t, c_int]
gcry_randomize.restype = None

#* Add the external random from BUFFER with LENGTH bytes into the
#  pool. QUALITY should either be -1 for unknown or in the range of 0
#  to 100 */
# gcry_error_t gcry_random_add_bytes (const void *buffer, size_t length,
#                                     int quality);

# /* If random numbers are used in an application, this macro should be
#    called from time to time so that new stuff gets added to the
#    internal pool of the RNG.  */
#define gcry_fast_random_poll()  gcry_control (GCRYCTL_FAST_POLL, NULL)


# /* Return NBYTES of allocated random using a random numbers of quality
#    LEVEL. */
# void *gcry_random_bytes (size_t nbytes, enum gcry_random_level level)
#                          _GCRY_GCC_ATTR_MALLOC;
gcry_random_bytes = _gcrypt_lib.gcry_random_bytes
gcry_random_bytes.argtypes = [c_size_t, c_int]
gcry_random_bytes.restype = c_void_p

# /* Return NBYTES of allocated random using a random numbers of quality
#    LEVEL.  The random numbers are created returned in "secure"
#    memory. */
# void *gcry_random_bytes_secure (size_t nbytes, enum gcry_random_level level)
#                                 _GCRY_GCC_ATTR_MALLOC;
gcry_random_bytes_secure = _gcrypt_lib.gcry_random_bytes_secure
gcry_random_bytes_secure.argtypes = [c_size_t, c_int]
gcry_random_bytes_secure.restype = c_void_p


# /* Set the big integer W to a random value of NBITS using a random
#    generator with quality LEVEL.  Note that by using a level of
#    GCRY_WEAK_RANDOM gcry_create_nonce is used internally. */
# void gcry_mpi_randomize (gcry_mpi_t w,
#                          unsigned int nbits, enum gcry_random_level level);


# /* Create an unpredicable nonce of LENGTH bytes in BUFFER. */
# void gcry_create_nonce (void *buffer, size_t length);
gcry_create_nonce = _gcrypt_lib.gcry_create_nonce
gcry_create_nonce.argtypes = [c_void_p, c_size_t]
gcry_create_nonce.restype = None


