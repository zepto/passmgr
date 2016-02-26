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


""" Account manager.  Stores account information in a lzma compressed file.
The account info is put in json format and each accoun name is hashed, and the
data is encrypted using AES-256-CBC encryption.

"""


from os.path import isfile as os_isfile
from lzma import compress as lzma_compress
from lzma import decompress as lzma_decompress
from json import loads as json_loads
from json import dumps as json_dumps
import codecs
import getpass
from os import environ as os_environ

from Crypto.Cipher import AES
from Crypto.Hash import SHA512, SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto import Random
from Crypto.Hash import HMAC


# Disable writing lesshst file so when searching in the less pager the
# search terms won't be recorded.
os_environ['LESSHISTFILE'] = '/dev/null'

# Use less as the pager.
os_environ['PAGER'] = '$(which less)'

# Set the salt length
SALT_LEN = AES.key_size[-1]


def key_gen(key: bytes, salt: bytes, dkLen: int = AES.key_size[-1],
            iterations: int = 5000) -> bytes:
    """ Return a PBKDF2 key generated form the key and salt using HMAC-SHA512.

    """

    # Use SHA512 as the hash method in hmac.
    prf = lambda p, s: HMAC.new(p, s, SHA512).digest()
    return PBKDF2(key, salt, dkLen=dkLen, count=iterations, prf=prf)


def PKCS7_pad(data: bytes, multiple: int) -> bytes:
    """ Pad the data using the PKCS#7 method.

    """

    # Pads byte pad_len to the end of the plaintext to make it a
    # multiple of the multiple.
    pad_len = multiple - (len(data) % multiple)

    return data + bytes([pad_len]) * pad_len


def simple_encrypt(data: bytes, aes_key: bytes) -> bytes:
    """ Returns the AES_CBC encryption of data using key.

    """

    block_size = AES.block_size

    iv = Random.new().read(block_size)
    encrypt_obj = AES.new(aes_key, AES.MODE_CBC, iv)

    # Put the salt and iv at the start of the ciphertext so when it
    # needs to be decrypted the same salt and iv can be used.
    return iv + encrypt_obj.encrypt(data)


def verify(ciphertext: bytes, aes_key: bytes) -> bytes:
    """ Raises an error if the ciphertext isn't valid.

    """

    block_size = AES.block_size

    encrypted_hmac_key, hmac_digest, ciphertext = get_hmac_data(ciphertext)

    # Decrypt hmac key.
    hmac_iv = encrypted_hmac_key[:block_size]
    hmac_decrypt_obj = AES.new(aes_key, AES.MODE_CBC, hmac_iv)
    hmac_key = hmac_decrypt_obj.decrypt(encrypted_hmac_key[block_size:])

    # Re-generate the hmac digest of ciphertext.
    hmac = HMAC.new(hmac_key, digestmod=SHA512)
    hmac.update(ciphertext)

    # Test the generated digest against the stored digest and fail if they
    # are different.
    assert(hmac_digest == hmac.digest())

    # Only return the ciphertext to be decrypted if the digests match.
    return ciphertext


def hmac(ciphertext: bytes, aes_key: bytes) -> tuple:
    """ Generates an hmac digest of ciphertext and encryptes the key using
    aes_key.  The encrypted key and digest are returned as a tuple.

    """

    # Generate the largest key we can use.
    hmac_key = Random.new().read(AES.key_size[-1])

    # Create the hmac digest.
    hmac = HMAC.new(hmac_key, digestmod=SHA512)
    hmac.update(ciphertext)
    hmac_digest = hmac.digest()

    # Encrypt the hmac key
    return simple_encrypt(hmac_key, aes_key), hmac_digest


def get_hmac_data(ciphertext: bytes) -> tuple:
    """ Gets the hmac_digest and encrypted hmac key out of the ciphertext and
    returns all three.

    """

    block_size = AES.block_size

    hmac_digest = ciphertext[-SHA512.digest_size:]
    ciphertext = ciphertext[:-SHA512.digest_size]

    encrypted_hmac_key = ciphertext[-(block_size + AES.key_size[-1]):]
    ciphertext = ciphertext[:-(block_size + AES.key_size[-1])]

    return (encrypted_hmac_key, hmac_digest, ciphertext)


def encrypt_hmac_key(aes_key: bytes, plaintext: str) -> bytes:
    """ encrypt(key, plaintext) ->  Encrypts plaintext using key.

    """

    # Pad the plaintext.
    padded_plaintext = PKCS7_pad(plaintext.encode(), AES.block_size)

    # Encrypt it.
    ciphertext = simple_encrypt(padded_plaintext, aes_key)

    # Generate an hmac of the ciphertext, and put the encrypted key and
    # digest at the end of the ciphertext.
    encrypted_hmac_key, hmac_digest = hmac(ciphertext, aes_key)

    return ciphertext + encrypted_hmac_key + hmac_digest


def decrypt_hmac_key(aes_key: bytes, ciphertext: bytes) -> str:
    """ decrypt(key, ciphertext) -> Decrypts the ciphertext using the key.

    """

    block_size = AES.block_size

    ciphertext = verify(ciphertext, aes_key)

    iv = ciphertext[:block_size]
    real_ciphertext = ciphertext[block_size:]

    decrypt_obj = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_plaintext = decrypt_obj.decrypt(real_ciphertext)

    try:
        # Remove the padding from the plaintext.
        plaintext = padded_plaintext[:-padded_plaintext[-1]].decode()
    except UnicodeDecodeError:
        print("There was an error.  Maybe the wrong password was given.")
        return ''

    return plaintext


def get_data_hmac(ciphertext: bytes) -> tuple:
    """ Breaks the ciphertext up into its components and returns a tuple of the
    result.

    """

    block_size = AES.block_size

    encrypted_hmac_key = ciphertext[:block_size + 32]
    ciphertext = ciphertext[block_size + 32:]

    hmac_digest = ciphertext[:SHA512.digest_size]
    ciphertext = ciphertext[SHA512.digest_size:]

    salt = ciphertext[:SALT_LEN]
    ciphertext = ciphertext[SALT_LEN:]

    iv = ciphertext[:block_size]
    ciphertext = ciphertext[block_size:]

    return (encrypted_hmac_key, hmac_digest, salt, iv, ciphertext)


def encrypt_hmac(key: bytes, plaintext: str) -> bytes:
    """ encrypt(key, plaintext) ->  Encrypts plaintext using key.

    """

    block_size = AES.block_size

    # Generate a key from a salt and hashed key.
    salt = Random.new().read(SALT_LEN)
    valid_key = key_gen(key, salt)

    iv = Random.new().read(block_size)

    # Pads '\x00' (null) bytes to the end of the plaintext to make it a
    # multiple of the block_size.
    pad_len = block_size - (len(plaintext) % block_size)
    padded_plaintext = plaintext.encode() + bytes([pad_len]) * pad_len

    encrypt_obj = AES.new(valid_key, AES.MODE_CBC, iv)

    # Put the salt and iv at the start of the ciphertext so when it
    # needs to be decrypted the same salt and iv can be used.
    ciphertext = salt + iv + encrypt_obj.encrypt(padded_plaintext)

    hmac_key = Random.new().read(32)
    hmac = HMAC.new(hmac_key, digestmod=SHA512)
    hmac.update(ciphertext)
    hmac_digest = hmac.digest()

    # Encrypt the hmac key
    hmac_iv = Random.new().read(block_size)
    hmac_encrypt_obj = AES.new(valid_key, AES.MODE_CBC, hmac_iv)
    encrypted_hmac_key = hmac_iv + hmac_encrypt_obj.encrypt(hmac_key)

    # ciphertext = encrypted hmac key + hmac digest + salt + iv +
    # encrypted data.
    ciphertext = encrypted_hmac_key + hmac_digest + ciphertext

    return ciphertext


def decrypt_hmac(key: bytes, ciphertext: bytes) -> str:
    """ decrypt(key, ciphertext) -> Decrypts the ciphertext using the key.

    """

    block_size = AES.block_size

    encrypted_hmac_key, hmac_digest, salt, iv, real_ciphertext = get_data_hmac(ciphertext)

    # Re-generate the key from the salt.
    valid_key = key_gen(key, salt)

    hmac_iv = encrypted_hmac_key[:block_size]
    hmac_decrypt_obj = AES.new(valid_key, AES.MODE_CBC, hmac_iv)
    hmac_key = hmac_decrypt_obj.decrypt(encrypted_hmac_key[block_size:])
    assert(verify_mac(hmac_key, hmac_digest, salt + iv + real_ciphertext))

    decrypt_obj = AES.new(valid_key, AES.MODE_CBC, iv)
    padded_plaintext = decrypt_obj.decrypt(real_ciphertext)

    try:
        # Remove the padding from the plaintext.
        plaintext = padded_plaintext[:-padded_plaintext[-1]].decode()
    except UnicodeDecodeError:
        print("There was an error.  Maybe the wrong password was given.")
        return ''

    return plaintext


def encrypt_pbkdf2(key: bytes, plaintext: str) -> bytes:
    """ encrypt(key, plaintext) ->  Encrypts plaintext using key.

    """

    block_size = AES.block_size

    # Generate a key from a salt and hashed key.
    salt = Random.new().read(SALT_LEN)
    valid_key = key_gen(key, salt)

    iv = Random.new().read(AES.block_size)

    # Pads '\x00' (null) bytes to the end of the plaintext to make it a
    # multiple of the block_size.
    pad_len = block_size - (len(plaintext) % block_size)
    padded_plaintext = plaintext.encode() + bytes([pad_len]) * pad_len

    encrypt_obj = AES.new(valid_key, AES.MODE_CBC, iv)

    # Put the salt and iv at the start of the ciphertext so when it
    # needs to be decrypted the same salt and iv can be used.
    ciphertext = salt + iv + encrypt_obj.encrypt(padded_plaintext)

    return ciphertext


def decrypt_pbkdf2(key: bytes, ciphertext: bytes) -> str:
    """ decrypt(key, ciphertext) -> Decrypts the ciphertext using the key.

    """

    block_size = AES.block_size

    # The salt is the first SALT_LEN bytes at the start of the
    # ciphertext.
    salt = ciphertext[:SALT_LEN]

    # Re-generate the key from the salt.
    valid_key = key_gen(key, salt)

    # The iv is the first block_size of data, after the salt, at the start
    # of the cyptertext.
    iv = ciphertext[SALT_LEN:SALT_LEN + block_size]
    real_ciphertext = ciphertext[SALT_LEN + block_size:]

    decrypt_obj = AES.new(valid_key, AES.MODE_CBC, iv)
    padded_plaintext = decrypt_obj.decrypt(real_ciphertext)

    try:
        # Remove the padding from the plaintext.
        plaintext = padded_plaintext[:-padded_plaintext[-1]].decode()
    except UnicodeDecodeError:
        print("There was an error.  Maybe the wrong password was given.")
        return ''

    return plaintext


def encrypt_sha256(key: bytes, plaintext: str) -> bytes:
    """ encrypt(key, plaintext) ->  Encrypts plaintext using key.

    """

    block_size = AES.block_size

    valid_key = SHA256.new(key.encode()).digest()
    iv = Random.new().read(AES.block_size)

    # Pads '\x00' (null) bytes to the end of the plaintext to make it a
    # multiple of the block_size.
    pad_len = block_size - (len(plaintext) % block_size)
    padded_plaintext = plaintext.encode() + bytes([pad_len]) * pad_len

    encrypt_obj = AES.new(valid_key, AES.MODE_CBC, iv)

    # Put the iv at the start of the ciphertext so when it needs to be
    # decrypted the same iv can be used.
    ciphertext = iv + encrypt_obj.encrypt(padded_plaintext)

    return ciphertext


def decrypt_sha256(key: bytes, ciphertext: bytes) -> str:
    """ decrypt(key, ciphertext) -> Decrypts the ciphertext using the key.

    """

    block_size = AES.block_size

    valid_key = SHA256.new(key.encode()).digest()

    # iv is the first block_size of data at the start of ciphertext.
    iv = ciphertext[:block_size]
    real_ciphertext = ciphertext[block_size:]

    decrypt_obj = AES.new(valid_key, AES.MODE_CBC, iv)
    padded_plaintext = decrypt_obj.decrypt(real_ciphertext)

    try:
        # Remove the padding from the plaintext.
        plaintext = padded_plaintext[:-padded_plaintext[-1]].decode()
    except UnicodeDecodeError:
        print("There was an error.  Maybe the wrong password was given.")
        return ''

    return plaintext


def list_to_dict(key_val_list: list, key_val_seperator: str = '=') -> dict:
    """ Turns a ['key=val'] list into a dictionary.

    """

    # Return an empty dictionary if key_val_list is empty.
    if not key_val_list: return {}

    # Split the list values at the '=' into a tuple.
    split_list = [i.split(key_val_seperator) for i in key_val_list]

    return dict(split_list)


def bytes_to_str(bytes_obj: bytes) -> str:
    """ Encodes the bytes object using base64, and returns that string value.

    """

    return codecs.encode(bytes_obj, 'base64').decode()


def str_to_bytes(str_obj: str) -> bytes:
    """ Decodes a base64 string into a bytes object.

    """

    return codecs.decode(str_obj.encode(), 'base64')


def write_file(filename: str, accounts_dict: dict):
    """ Compresses and writes the accounts_dict to the file at filename.

    """

    json_data = json_dumps(accounts_dict)

    lzma_data = lzma_compress(json_data.encode())

    with open(filename, 'wb') as pass_file:
        pass_file.write(lzma_data)



def crypt_to_dict_key(crypt_data: str, aes_key: bytes) -> dict:
    """ Decrypts crypt_data and returns the json.loads dictionary.
    If skip_invalid is True then skip decryption of data if the password is
    invalid.

    """

    # Convert the data to a bytes object and decrypt it.
    json_data = decrypt_hmac_key(aes_key, str_to_bytes(crypt_data))

    # Load the decrypted data with json and return the resulting
    # dictionary.
    try:
        return json_loads(json_data)
    except:
        print('Invalid password.')


def dict_to_crypt_key(data_dict: dict, aes_key: bytes) -> str:
    """ Returns the encrypted json dump of data_dict.

    """

    # Dump the data_dict into json data.
    json_data = json_dumps(data_dict)

    ciphertext = encrypt_hmac_key(aes_key, json_data)

    # Return the string encoded encrypted json dump.
    return bytes_to_str(ciphertext)


def crypt_to_dict(crypt_data: str, password: str = '',
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
        json_data = decrypt_sha256(password, str_to_bytes(crypt_data))

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


def dict_to_crypt(data_dict: dict, password: str = '') -> str:
    """ Returns the encrypted json dump of data_dict.

    """


    # Dump the data_dict into json data.
    json_data = json_dumps(data_dict)

    if not password:
        # Get the password to encrypt the data.
        password = get_pass('password for encryption')

    # Return the string encoded encrypted json dump.
    return bytes_to_str(encrypt_hmac(password, json_data))


def dict_to_str(data_dict: dict) -> str:
    """ Returns a formated string of the (key, value) items in the supplied
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


def get_pass(what_str: str) -> str:
    """ Get a secret and by asking twice to make sure it was inputed correctly.

    """

    a1 = 'a'
    a2 = 'b'

    # Loop until both entries match.
    while a1 != a2:
        a1 = getpass.getpass('Enter the %s: ' % what_str)
        a2 = getpass.getpass('Verify the %s: ' % what_str)
        if a1 != a2:
            print('The %s did not match.  Please try again.' % what_str)

    print('Success...\n')
    return a1


def get_aes_key(aes_key_enc: bytes = b'') -> tuple:
    """ Decrypt or create a aes key.

    """

    block_size = AES.block_size

    if not aes_key_enc:
        # Get the password to encrypt the data.
        password = get_pass('Password for encryption')

        # Generate the largest key possible.
        aes_key = Random.new().read(AES.key_size[-1])
        salt = Random.new().read(SALT_LEN)

        key_mat_len = 2 * AES.key_size[-1]
        key_mat = key_gen(password.encode(), salt, dkLen=key_mat_len)
        enc_key = key_mat[:AES.key_size[-1]]
        key_mac = key_mat[AES.key_size[-1]:]

        iv = Random.new().read(block_size)
        encrypt_obj = AES.new(enc_key, AES.MODE_CBC, iv)
        aes_key_enc = salt + iv + encrypt_obj.encrypt(aes_key) + key_mac
    else:
        password = getpass.getpass('Password to use for decryption: ')

        # Get the salt from the start of the encrypted data.
        salt = aes_key_enc[:SALT_LEN]

        # Re-generate the 512-bit key material.
        key_mat_len = 2 * AES.key_size[-1]
        key_mat = key_gen(password.encode(), salt, dkLen=key_mat_len)
        # The encryption key was the first 256-bits of material.
        enc_key = key_mat[:AES.key_size[-1]]
        # The second 256-bits is used to verify the key and password.
        key_mac = key_mat[AES.key_size[-1]:]

        # Get the previously generated key mac.
        key_mac_test = aes_key_enc[-AES.key_size[-1]:]

        if key_mac != key_mac_test:
            raise(Exception("Invalid password or file was tampered with."))
        else:
            print("Valid passwerd and file.")

        iv = aes_key_enc[SALT_LEN:block_size + SALT_LEN]

        encrypt_obj = AES.new(enc_key, AES.MODE_CBC, iv)
        enc_aes_key = aes_key_enc[SALT_LEN + block_size:-AES.key_size[-1]]

        # Decrypt the aes key.
        aes_key = encrypt_obj.decrypt(enc_aes_key)

    return aes_key_enc, aes_key


def main(args: dict) -> int:
    """ Read the password file, decrypt it and print the requested info.

    """

    filename = args.pop('filename')
    account = args.pop('account')
    remove_account = args.pop('remove_account')
    password = args.pop('password')

    if account:
        # Get the sha256 hash of the account name.
        hashed_account = bytes_to_str(SHA256.new(account.encode()).digest())

        # Create the information dictionary from the info list supplied
        # by the user.
        info_dict = list_to_dict(args.pop('info_list'), args['info_seperator'])

        if info_dict:
            # Put the non hashed account name in the info dict so it is
            # not lost.
            info_dict['Account Name'] = account

            # Get the secret information.
            for key, value in info_dict.items():
                if value == '{secret}':
                    secret = get_pass(key)
                    info_dict[key] = secret
    else:
        # No account name was given.
        hashed_account = ''

    # Create the file if it doesn't exist.
    if not os_isfile(filename):
        open_mode = 'w+b'
    else:
        open_mode = 'rb'

    with open(filename, open_mode) as pass_file:
        # Read all the data from the file.
        lzma_data = pass_file.read()

    # Get the json data out of the file data or an empty json dict of
    # the file was empty.
    if lzma_data:
        json_data = lzma_decompress(lzma_data).decode()
    else:
        json_data = '{}'

    # Load the json data into a dictionary.
    accounts_dict = json_loads(json_data)

    aes_key_digest = bytes_to_str(SHA512.new(b'aes_key').digest())
    aes_key_enc = str_to_bytes(accounts_dict.pop(aes_key_digest, ''))
    aes_key_enc, aes_key = get_aes_key(aes_key_enc)

    if not hashed_account:
        if args.get('list_account_info', False):
            # List all accounts if none where given, but list was requested.
            account_str = ''
            for account_data in accounts_dict.values():
                # account_dict = crypt_to_dict(account_data, password)
                account_dict = crypt_to_dict_key(account_data, aes_key)
                if account_dict:
                    account_str += '\n' + dict_to_str(account_dict)
            import pydoc
            pydoc.pager(account_str)
        elif args.get('re-encrypt', False):
            # Try to re-encrypt every account.
            encrypt_pass = get_pass('encryption password')
            tmp_accounts_dict = accounts_dict.copy()
            for account_hash, account_data in accounts_dict.items():
                account_dict = crypt_to_dict(account_data, password=password,
                                             skip_invalid=True)
                # account_dict = crypt_to_dict_key(account_data, aes_key)
                if account_dict:
                    # new_account_data = dict_to_crypt(account_dict, encrypt_pass)
                    new_account_data = dict_to_crypt_key(account_dict, aes_key)
                else:
                    print("Invalid password.  Account will use the old password")
                tmp_accounts_dict[account_hash] = new_account_data
            tmp_accounts_dict[aes_key_digest] = bytes_to_str(aes_key_enc)
            write_file(filename, tmp_accounts_dict)
            return 0
        elif args.get('search', ''):
            search_str = args['search'].lower()

            # String to store all matching account information.
            account_str = ''

            for account_data in accounts_dict.values():
                # Search through every account that can be decrypted with
                # the password, or ask for a password for each account.
                # account_dict = crypt_to_dict(account_data, password=password,
                #                              skip_invalid=True)
                account_dict = crypt_to_dict_key(account_data, aes_key)

                # If the password could decrypt the account, info search
                # throuth every key and value in the account.
                if account_dict:
                    for key, value in account_dict.items():
                        if search_str in key.lower() or search_str in value.lower():
                            account_str += '\n' + dict_to_str(account_dict)
                            # Don't add the same account more than once.
                            break
            import pydoc
            pydoc.pager(account_str)
    else:
        # Pop the requested account out of the dictionary, so it can be
        # modified, removed, or just printed to stdout.
        account_data = accounts_dict.pop(hashed_account, '')

        # Don't do anything with the account_data if it is to be
        # removed.
        if remove_account:
            accounts_dict[aes_key_digest] = bytes_to_str(aes_key_enc)
            write_file(filename, accounts_dict)
            return 0

        # If there was account data, then put the decrypted dictionary in
        # account_dict.  Otherwise put an empty dictionary.
        if account_data:
            # account_dict = crypt_to_dict(account_data, skip_invalid=False)
            account_dict = crypt_to_dict_key(account_data, aes_key)
        else:
            account_dict = {}

        # Update the account info if new data was supplied.
        if info_dict:
            account_dict.update(info_dict)

            # Remove items from account_dict for which info_dict has an
            # empty value.  (i.e. to remove items from an accounts info
            # the user needs to supply and empty value after the
            # sperator.
            for key, value in info_dict.items():
                if not value.strip():
                    account_dict.pop(key)

            # Encrypt the account_dict.
            # account_data = dict_to_crypt(account_dict)
            account_data = dict_to_crypt_key(account_dict, aes_key)

        # Print the account info.
        if args.get('list_account_info', False) and account_dict:
            import pydoc
            pydoc.pager(dict_to_str(account_dict))

        # Put the accounts data back into the dictionary.
        accounts_dict[hashed_account] = account_data
        accounts_dict[aes_key_digest] = bytes_to_str(aes_key_enc)

        # Write accounts_dict to the password file.
        write_file(filename, accounts_dict)

    return 0


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser(description="Password manager")
    parser.add_argument('-i', '--info', dest='info_list', action='append',
                        help='Set account info.  Use {secret} to input \
                        secrets e.g. (Question={secret})')
    parser.add_argument('-s', '--seperator', dest='info_seperator',
                        action='store', default='=',
                        help='Set the info seperator (default is "=")')
    parser.add_argument('-r', '--remove', dest='remove_account',
                        action='store_true', default=False,
                        help='Remove account')
    parser.add_argument('-f', '--filename', dest='filename', action='store',
                        required=True, help='Account details file.')
    parser.add_argument('-l', '--list', dest='list_account_info',
                        action='store_true',
                        help='Print out the account information.')
    parser.add_argument('-o', '--onepassword', dest='one_password',
                        action='store_true',
                        help='Use the same password for all account \
                        decryption.')
    parser.add_argument('-a', '--account', dest='account', action='store',
                        help='The account to operate on')
    parser.add_argument('-e', '--encrypt', dest='re-encrypt',
                        action='store_true', default=False,
                        help='Re-encrypt all entries.  Use with -o to use the \
                        same password for all accounts.')
    parser.add_argument('-x', '--search', dest='search', action='store',
                        help='Search through all entries. (use with -o to use \
                        one password)')
    args = parser.parse_args()

    if args.one_password:
        password = getpass.getpass('Password to use for decryption: ')
        args.password = password
    else:
        args.password = ''

    main(args.__dict__)
