# This file is part of the chafe Python package which is distributed
# under the MIT license.  See the file LICENSE for details.
# Copyright © 2024 by Marc Culler and others️

"""
This package provides tools for encrypting and decrypting files with
the ChaCha20 stream cipher using a key based on a pass phrase.

It provides two entry points named encrypt and decrypt.  That means
that if this module is in your python path then the module can be
used as follows:

To encrypt a file named myfile:

 % python3 -m chacha.encrypt myfile

You will be prompted for a password, and an encrypted file named
myfile.cha will be created.  The password will be visible until the
encryption is finished, then erased.  (So write it down first!)

To decrypt myfile.cha:

  % python3 -m chacha.decrypt myfile.cha

You will be prompted for the password, and a decrypted file named myfile.
will be created.  The password will be visible until the decryption is
finished, then erased.

If you install this module with pip then the commands will simply be:

  % chacha-encrypt myfile

and

  % chacha-decrypt myfile.cha
"""

import os
import sys
from hashlib import sha256
from ._chacha import encrypt as chacha_encrypt

__version__ = '1.0.0a5'

class ChaChaContext:
    """Encrypts or decrypts strings or files using ChaCha20.

    The key is the sha256 hash of a provided passphrase.  Each
    encryption uses a new randomly generated nonce, which is saved at
    the start of the cyphertext.  When encrypting a file, a 32 byte
    check value is stored at the beginning of the file, before the
    nonce.  The check value is constructed by applying the sha256 hash
    to the pass phrase twice.  This allows checking that the passphrase
    provided for decryption matches the one used for encryption (without
    exposing the key).

    Currently the encrypted files are not authenticated - this is a
    work in progress.

    This class is not suitable for very large files, because it reads
    the entire file into memory before encrypting or decrypting it.
    """
    
    def __init__(self, passphrase:bytes=b''):
        if not passphrase:
            raise ValueError('You must provide a pass phrase.')
        self.key_bytes = sha256(passphrase).digest()
        self.check_bytes = sha256(self.key_bytes).digest()

    def encrypt_bytes(self, plaintext: bytes) -> bytes:
        """Return the ciphertext with the nonce prepended."""
        nonce = os.urandom(12)
        #encryptor = ChaCha20Poly1305(self.key_bytes)
        #ciphertext = encryptor.encrypt(nonce, plaintext, self.check_bytes)
        ciphertext = chacha_encrypt(self.key_bytes, nonce, plaintext)
        return nonce + ciphertext
    
    def decrypt_bytes(self, ciphertext: bytes) -> bytes:
        """Return the plaintext, decrypted with the prepended nonce.""" 
        nonce = ciphertext[:12]
        #decryptor = ChaCha20Poly1305(self.key_bytes)
        #return decryptor.decrypt(nonce, ciphertext[12:], self.check_bytes)
        return chacha_encrypt(self.key_bytes, nonce, ciphertext[12:])

    def encrypt_file_from_bytes(self, plaintext: bytes, filename: str) ->None:
        """Encrypt and write, prepending the 32 byte check."""
        encrypted = self.encrypt_bytes(plaintext)
        with open(filename, 'wb') as outfile:
            outfile.write(self.check_bytes)
            outfile.write(encrypted)

    def decrypt_file_to_bytes(self, filename: str) -> bytes:
        """Validate the 32 byte check value and return the decrypted tail."""
        with open(filename, 'rb') as infile:
            saved_check = infile.read(32)
            tail = infile.read()
        if self.check_bytes != saved_check:
            raise ValueError('Invalid check value.')
        return self.decrypt_bytes(tail)

    def encrypt_file(self, filename: str) -> None:
        "Read an unencrypted file and write its encryption."
        with open(filename, 'rb') as infile:
            plaintext = infile.read()
        self.encrypt_file_from_bytes(plaintext, filename + '.cha')

    def decrypt_file(self, filename: str) -> None:
        """Read an encrypted file and write its decryption."""
        decrypted = self.decrypt_file_to_bytes(filename)
        basename, _ = os.path.splitext(filename)
        with open(basename, 'wb') as outfile:
            outfile.write(decrypted)

def check_for_dot_cha(filename):
    basename, ext = os.path.splitext(filename)
    if ext != '.cha':
        raise ValueError ('The filename extension must be .cha.')
    return basename

def can_destroy(filename):
    if os.path.exists(filename):
        print('The current file %s will be destroyed.' % filename)
        answer = input('Type yes to continue, no to cancel: ')
        if answer != 'yes':
            print('Canceled.')
            return False
    return True

def get_passphrase() ->str:
    prompt = 'pass phrase: '
    passphrase = input(prompt)
    print('\033[1F\033[0K', end='')
    return passphrase.encode('utf-8')

def encrypt_file():
    """Entry point for encrypting a file.  Writes a .cha file."""
    filename = sys.argv[1]
    if not can_destroy(filename + '.cha'):
        sys.exit(1)
    passphrase = get_passphrase()
    context = ChaChaContext(passphrase)
    context.encrypt_file(filename)

def decrypt_file():
    """Entry point for decrypting a .cha file."""
    filename = sys.argv[1]
    try:
        basename = check_for_dot_cha(filename)
    except ValueError:
        print('The filename extension must be .cha.')
        sys.exit(1)
    if not can_destroy(basename):
        sys.exit(1)
    passphrase = get_passphrase()
    context = ChaChaContext(passphrase)
    try:
        context.decrypt_file(filename)
    except ValueError:
        print('That pass phrase is not the one used to encrypt the file.')
