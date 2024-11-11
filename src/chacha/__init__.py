"""
This package provides tools for encrypting and decrypting files with
the ChaCha stream cipher using a key based on a pass phrase.

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
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from hashlib import sha256
__version__ = '1.0.0a2'
zero = b'\x00\x00\x00\x00\x00\x00\x00\x00'

class ChaChaContext:
    """Encrypts or decrypts strings or files using ChaCha20.

    The key is the sha256 hash of a provided passphrase.  Each
    encryption uses a new randomly generated nonce, which is saved at
    the end of the cyphertext.  When encrypting a file, a 32 byte check
    value is stored at the beginning of the file.  This allows checking
    that the passphrase provided for decryption matches the one used for
    encryption (without exposing the key).  The check value is
    constructed by applying the sha256 hash to the key. The ChaCha
    counter is set to 0 for both encryption and decryption.
    """
    
    def __init__(self, passphrase:bytes=b''):
        if not passphrase:
            raise ValueError('You must provide a pass phrase.')
        self.key_bytes = sha256(passphrase).digest()

    def encrypt_bytes(self, plaintext: bytes) -> bytes:
        """Return the ciphertext with the random nonce appended."""
        nonce = os.urandom(8)
        algorithm = ChaCha20(self.key_bytes, zero + nonce)
        encryptor = Cipher(algorithm, mode=None).encryptor()
        encrypted = encryptor.update(plaintext) + encryptor.finalize()
        return encrypted + nonce
    
    def decrypt_bytes(self, ciphertext: bytes) -> bytes:
        """Return the plaintext, decrypted with the appended nonce.""" 
        nonce = ciphertext[-8:]
        algorithm = ChaCha20(self.key_bytes, zero + nonce)
        decryptor = Cipher(algorithm, mode=None).decryptor()
        decrypted = decryptor.update(ciphertext[:-8]) + decryptor.finalize()
        return decrypted

    def encrypt_file_from_bytes(self, plaintext: bytes, filename: str,
            check: bytes) -> None:
        """Encrypt and write, prepending the 32 byte check."""
        encrypted = self.encrypt_bytes(plaintext)
        with open(filename, 'wb') as outfile:
            outfile.write(check)
            outfile.write(encrypted)

    def decrypt_file_to_bytes(self, filename: str, check: bytes) -> bytes:
        """Validate the 32 byte header and return the decrypted tail."""
        with open(filename, 'rb') as infile:
            saved_check = infile.read(32)
            tail = infile.read()
        if check != saved_check:
            raise ValueError('Invalid check block.')
        return self.decrypt_bytes(tail)

    def encrypt_file(self, filename: str, check: bytes) -> None:
        "Read an unencrypted file and write its encryption."
        with open(filename, 'rb') as infile:
            plaintext = infile.read()
        self.encrypt_file_from_bytes(plaintext, filename + '.cha', check)

    def decrypt_file(self, filename: str, check: bytes) -> None:
        """Read an encrypted file and write its decryption."""
        decrypted = self.decrypt_file_to_bytes(filename, check)
        basename, _ = os.path.splitext(filename)
        with open(basename, 'wb') as outfile:
            outfile.write(decrypted)

def check_for_cha(filename):
    basename, ext = os.path.splitext(filename)
    if ext != '.cha':
        raise ValueError ('The filename extension must be .cha.')
    return basename

def check_file(filename):
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
    blanks = ' '*(len(passphrase) + len(prompt))
    print('\033[1A' + blanks + '\033[1A')
    return passphrase.encode('utf-8')

def encrypt_file():
    """Entry point for encrypting a file.  Writes a .cha file."""
    filename = sys.argv[1]
    if not check_file(filename + '.cha'):
        sys.exit(1)
    passphrase = get_passphrase()
    check = sha256(sha256(passphrase).digest()).digest()
    context = ChaChaContext(passphrase)
    context.encrypt_file(filename, check)

def decrypt_file():
    """Entry point for decrypting a .cha file."""
    filename = sys.argv[1]
    try:
        basename = check_for_cha(filename)
    except ValueError:
        print('The filename extension must be .cha.')
        sys.exit(1)
    if not check_file(basename):
        sys.exit(1)
    passphrase = get_passphrase()
    check = sha256(sha256(passphrase).digest()).digest()
    context = ChaChaContext(passphrase)
    try:
        context.decrypt_file(filename, check)
    except ValueError:
        print('That pass phrase is not the one used to encrypt the file.')
