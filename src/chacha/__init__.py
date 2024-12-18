# This file is part of the chafe Python package which is distributed
# under the MIT license.  See the file LICENSE for details.
# Copyright © 2024 by Marc Culler and others️

"""This package provides tools for encrypting and decrypting files with
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

To view myfile.cha with less:

  % python3 -m chacha.view myfile.cha

You will be prompted for the password, and the decrypted plaintext
will be piped to less.  The password will be visible until less is
launched, then erased.

If you install this module with pip then the commands will simply be:

  % chacha-encrypt myfile
  % chacha-decrypt myfile.cha
  % chacha-view myfile.cha

"""

import os
import sys
import tempfile
import subprocess
from hashlib import sha256
from ._chacha import chacha_encrypt
from ._chacha import poly1305_tag
__version__ = '1.0.0'
class BadPassphrase(Exception):
    pass

class BadTag(Exception):
    pass
    
class ChaChaContext:
    """Encrypts or decrypts strings or files using ChaCha20 and Pply1305.

    The ChaCha20 key is the sha256 hash of a provided passphrase.  Each
    encryption uses a new randomly generated nonce, which is prepended
    at the start of the byte sequence produced by encrypting a plaintext
    byte sequence.  The nonce is followed by a 16 byte authentication
    tag generated with the Poly1305 algorithm.  The tag is followed by a
    16 bit hash which can be used to check if a user made a typo when
    entering the pass phrase for decryption.

    This class is not suitable for very large files, because it reads
    the entire file into memory before encrypting or decrypting it.
    """
    
    def __init__(self, passphrase:bytes=b''):
        if not passphrase:
            raise ValueError('You must provide a pass phrase.')
        self.passphrase = passphrase
        self.key = sha256(self.passphrase).digest()

    def encrypt_bytes(self, plaintext: bytes) -> bytes:
        """Return the ciphertext with the nonce, tag, and check prepended."""
        nonce = os.urandom(12)
        # Use the nonce as salt to avoid exposing the key.
        check = sha256(nonce + self.passphrase).digest()[:16]
        ciphertext = chacha_encrypt(self.key, nonce, plaintext)
        tag = poly1305_tag(self.key, nonce, plaintext)
        return nonce + tag + check + ciphertext
    
    def decrypt_bytes(self, encryption: bytes) -> bytes:
        """Return the plaintext, decrypted using the prepended nonce."""
        saved_nonce = encryption[:12]
        saved_tag = encryption[12:28]
        saved_check = encryption[28:44]
        ciphertext = encryption[44:]
        check = sha256(saved_nonce + self.passphrase).digest()[:16]
        if saved_check != check:
            raise BadPassphrase
        # ChaCha is symmetric:
        plaintext = chacha_encrypt(self.key, saved_nonce, ciphertext)
        tag = poly1305_tag(self.key, saved_nonce, plaintext)
        if saved_tag != tag:
            raise BadTag
        return plaintext

    def encrypt_file_from_bytes(self, plaintext: bytes, filename: str) ->None:
        """Encrypt plaintext and write to file."""
        encrypted = self.encrypt_bytes(plaintext)
        with open(filename, 'wb') as outfile:
            outfile.write(encrypted)

    def decrypt_file_to_bytes(self, filename: str) -> bytes:
        """Read file and decrypt the contents."""
        with open(filename, 'rb') as infile:
            encryption = infile.read()
        return self.decrypt_bytes(encryption)

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

    def check_passphrase(self, filename: str) -> None:
        """Check that the file was encrypted with our pass phrase."""
        with open(filename, 'rb') as encrypted:
            header = encrypted.read(44)
        saved_nonce = header[:12]
        saved_check = header[28:44]
        check = sha256(saved_nonce + self.passphrase).digest()[:16]
        return (check == saved_check)    

def check_for_dot_cha(filepath):
    basepath, ext = os.path.splitext(filepath)
    if ext != '.cha':
        raise ValueError ('The filename extension must be .cha.')
    return basepath

def can_destroy(filename):
    if os.path.exists(filename):
        print('The current file %s will be destroyed.' % filename)
        answer = input('Type yes to continue, no to cancel: ')
        if answer != 'yes':
            print('Canceled.')
            return False
    return True

def get_passphrase(prompt: str='pass phrase: ') ->str:
    passphrase = input(prompt)
    print('\033[1F\033[0K', end='')
    return passphrase.encode('utf-8')

def encrypt_file() -> None:
    """Entry point for encrypting a file.  Writes a .cha file."""
    try:
        filepath = sys.argv[1]
    except IndexError:
        print('Usage: chacha-encrypt <filename>')
        sys.exit(1)
    target = filepath + '.cha'
    if not can_destroy(target):
        sys.exit(2)
    passphrase = get_passphrase()
    context = ChaChaContext(passphrase)
    if os.path.exists(target) and not context.check_passphrase(target):
        print('%s was not encrypted with that pass phrase! Aborting.' % target)
        sys.exit(2)
    context.encrypt_file(filepath)

def decrypt_file() -> None:
    """Entry point for decrypting a .cha file."""
    try:
        filepath = sys.argv[1]
    except IndexError:
        print('Usage: chacha-decrypt <path_to_file.cha>')
        sys.exit(1)
    try:
        basepath = check_for_dot_cha(filepath)
    except ValueError:
        print('The filename extension must be .cha.')
        sys.exit(1)
    if not can_destroy(basepath):
        sys.exit(2)
    passphrase = get_passphrase()
    context = ChaChaContext(passphrase)
    try:
        context.decrypt_file(filepath)
    except BadPassphrase:
        print('That pass phrase is invalid.')
        sys.exit(3)
    except BadTag:
        print('This file has been tampered with!')
        sys.exit(4)

def view_file() -> None:
    """ Entry point which Decrypts a file and pipes it to less. """
    try:
        filepath = sys.argv[1]
    except IndexError:
        print('Usage: chacha-view <path_to_file.cha>')
        sys.exit(1)
    try:
        check_for_dot_cha(filepath)
    except ValueError:
        print('The filename extension must be .cha.')
        sys.exit(1)
    passphrase = get_passphrase()
    context = ChaChaContext(passphrase)
    try:
        plaintext = context.decrypt_file_to_bytes(filepath)
    except BadPassphrase:
        print('That pass phrase is invalid.')
        sys.exit(3)
    except BadTag:
        print('This file has been tampered with!')
        sys.exit(4)
    with tempfile.TemporaryFile() as temp:
        temp.write(plaintext)
        less = subprocess.Popen(['/usr/bin/less'], stdin=subprocess.PIPE,
                                stdout=sys.stdout, stderr=sys.stderr)
        less.communicate(plaintext)
