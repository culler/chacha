A CHAcha File Encryptor
=======================

This Python package provides tools for encrypting and decrypting files with
Daniel Bernstein's ChaCha20 stream cipher, using a key derived from a pass
phrase. Encrypted files include a Poly1305 authentication tag to detect
tampering with an encrypted file.

Warning
-------

This is still a work in progress, published here for testing only.  Do not use
it for anything important.  The file formats and encryption algorithms are
subject to change, which could leave you with encrypted files that you cannot
decrypt.

Installation
------------

Install this package with pip:

``python3 -m pip install --pre chafe``

The pypi package name is "chafe".  The python module installed with
this command is named "chacha".  The --pre option is needed because
the current version of this package is a pre-release.

Usage  
----- 
The package provides two entry points named encrypt and decrypt. That
means that if this module is in your Python path then the module can
be used as follows:

To encrypt a file named myfile:

 ``% python3 -m chacha.encrypt myfile``

You will be prompted for a password, and an encrypted file named
*myfile.cha* will be created.  The password will be visible until the
encryption is finished, then erased.  (So write it down on a piece of
paper before it disappears!)  Note that the erasure uses ANSI escape
sequences which will not work correctly if the terminal window is
too narrow.

To decrypt myfile.cha:

  ``% python3 -m chacha.decrypt myfile.cha``

You will be prompted for the password, and a decrypted file named *myfile*
will be created.  The password will be visible until the decryption is
finished, then erased.

If you install this module with pip and have configured your path to make
your pip-installed scripts available, then the commands will simply be:

  ``% chacha-encrypt myfile``

and

  ``% chacha-decrypt myfile.cha``
