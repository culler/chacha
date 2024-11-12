A ChaCha File Encryptor
=======================

This Python package provides tools for encrypting and decrypting files
with Dan Bernstein's ChaCha20 stream cipher, using a key derived from
a pass phrase.  The package uses the ChaCha20 implementation in the
pypi cryptography package, which will be installed as a dependency 

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
encryption is finished, then erased.  (So write it down first!)

To decrypt myfile.cha:

  ``% python3 -m chacha.decrypt myfile.cha``

You will be prompted for the password, and a decrypted file named *myfile*
will be created.  The password will be visible until the decryption is
finished, then erased.

If you install this module with pip then the commands will simply be:

  ``% chacha-encrypt myfile``

and

  ``% chacha-decrypt myfile.cha``
