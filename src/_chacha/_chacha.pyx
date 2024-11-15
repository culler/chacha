# This file is part of the chafe Python package which is distributed
# under the MIT license.  See the file LICENSE for details.
# Copyright © 2024 Marc Culler

#cython: language-level=3str

include 'implementation.pxi'

cdef extern from *:
    ctypedef struct chacha_context:
        unsigned int input[16]
    ctypedef unsigned int u32
    ctypedef unsigned char u8
    void chacha_wordtobyte(u8 *output, u32 *input)
    void chacha_init()
    void chacha_keysetup(chacha_context *x, const u8 *k, u32 kbits, u32 ivbits)
    void chacha_ivsetup(chacha_context *x, const u8 counter, const u8 *nonce)
    void chacha_encrypt_bytes(chacha_context *x, const u8 *m, u8 *c, u32 bytes)
    void chacha_decrypt_bytes(chacha_context *x, const u8 *m, u8 *c, u32 bytes)
    void chacha_keystream_bytes(chacha_context *x, u8 *stream, u32 bytes)

from libc.stdlib cimport malloc, free
from cpython.bytes cimport PyBytes_FromStringAndSize

def encrypt(bytes key, bytes nonce, bytes plaintext, u32 counter=0):
    cdef chacha_context context
    cdef Py_ssize_t length = len(plaintext)
    cdef u8* ciphertext = <u8*>malloc(length)
    cdef bytes result
    assert len(nonce) == 12
    # We use a 32 byte key and a 16 byte initial value.
    chacha_keysetup(&context, key, 256, 128)
    chacha_ivsetup(&context, counter, nonce) 
    chacha_encrypt_bytes(&context, plaintext, ciphertext, length)
    result = PyBytes_FromStringAndSize(<char *>ciphertext, length)
    free(ciphertext)
    return result

