# This file is part of the chafe Python package which is distributed
# under the MIT license.  See the file LICENSE for details.
# Copyright © 2024 Marc Culler

#cython: language-level=3str

include 'implementation.pxi'

cdef extern from *:
    ctypedef struct chacha_context:
        u32 input[16]
    void chacha_wordtobyte(u8 *output, u32 *state, u32 *input)
    void chacha_init()
    void chacha_keysetup(chacha_context *x, const u8 *k, u32 kbits)
    void chacha_ivsetup(chacha_context *x, const u8 counter, const u8 *nonce)
    void chacha_encrypt_bytes(chacha_context *x, const u8 *m, u8 *c, u32 bytes)
    void chacha_decrypt_bytes(chacha_context *x, const u8 *m, u8 *c, u32 bytes)
    void chacha_keystream_bytes(chacha_context *x, u8 *stream, u32 bytes)

from libc.stdlib cimport malloc, free
from cpython.bytes cimport PyBytes_FromStringAndSize

def chacha_encrypt(bytes key, bytes nonce, bytes plaintext, u32 counter=0):
    cdef chacha_context context
    cdef Py_ssize_t length = len(plaintext)
    cdef u8* ciphertext = <u8*>malloc(length)
    cdef bytes result
    assert len(nonce) == 12, 'Nonce must be 12 bytes.'
    assert len(key) == 32, 'Key must be 32 bytes.'
    chacha_keysetup(&context, key, 256)
    chacha_ivsetup(&context, counter, nonce) 
    chacha_encrypt_bytes(&context, plaintext, ciphertext, length)
    result = PyBytes_FromStringAndSize(<char *>ciphertext, length)
    free(ciphertext)
    return result

def chacha_block_function(bytes key, bytes nonce):
    """Initialize a state matrix, apply 20 chacha rounds, and add."""
    cdef chacha_context context
    cdef u8 output[64]
    cdef u32 state[16]
    cdef u32 *x
    for i in range(64):
        output[i] = 0
    assert len(key) == 32, 'Key must be 32 bytes.'
    assert len(nonce) == 12, 'Nonce must be 12 bytes.'
    chacha_keysetup(&context, key, 256)
    chacha_ivsetup(&context, 0, nonce)
    chacha_wordtobyte(&output[0], &state[0], &context.input[0])
    return PyBytes_FromStringAndSize(<char *> output, 64)

def poly1305_tag(key: bytes, nonce: bytes, msg:bytes)->bytes:
    """Generate a 16 byte authentication tag for an encrypted message."""
    # The chacha cipher works by XORing the plaintext with a byte
    # sequence generated from the key and nonce.  That means that if
    # bit n is changed in the encrypted message and if that modified
    # message is then decrypted, then bit n will also have been
    # changed in the decrypted message.  The authentication tag allows
    # detection of such tampering.  Changing a bit in the encrypted
    # message will produce a different tag.
    assert len(key) == 32, 'Key must be 32 bytes.'
    assert len(nonce) == 12, 'Nonce must be 12 bytes.'
    # Work modulo this large prime:
    p1305 = (1 << 130) - 5
    # Generate a pair (r,s) of 128 bit integers which is unique per
    # invocation of the encryption process and unpredictable.
    tag_key = chacha_block_function(key, nonce)[:32]
    r = int.from_bytes(tag_key[:16], byteorder='little')
    s = int.from_bytes(tag_key[16:], byteorder='little')
    # The integer r must be "clamped" by setting certain bits to 0:
    r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
    # Divide the message into 16 byte chunks.  Each chunk determines
    # one coefficient of a polynomial; evaluate that polynomial at r
    # modulo p1305.
    accumulator = 0
    for i in range(0, len(msg), 16):
        chunk = msg[i : i + 16] + b"\x01"
        if len(chunk) < 17:
            chunk += (17 - len(chunk)) * b"\x00"
        coefficient = int.from_bytes(chunk, byteorder="little")
        accumulator = ((accumulator + coefficient) * r) % p1305
    # Add s and truncate to 128 bits
    result = (accumulator + s) % (1 << 128)
    # Convert the result to a byte sequence.
    return result.to_bytes(16, byteorder='little')
