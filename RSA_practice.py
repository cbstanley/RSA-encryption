#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Practice with RSA encryption.

Using some helper functions from Udacity Applied Cryptography course.
These can be found at:
https://www.udacity.com/course/applied-cryptography--cs387
'''

from Crypto.PublicKey import RSA

# Generate an RSA key
key = RSA.generate(2048)

print('p =')
print(key.p)
print('\n')

print('q =')
print(key.q)
print('\n')

print('n =')
print(key.n)
print('\n')

# Totient(n)
phi_n = (key.p - 1)*(key.q - 1)
print('phi(n) =')
print(phi_n)
print('\n')

# key.d * key.e - 1 = k * phi(n), for some int k

###########################################################
# Helper functions from Udacity Applied Cryptography course

BITS = ('0', '1')
ASCII_BITS = 7


def display_bits(b):
    """converts list of {0, 1}* to string"""
    return ''.join([BITS[e] for e in b])


def seq_to_bits(seq):
    return [0 if b == '0' else 1 for b in seq]


def pad_bits(bits, pad):
    """pads seq with leading 0s up to length pad"""
    assert len(bits) <= pad
    return [0] * (pad - len(bits)) + bits


def convert_to_bits(n):
    """converts an integer `n` to bit array"""
    result = []
    if n == 0:
        return [0]
    while n > 0:
        result = [(n % 2)] + result
        n = n // 2
    return result


def string_to_bits(s):
    def chr_to_bit(c):
        return pad_bits(convert_to_bits(ord(c)), ASCII_BITS)
    return [b for group in
            map(chr_to_bit, s)
            for b in group]


def bits_to_char(b):
    assert len(b) == ASCII_BITS
    value = 0
    for e in b:
        value = (value * 2) + e
    return chr(value)


def bits_to_string(b):
    return ''.join([bits_to_char(b[i:i + ASCII_BITS])
                    for i in range(0, len(b), ASCII_BITS)])

###########################################################


# Create a message to encrypt
message = 'Grocery list: sweet potatoes, broccoli, apples, bananas, yogurt'

# Convert to bits
msg_bits = string_to_bits(message)
msg_bits = int(display_bits(msg_bits))
# print(msg_bits)

# Encrypted message: E(m) = m**e % n
E_m = pow(msg_bits, key.e, key.n)
print('Cipher: \n' + str(E_m) + '\n')

# Decrypted message: D(c) = c**d % n
D_c = pow(E_m, key.d, key.n)
D_c_str = seq_to_bits(str(D_c))
D_c_str = bits_to_string(D_c_str)
print('Decrypted message: \n' + D_c_str)
