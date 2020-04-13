#!/usr/bin/env python
# coding:utf-8
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

data = b"hello"
key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_EAX)
ciphertext, tag = cipher.encrypt_and_digest(data)

file_out = open("encrypted.bin", "wb")
[file_out.write(x) for x in (cipher.nonce, tag, ciphertext)]
