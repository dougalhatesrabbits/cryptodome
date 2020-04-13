from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

"""
https://www.pycryptodome.org/en/latest/src/examples.html
"""
'''
Encrypt data with AES

The following code generates a new AES128 key and encrypts a piece of data into a file. 
We use the EAX mode because it allows the receiver to detect any unauthorized modification (similarly, 
we could have used other authenticated encryption modes like GCM, CCM or SIV).

'''
data = b"hello"
key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_EAX)
ciphertext, tag = cipher.encrypt_and_digest(data)
print(key, cipher, ciphertext)

file_out = open("encrypted.bin", "wb")
[file_out.write(x) for x in (cipher.nonce, tag, ciphertext)]
print(cipher.nonce, tag, ciphertext)
file_out.close()



'''
At the other end, the receiver can securely load the piece of data back (if they know the key!). 
Note that the code generates a ValueError exception when tampering is detected.

'''
file_in = open("encrypted.bin", "rb")
nonce, tag, ciphertext = [file_in.read(x) for x in (16, 16, -1)]

# let's assume that the key is somehow available again
cipher = AES.new(key, AES.MODE_EAX, nonce)
data = cipher.decrypt_and_verify(ciphertext, tag)
print(data)
file_in.close()
