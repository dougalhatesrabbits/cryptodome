from Crypto import Random  # use to generate a random byte string of a length we decide
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from Cryptodome import Random
from Cryptodome.Random import get_random_bytes

# Builtins
import base64
import hashlib

'''
https://tutorialsoverflow.com/python-encryption-and-decryption/
'''

"""
# Block sizes for AES encryption is 16 bytes or 128 bits. When AES encryption taking place it will divide our data
# into blocks of length 16. This is a fixed size. So what if your data is smaller than the blocksize ? That’s where
# padding comes into play. Now we need to create a padding function. And also we need to create a unpadding function
# so that we can remove the padding during our encryption process.
"""

BS = 16


# pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
# unpad = lambda s: s[0:-s[-1]]
def pad(s):
    return s + (BS - len(s) % BS) * chr(BS - len(s) % BS)


def unpad(s):
    return s[0:-s[-1]]


class AESCipher:

    def __init__(self, key):
        self.key = hashlib.sha256(key.encode('utf-8')).digest()

    def encrypt(self, raw):
        raw = pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode('utf8')))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[16:]))


cipher = AESCipher('mysecretpassword')
encrypted = cipher.encrypt('Secret Message A')
decrypted = cipher.decrypt(encrypted)
print(encrypted)
print(decrypted)


# https://stackoverflow.com/questions/42568262/how-to-encrypt-text-with-a-password-in-python/44212550#44212550
# Here's how to do it properly in CBC mode, including PKCS#7 padding:

def encrypt(key, source, encode=True):
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = Random.new().read(AES.block_size)  # generate IV
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    padding = AES.block_size - len(source) % AES.block_size  # calculate needed padding
    source += bytes([padding]) * padding  # Python 2.x: source += chr(padding) * padding
    data = IV + encryptor.encrypt(source)  # store the IV at the beginning and encrypt
    return base64.b64encode(data).decode("latin-1") if encode else data


def decrypt(key, source, decode=True):
    if decode:
        source = base64.b64decode(source.encode("latin-1"))
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = source[:AES.block_size]  # extract the IV from the beginning
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    data = decryptor.decrypt(source[AES.block_size:])  # decrypt
    padding = data[-1]  # pick the padding value from the end; Python 2.x: ord(data[-1])
    if data[-padding:] != bytes([padding]) * padding:  # Python 2.x: chr(padding) * padding
        raise ValueError("Invalid padding...")
    return data[:-padding]  # remove the padding


# Now if you test it as:

my_password = b"secret_AES_key_string_to_encrypt/decrypt_with"
my_data = b"input_string_to_encrypt/decrypt"

print("key:  {}".format(my_password))
print("data: {}".format(my_data))
encrypted = encrypt(my_password, my_data)
print("\nenc:  {}".format(encrypted))
decrypted = decrypt(my_password, encrypted)
print("dec:  {}".format(decrypted))
print("\ndata match: {}".format(my_data == decrypted))
print("\nSecond round....")
encrypted = encrypt(my_password, my_data)
print("\nenc:  {}".format(encrypted))
decrypted = decrypt(my_password, encrypted)
print("dec:  {}".format(decrypted))
print("\ndata match: {}".format(my_data == decrypted))

