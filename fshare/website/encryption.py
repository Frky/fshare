import hashlib
import os
import tempfile

from random import randint, choice
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

from django.utils.encoding import smart_str

CHUNK_SIZE = 24*1024

def generate_random_name(length=50):
    charset  = "azertyuiopmlkjhgfdsqwxcvbnAZERTYUIOPQSDFGHJKLMWXCVBN1234567890"
    return "".join([choice(charset) for i in range(length)])

def generate_random_path(folder):
    charset  = "azertyuiopmlkjhgfdsqwxcvbnAZERTYUIOPQSDFGHJKLMWXCVBN1234567890"
    path = "{0}/{1}".format(folder, generate_random_name())
    while os.path.exists(path):
        path = "{0}/{1}".format(folder, generate_random_name())
    return path

def encrypt_filename(filename, pwd, iv):
    # Derive a key from "human" password
    key = PBKDF2(pwd, iv)
    # Create a AES encryptor object
    enc = AES.new(key, AES.MODE_CBC, iv)
    while len(filename) % 16 != 0:
        filename += smart_str(' ', "utf-8")
    return b64encode(enc.encrypt(filename))

def decrypt_filename(filename_enc, pwd, iv):
    # Derive a key from "human" password and iv
    key = PBKDF2(pwd, iv.encode("utf-8"))
    # Create a AES decryptor object
    dec = AES.new(key, AES.MODE_CBC, iv.encode("utf-8"))
    filename_enc = b64decode(filename_enc)
    filename = dec.decrypt(filename_enc)
    while filename.endswith(b' '):
        filename = filename[:-1]
    return filename

def encrypt_file(filename, file_content, folder, pwd):
    # Generate a random IV
    iv = str.encode("".join([chr(randint(0, 127)) for i in range(16)]))
    # Derive a key from "human" password
    key = PBKDF2(pwd, iv)
    # Create a AES encryptor object
    enc = AES.new(key, AES.MODE_CBC, iv)
    # Create a MD5 hasher for file checksum
    m = hashlib.md5()
    # Generate a file path
    filepath = generate_random_path(folder)
    # Open destination for write
    with open(filepath, 'wb+') as dest:
        # Iteration chunk by chunk
        while True:
            # Getting bytes from file
            chunk = file_content.read(CHUNK_SIZE)
            # Update md5
            m.update(chunk)
            # Detect EOF
            if len(chunk) == 0:
                break
            # Add padding if needed
            elif len(chunk) % 16 != 0:
                chunk += str.encode(' ' * (16 - len(chunk) % 16))
            # Write to destination encrypted chunk
            dest.write(enc.encrypt(chunk))
    # Return iv used for encryption (need to be stored in DB)
    return iv, m.hexdigest(), filepath

def decrypt_file(file_object, pwd):
    # Getting iv from DB
    iv = file_object.iv
    # Derive a key from "human" password and iv
    key = PBKDF2(pwd, iv.encode("utf-8"))
    # Create a AES decryptor object
    dec = AES.new(key, AES.MODE_CBC, iv.encode("utf-8"))
    # Content of the deciphered file to be filled chunk by chunk
    clear_file = tempfile.TemporaryFile(mode='wb+')
    # Open source file
    with open(file_object.path, 'rb') as f:
        # Iteration on each chunk
        i = 0
        while True:
            i += 1
            # Getting bytes from file
            chunk = f.read(CHUNK_SIZE)
            # Detect EOF
            if len(chunk) == 0:
                break
            # Decrypt chunk
            clear_file.write(dec.decrypt(chunk))
    clear_file.seek(0)
    # Return deciphered content truncated by the padding
    return clear_file
