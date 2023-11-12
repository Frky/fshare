from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import binascii
import json
import hashlib
import os
import re
import secrets
import tempfile

from django.db import models
from django.contrib.auth.models import User
from django.conf import settings

from website.random_primary import RandomPrimaryIdModel

from website.utils import generate_random_path, generate_random_name

CHUNK_SIZE = 24*1024

def unescape(text):
    regex = re.compile(b'\\\\(x[0-9a-f]{2}|[\'"abfnrt]|.|$)')
    def replace(m):
        b = m.group(1)
        if len(b) == 0:
            raise ValueError("Invalid character escape: '\\'.")
        if b[0] == ord('x'):
            v = int(b[1:], 16)
        elif 48 <= b[0] <= 55:
            v = int(b, 8)
        elif b[0] == 34: return b'"'
        elif b[0] == 39: return b"'"
        elif b[0] == 92: return b'\\'
        elif b[0] == 97: return b'\a'
        elif b[0] == 98: return b'\b'
        elif b[0] == 102: return b'\f'
        elif b[0] == 110: return b'\n'
        elif b[0] == 114: return b'\r'
        elif b[0] == 116: return b'\t'
        elif b[0] == ord("\\"): return b'\\'
        else:
            return b'?'
        return bytes((v, ))
    return regex.sub(replace, text.encode("latin1"))

def is_b64(s):
    return len(list(filter(lambda a: a in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890+/=', s))) == len(s)


class File(RandomPrimaryIdModel):
    """
        Base model for files uploaded with fshare

    """

    # Owner of the file
    owner = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)

    # File Description 

    # Title of the file
    title = models.CharField(max_length=255, null=True, blank=True)
    # Private label : not shown to downloader
    # Only used for the uploader for additional description
    private_label = models.CharField(max_length=255, null=True, blank=True)
    # Public description of the file
    description = models.TextField(null=True, blank=True, default="")
    # List of files (relevant only if file is an archive)
    file_list = models.CharField(max_length=1024, null=True, blank=True)

    # File Information

    # Path where the file is stored
    path = models.CharField(max_length=1024, null=False, blank=False)
    # Checksum of the uploaded file
    checksum = models.CharField(max_length=128, null=False, blank=False)
    # Size of the file in bytes
    size = models.IntegerField(null=False, blank=False)
    # Date of upload
    uploaded = models.DateTimeField(auto_now_add=True)
    # Date of last modification of descritions
    edited = models.DateTimeField(auto_now=True)

    # Statistics

    # Number of view of DL page
    nb_hits = models.IntegerField(default=0)
    # Number of DLs
    nb_dl = models.IntegerField(default=0)

    # Privacy

    # Is the file protected with a password/key ?
    # useless (?)
    # Need to add hash of pwd to check (OR a header ?)
    is_private = models.BooleanField(default=False)
    # Hash of the key used to cipher file
    key = models.CharField(max_length=512, blank=True, null=True, verbose_name="Key")
    # Real key - stored ONLY for authenticated users
    # (to be able to edit content later on)
    # In this case, confidentiality of content is not ensured anymore
    # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    # (to preserve confidentiality, please use anonymous uploads)
    real_key = models.CharField(max_length=512, blank=True, null=True, default=None)
    # Initialization Vector for AES encryption
    iv = models.CharField(max_length=32, blank=True, null=True)
    # Password to protect download 
    # NB. This password is NOT hashed 
    # To be removed in the future
    pwd = models.CharField(max_length=512, blank=True, null=True, verbose_name="Key")

    # Limitations

    # Number of DL before deleted
    max_dl = models.IntegerField(default=1)
    # Expiration date
    expiration_date = models.DateTimeField(default=None, blank=True, null=True)

    def set_name(self, filename, pwd=""):
        if not self.iv:
            # Generate a random IV
            self.iv = b64encode(secrets.token_bytes(16)).decode("utf-8")
        iv = b64decode(self.iv.encode("utf-8"))
        # Derive a key from "human" password
        key = PBKDF2(pwd, iv)
        # Create a AES encryptor object
        enc = AES.new(key, AES.MODE_CBC, iv)
        filename = filename.encode("utf-8")
        while len(filename) % 16 != 0:
            filename += b' '
        c = enc.encrypt(filename) 
        self.title = b64encode(
                c
            ).decode("utf-8")

    def get_name(self, pwd=""):
        if is_b64(self.iv):
            iv = b64decode(self.iv.encode("utf-8"))
        elif self.iv[:2] == "b'":
            iv = unescape(self.iv[2:-1])
        else:
            iv = self.iv.encode()
        # Derive a key from "human" password and iv
        key = PBKDF2(pwd, iv)
        # Create a AES decryptor object
        dec = AES.new(key, AES.MODE_CBC, iv)
        try:
            if self.title[:2] == "b'":
                title = self.title[2:-1]
            else:
                title = self.title
            if is_b64(title):
                title = b64decode(title.encode("utf-8"))
            else:
                title = title.encode("utf-8")
            filename = dec.decrypt(title)
            while filename.endswith(b' '):
                filename = filename[:-1]
            return filename.decode("utf-8")
        except UnicodeDecodeError:
            key = PBKDF2(pwd, iv)
            dec = AES.new(key, AES.MODE_CBC, iv)
            filename = dec.decrypt(b64decode(self.title.encode("utf-8"))[2:] + b'aa')
            return filename
        except (binascii.Error, ValueError):
            if is_b64(self.title):
                return b64decode(self.title)
            elif is_b64(self.title[2:-1]):
                return b64decode(self.title[2:-1])
            else:
                return self.title.encode("utf-8")

    def set_list(self, flist, pwd=""):
        if not self.iv:
            # Generate a random IV
            self.iv = b64encode(secrets.token_bytes(16)).decode("utf-8")
        iv = b64decode(self.iv.encode("utf-8"))
        # Derive a key from "human" password
        key = PBKDF2(pwd, iv)
        # Create a AES encryptor object
        enc = AES.new(key, AES.MODE_CBC, iv)
        content = json.dumps(flist)
        while len(content) % 16 != 0:
            content += ' '
        self.file_list = b64encode(
                enc.encrypt(content.encode("utf-8"))
            ).decode("utf-8")

    def get_list(self, pwd=""):
        """
        iv = b64decode(self.iv.encode("utf-8"))
        # Derive a key from "human" password and iv
        key = PBKDF2(pwd, iv)
        # Create a AES decryptor object
        dec = AES.new(key, AES.MODE_CBC, iv)
        flist = dec.decrypt(b64decode(self.file_list.encode("utf-8")))
        while flist.endswith(b' '):
            flist = flist[:-1]
        return json.loads(flist.decode("utf-8"))
        """
        if is_b64(self.iv):
            iv = b64decode(self.iv.encode("utf-8"))
        elif self.iv[:2] == "b'":
            iv = unescape(self.iv[2:-1])
        else:
            iv = self.iv.encode()
        # Derive a key from "human" password and iv
        key = PBKDF2(pwd, iv)
        # Create a AES decryptor object
        dec = AES.new(key, AES.MODE_CBC, iv)
        try:
            if self.file_list[:2] == "b'":
                file_list = self.file_list[2:-1]
            else:
                file_list = self.file_list
            if is_b64(file_list):
                file_list = b64decode(file_list.encode("utf-8"))
            else:
                file_list = file_list.encode("utf-8")
            filelist = dec.decrypt(file_list)
            while filelist.endswith(b' '):
                filelist = filelist[:-1]
            return json.loads(filelist.decode("utf-8"))
        except UnicodeDecodeError:
            key = PBKDF2(pwd, iv)
            dec = AES.new(key, AES.MODE_CBC, iv)
            filelist = dec.decrypt(b64decode(self.file_list.encode("utf-8"))[2:] + b'aa')
            return filelist
        except (binascii.Error, ValueError):
            if is_b64(self.file_list):
                return b64decode(self.file_list)
            elif is_b64(self.file_list[2:-1]):
                return b64decode(self.file_list[2:-1])
            else:
                return self.file_list.encode("utf-8")

    def set_content(self, content, pwd=""):
        if not self.iv:
            # Generate a random IV
            self.iv = b64encode(secrets.token_bytes(16)).decode("utf-8")
        iv = b64decode(self.iv.encode("utf-8"))
        # Derive a key from "human" password
        key = PBKDF2(pwd, iv)
        # Create a AES encryptor object
        enc = AES.new(key, AES.MODE_CBC, iv)
        # Create a MD5 hasher for file checksum
        m = hashlib.md5()
        # Open destination for write
        with open(self.path, 'wb+') as dest:
            # Iteration chunk by chunk
            while True:
                # Getting bytes from file
                chunk = content.read(CHUNK_SIZE)
                # Update md5
                m.update(chunk)
                # Detect EOF
                if len(chunk) == 0:
                    break
                # Add padding if needed
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - len(chunk) % 16)
                # Write to destination encrypted chunk
                dest.write(enc.encrypt(chunk))
        self.checksum = m.hexdigest()

    def get_content(self, pwd=""):
        if is_b64(self.iv):
            iv = b64decode(self.iv.encode("utf-8"))
        elif self.iv[:2] == "b'":
            iv = unescape(self.iv[2:-1])
        else:
            iv = self.iv.encode()
        # Derive a key from "human" password and iv
        key = PBKDF2(pwd, iv)
        # Create a AES decryptor object
        dec = AES.new(key, AES.MODE_CBC, iv)
        clear_file = tempfile.TemporaryFile(mode='wb+')
        with open(self.path, 'rb') as f:
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

    def delete(self):
        try:
            # Delete file on disk
            os.remove(self.path)
        except OSError:
            # If file was not found, pass
            pass
        super(File, self).delete()


class Permission(models.Model):
    """
        Class of permissions for a given user.
        Defines storage space, location of storage, etc.

    """
    # Name of the permission category
    name = models.CharField(max_length=255, primary_key=True)
    # Max storage space in bytes
    storage_limit = models.IntegerField(default=209715200)
    # Max number of DLs per file
    max_dl_limit = models.IntegerField(default=5)
    # Max expiration date delay
    max_expiration_delay = models.IntegerField(default=30)
    # Location where to store the files
    base_path = models.CharField(max_length=1024, null=False, blank=False, default=os.path.abspath(getattr(settings, "MEDIA_ROOT", "/tmp/")))


class RegistrationKey(models.Model):
    """
        Model for key needed for registration

    """
    # Registration key (can be used only once)
    key = models.CharField(max_length=100, null=False, blank=False)
    # Has it been used yet ?
    used = models.BooleanField(default=False)
    # Has it been distributed yet ?
    distributed = models.BooleanField(default=False)
    # Has it been revoked by admin ?
    revoked = models.BooleanField(default=False)
    # Corresponding permission
    permission = models.ForeignKey(Permission, null=False, blank=False, on_delete=models.PROTECT)


class FSUser(models.Model):
    """
        Defines a user with specified permissions

    """
    user = models.OneToOneField(User, related_name="fshare_user", on_delete=models.CASCADE)
    permission = models.ForeignKey(Permission, null=False, blank=False, on_delete=models.PROTECT)

    def can_upload(self, size, max_dl, ttl):
        """
            Check if a user can upload a file

        """
        # max_dl_limit set to 0 means no limit
        if self.permission.max_dl_limit > 0:
            if max_dl is None or max_dl > self.permission.max_dl_limit:
                return False
        # expiration delay set to 0 means no limit
        if self.permission.max_expiration_delay > 0:
            if ttl is None or ttl > self.permission.max_expiration_delay:
                return False
        return (self.storage_left - size) > 0

    @property
    def storage_limit(self):
        return self.permission.storage_limit 

    @property
    def storage_left(self):
        storage_used = sum([f.size for f in File.objects.all().filter(owner=self.user)])
        return max(self.storage_limit - storage_used, 0)

    @property
    def storage_percent(self):
        return min(int(100. * (self.storage_limit - self.storage_left) / float(self.storage_limit)), 100)
