import os
from random import randint

from django.db import models
from django.contrib.auth.models import User
from django.conf import settings

from website.random_primary import RandomPrimaryIdModel


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
    iv = models.CharField(max_length=16, blank=True, null=True)
    # Password to protect download 
    # NB. This password is NOT hashed 
    # To be removed in the future
    pwd = models.CharField(max_length=512, blank=True, null=True, verbose_name="Key")

    # Limitations

    # Number of DL before deleted
    max_dl = models.IntegerField(default=1)
    # Expiration date
    expiration_date = models.DateTimeField(default=None, blank=True, null=True)

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
