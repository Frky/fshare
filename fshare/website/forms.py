import hashlib
import os
import json
from datetime import datetime, timedelta

from django import forms
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.hashers import make_password
from django.utils.safestring import mark_safe
from django.utils.encoding import smart_str
from django.contrib.auth.models import AnonymousUser

from website.models import User, Permission, FSUser, RegistrationKey, File
from website.expiration import compute_expiration_date
from website.encryption import encrypt_file, encrypt_filename, generate_random_path, decrypt_filename


class RegisterForm(UserCreationForm):

    class Meta:
        model = User
        fields = ['username', 'password1', 'password2', 'email']
        widgets = {
                    'username': forms.TextInput(attrs={'placeholder': "a-z, A-Z, 0-9 and @/./+/-/_", 'class': "form-control"}),
                    'email': forms.TextInput(attrs={'type': 'email', 'placeholder': "not required", 'class': "form-control"}),
                }
        labels = {
                    'username': "Username",
                    'password1': "Password",
                    'password2': "Password (again)",
                    'email': "@email",
                }

    def __init__(self, *args, **kwargs):
        self.base_fields['password1'].widget = forms.TextInput(attrs={'type': 'password', 'placeholder': "e.g. hunter2", 'class': "form-control"})
        self.base_fields['password1'].label = "Password"
        self.base_fields['password2'].widget = forms.TextInput(attrs={'type': 'password', 'placeholder': "e.g. hunter2", 'class': "form-control"})
        self.base_fields['password2'].label = "Password (again)"
        super(RegisterForm, self).__init__(*args, **kwargs)
        # Add field for registration key
        self.fields['registration_key'] = forms.CharField(
                                                            label="Registration Key", 
                                                            widget=forms.TextInput(attrs={
                                                                'type': "text",
                                                                'placeholder': "required",
                                                                'class': "form-control",
                                                                                    })
                                                        )

    def is_valid(self):
        """
            Override validation method
            This method performs parent validation, plus checks the registration key

        """
        # TODO return specific error code
        if not super(RegisterForm, self).is_valid():
            return False
        try:
            key = RegistrationKey.objects.get(key=self.cleaned_data["registration_key"])
        except ObjectDoesNotExist:
            return False
        if key.used or key.revoked:
            return False
        return True

    def save(self):
        """
            Create a user object from form, and a FS user object 
            with permissions relative to registration key

        """
        # Create django user object
        user = super(RegisterForm, self).save()
        # Get the registration key from db
        key = RegistrationKey.objects.get(key=self.cleaned_data["registration_key"])
        # Mark the key as used
        key.used = True
        key.save()
        # Get permissions corresponding to registration key 
        perm = Permission.objects.get(name=key.permission.name)
        # Create FS user object
        fsuser = FSUser(user=user, permission=perm)
        fsuser.save()
        return fsuser


class PermissionForm(forms.ModelForm):
    """
        Form relative to creation of new permissions

    """

    class Meta:
        model = Permission
        fields = [
                    'name', 
                    'storage_limit', 
                    'max_dl_limit', 
                    'max_expiration_delay',
                    'base_path', 
                ]
        labels = {
                    'name': 'Permission name',
                    'storage_limit': 'Storage limit (in bytes)',
                    'base_path': 'Path to permission class storage',
                    'max_dl_limit': 'Max #DL per file',
                    'max_expiration_date': 'Max TTL per file',
                }
        # TODO handle base path field correctly
        widgets = {
                    'name': forms.TextInput(attrs={'placeholder': "permission class name", 'class': "form-control"}),
                    'storage_limit': forms.NumberInput(attrs={'placeholder': "storage limit (in bytes)", 'class': "form-control"}),
                    'max_dl_limit': forms.NumberInput(attrs={
                                                                'placeholder': "max number of downloads before deleting file", 
                                                                'class': "form-control"
                                                            }),
                    'max_expirtion_delay': forms.NumberInput(attrs={
                                                                'placeholder': "max number of days before deleting file", 
                                                                'class': "form-control"
                                                            }),
                    'base_path': forms.TextInput(attrs={'placeholder': "base path to store files", 'class': "form-control"}),
                }

    def split_path(self):
        """
            From the base path of the permission, try to extract the subpath corresponding
            to the permission name. If permission name was not specified, nothing is done
            and (base_path, '') is returned. Otherwise, remove permission name from base path 
            and returns (base_path_after_removal, permission_name).

            Examples:
                - if base_path = '/tmp/regular' for permission 'regular', 
                    returns ('/tmp', 'regular')
                - if base_path = '/tmp' for permission 'regular',
                    returns ('/tmp', '')

        """
        # Get the base path as specified in the form
        base_path = os.path.normpath(self.cleaned_data["base_path"])
        sub_path = ""
        # Remove '/' at the end of the path if any
        if base_path[-1] == "/":
            base_path = base_path[:-1]
        # Check if base path ends with permission name
        if os.path.basename(base_path) == self.cleaned_data["name"]:
            # sub_path takes the permission name as value
            sub_path = self.cleaned_data["name"]
            # Remove permission name from base_path
            base_path = base_path[:-len(sub_path)]
        return base_path, sub_path

    def is_valid(self):
        if not super(PermissionForm, self).is_valid():
            return False
        base_path, sub_path = self.split_path()
        # TODO specify error (does not exist or cannot read)
        # Check if base_path exists and is writable
        if not os.path.exists(base_path) or not os.access(base_path, os.W_OK):
            return False
        if sub_path == "":
            return True
        # TODO specify error (already exists but can't write)
        # If sub_path already exists, check if it is writable
        if os.path.exists(os.path.join(base_path, sub_path)) and not os.access(os.path.join(base_path, sub_path), os.W_OK):
            return False
        return True

    def save(self):
        base_path, sub_path = self.split_path()
        # Create target dir if does not exist
        if not os.path.exists(os.path.join(base_path,sub_path)):
            os.mkdir(os.path.join(base_path, sub_path))
        return super(PermissionForm, self).save()


class UploadFileForm(forms.ModelForm):
    expiration_date = forms.IntegerField(
                                            widget = forms.NumberInput(attrs={'class': "form-control"}),
                                            label = 'time to live in days',
                                        )
    file = forms.FileField(widget=forms.FileInput(attrs={'class': 'superDropzone'}), label='')

    class Meta:
        model = File
        fields = [
                    'key',
                    'max_dl',
                ]
        widgets = {
                    'key': forms.TextInput(attrs={'placeholder': "recommanded (used to encrypt file)", 'class': "form-control"}),
                    'max_dl': forms.NumberInput(attrs={'class': "form-control"}),
                }
        labels = {
                    'key': mark_safe("key (<span class=\"link\" id=\"gen-key-btn\">generate random</span>)"),
                    'max_dl': "maximum number of downloads",
                }

    def __init__(self, *args, **kwargs):
        if "set_default" in kwargs.keys():
            set_default = kwargs.pop("set_default")
        else:
            set_default = False
        # Get the authenticated user
        if "user" in kwargs.keys():
            user = kwargs.pop("user")
        else:
            user = AnonymousUser()
        # Init form with super constructor
        super(UploadFileForm, self).__init__(*args, **kwargs)
        # Case 1: user is anonymous (or not logged in) > remove unrelevant fields from form
        if not user.is_authenticated or user.is_anonymous:
            # So no max dl field
            self.fields.pop("max_dl")
            # And no expiration date field
            self.fields.pop("expiration_date")
        # Case 2: user is logged in > more permissions than anonymous user
        elif set_default:
            # Set default value for both fields
            self.fields["max_dl"].widget.__dict__["attrs"]["value"] = settings.FILE_MAX_DL_ANONYMOUS
            self.fields["expiration_date"].widget.__dict__["attrs"]["value"] = settings.FILE_MAX_DAYS_ANONYMOUS
            # Set min, max and label (if relevant) for max_dl
            if user.fshare_user.permission.max_dl_limit == 0:
                # 0 = no limit
                self.fields["max_dl"].widget.__dict__["attrs"]["min"] = 0
                self.fields["max_dl"].label += " (0 = no limit)"
            else:
                self.fields["max_dl"].widget.__dict__["attrs"]["min"] = 1
                self.fields["max_dl"].widget.__dict__["attrs"]["max"] = user.fshare_user.permission.max_dl_limit
            # Set min, max and label (if relevant) for expiration date
            if user.fshare_user.permission.max_expiration_delay == 0:
                # 0 = no limit
                self.fields["expiration_date"].widget.__dict__["attrs"]["min"] = 0
                self.fields["expiration_date"].label += " (0 = no limit)"
            else:
                self.fields["expiration_date"].widget.__dict__["attrs"]["min"] = 1
                self.fields["expiration_date"].widget.__dict__["attrs"]["max"] = user.fshare_user.permission.max_expiration_delay


    def is_valid(self, user=None):
        """
            Override validation method
            This method performs parent validation, plus check file size

        """
        if not super(UploadFileForm, self).is_valid():
            return False
        if user.is_anonymous or not user.is_authenticated:
            return self.cleaned_data.get('file').size <= settings.FILE_MAX_SIZE_ANONYMOUS
        else:
            return user.fshare_user.can_upload(
                            self.cleaned_data.get('file').size, 
                            self.cleaned_data.get('max_dl'),
                            self.cleaned_data.get('expiration_date'),
                                                )

    def save(self, user, file_names, fid=None):
        if user.is_anonymous or not user.is_authenticated:
            folder = settings.UPLOAD_DIRECTORY_ANONYMOUS
            max_dl = settings.FILE_MAX_DL_ANONYMOUS
            ttl = settings.FILE_MAX_DAYS_ANONYMOUS
        else:
            folder = os.path.join(user.fshare_user.permission.base_path, user.username)
            max_dl = self.cleaned_data.get('max_dl')
            ttl = self.cleaned_data.get('expiration_date')
        if not os.path.exists(folder):
            os.makedirs(folder)

        key = self.cleaned_data.get('key') or None

        uploaded_file = self.cleaned_data.get('file')

        if key is not None:
            iv, md5, filepath = encrypt_file(uploaded_file.name, uploaded_file, folder, key)
            filename = encrypt_filename(uploaded_file.name, key, iv)
            file_list = encrypt_filename(json.dumps(file_names), key, iv)
        else:
            filepath = generate_random_path(folder)
            filename = uploaded_file.name
            file_list = file_list_safe
            iv = None
            m = hashlib.md5()
            with open(filepath, 'wb+') as destination:
                for chunk in uploaded_file.chunks():
                    m.update(chunk)
                    destination.write(chunk)
            md5 = m.hexdigest()

        old_path = None
        if fid is not None:
            try:
                new_file = File.objects.get(id=fid)
                old_path = new_file.path
                new_file.title = filename
                new_file.size = uploaded_file.size
                new_file.file_list = file_list
                new_file.path = filepath
                new_file.checksum = md5
                new_file.iv = iv
                new_file.nb_dl = 0
            except Exception:
                new_file = None
        else:
            new_file = None

        # IF user is authenticated, we DO store the key to allow modification
        # of content later on
        # !!! CONFIDENTIALITY IS NOT PRESERVED IN THIS CASE
        # (please use anonymous upload to ensure confidentiality)
        if user.is_authenticated and not user.is_anonymous:
            real_key = key
        else:
            real_key = None

        if not new_file:
            new_file = File(
                owner=user if not user.is_anonymous else None,
                title=uploaded_file.name,
                private_label=self.cleaned_data.get('private_label', self.cleaned_data.get('title')),
                description=self.cleaned_data.get('description'),
                file_list=json.dumps(file_names), 
                path=filepath,
                checksum=md5,
                size=uploaded_file.size,
                expiration_date=compute_expiration_date(ttl),
                key = hashlib.sha3_512(key.encode("utf-8")).hexdigest() if key is not None else None,
                real_key = real_key,
                iv = iv.decode("utf-8") if iv is not None else None,
                max_dl = max_dl,
            )
        pwd = self.cleaned_data.get('pwd') or None
        if new_file.is_private:
            new_file.pwd = pwd

        new_file.save()

        if old_path is not None:
            try:
                # Delete old file on disk
                os.remove(old_path)
            except OSError:
                # If file was not found, pass
                pass

        return new_file

