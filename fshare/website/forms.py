from django.contrib.auth.forms import UserCreationForm
from django import forms

from website.models import User, Permission, FSUser 


class RegisterForm(UserCreationForm):

    def __init__(self, *args, **kwargs):
        # Username field 
        self.base_fields['username'].widget = forms.TextInput(attrs={'placeholder': "username", 'class': "form-control"})
        # Password field
        self.base_fields['password1'].widget = forms.TextInput(attrs={'type': 'password', 'placeholder': "password", 'class': "form-control"})
        # Password field (confirmation)
        self.base_fields['password2'].widget = forms.TextInput(attrs={'type': 'password', 'placeholder': "password (again)", 'class': "form-control"})
        # Email field
        self.base_fields['email'].widget = forms.TextInput(attrs={'type': 'email', 'placeholder': "@email (not required)", 'class': "form-control"})
        super(RegisterForm, self).__init__(*args, **kwargs)
        # Add field for registration key
        self.fields['registration_key'] = forms.CharField(
                                                            label="Registration Key", 
                                                            widget=forms.TextInput(attrs={
                                                                'type': "text",
                                                                'placeholder': "registration key (required)",
                                                                'class': "form-control",
                                                                                    })
                                                        )

    def is_valid(self):
        """
            Override validation method
            This method performs parent validation, plus checks the registration key

        """
        if not super(RegisterForm, self).is_valid():
            return False
        # TODO check key in database (exists ? already used ?)
        if self.cleaned_data["registration_key"] != "plop":
            return False
        return True

    def save(self):
        """
            Create a user object from form, and a FS user object 
            with permissions relative to registration key

        """
        #TODO give permissions relatively to key
        # Create django user object
        user = super(RegisterForm, self).save()
        # Get permissions corresponding to registration key (#TODO)
        perm = Permission.objects.get(name="admin")
        # Create FS user object
        fsuser = FSUser(user=user, permission=perm)
        fsuser.save()
        return fsuser

    class Meta:
        model = User
        fields = ['username', 'password1', 'password2', 'email']
