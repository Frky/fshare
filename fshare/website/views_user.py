
from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect

from website.models import FSUser
from website.forms import RegisterForm

def register(request):
    """
        Registration of new users
        redirect to index if registration succeed

    """
    ctxt = dict()
    ctxt["title"] = "Registration"
    tpl = "registration/register.html"
    # Get registration form from POST values
    reg_form = RegisterForm(request.POST or None, label_suffix='')
    # Check the form validity
    if reg_form.is_valid():
        # Register the new user
        new_user = reg_form.save()
        # Authenticate
        new_user = authenticate(username=new_user.user.username, password=request.POST["password1"])
        # Log the new user in
        login(request, new_user)
        return redirect("index")
    else:
        # Else we show a registration form
        ctxt["reg_form"] = reg_form
        return render(request, tpl, ctxt)


def is_admin(user):
    """
        Check whether the user can access admin pages or not
        (admin here points the Permission class, not the django admin)

    """
    fsuser = FSUser.objects.get(user=user)
    return fsuser.permission.name == "admin"


