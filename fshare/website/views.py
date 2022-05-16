import mimetypes
import json

from django.shortcuts import render, redirect, HttpResponse, Http404, get_object_or_404
from django.contrib.auth.hashers import check_password
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist
from django.conf import settings
from django.utils.encoding import smart_str
from django.views.decorators.csrf import csrf_exempt

from website.models import Permission, FSUser, RegistrationKey, File
from website.forms import RegisterForm, PermissionForm, UploadFileForm
from website.encryption import decrypt_file, decrypt_filename, generate_random_name

from website.views_file import download, get, update, delete, get_name, get_files_from_req
from website.views_cockpit import cockpit, generate_registration_key, mark_key_distributed, revoke_key
from website.views_user import register, is_admin


def index(request):
    """
        Home page - presentation of FShare

    """
    ctxt = dict()
    ctxt["title"] = "Index"
    if request.user.is_anonymous:
        ctxt["size_limit"] = settings.FILE_MAX_SIZE_ANONYMOUS
    else:
        ctxt["size_limit"] = FSUser.objects.get(user=request.user).storage_left
    ctxt["day_limit"] = settings.FILE_MAX_DAYS_ANONYMOUS
    ctxt["dl_limit"] = settings.FILE_MAX_DL_ANONYMOUS
    ctxt["contact"] = settings.CONTACT
    tpl = "website/index.html"
    ctxt["form"] = UploadFileForm(request.POST, request.FILES, user=request.user, label_suffix='', set_default=True)
    return render(request, tpl, ctxt)


def about(request):
    return HttpResponse("To Do.")


@login_required(login_url="login")
def myfiles(request):
    """
        Homepage for authenticated users
        Shows the list of uploaded files

    """
    ctxt = dict()
    ctxt["title"] = "My files"
    tpl = "website/myfiles.html"
    ctxt["files"] = File.objects.all().filter(owner=request.user)
    return render(request, tpl, ctxt)


@csrf_exempt
def upload(request):
    """
        Handle the file upload
        (first version one file handled)

    """
    context = {}
    tpl = "website/upload.html"

    context["title"] = "Upload"

    if request.method == "GET":
        context["form"] = UploadFileForm(request.POST, request.FILES, label_suffix='', set_default=True)
        return render(request, tpl, context)
    elif request.method == "POST":
        files, file_names = get_files_from_req(request)
        # Upload file (either a single one or the ZIP containing all uploaded files)
        form = UploadFileForm(request.POST, files, label_suffix='', user=request.user)
        if form.is_valid(request.user):
            f = form.save(request.user, file_names)
            url = request.build_absolute_uri(location='dl/{}'.format(f.id))
            return HttpResponse(url + "\n")
        else:
            return HttpResponse("ERROR")
    raise Http404


def size_available(request):
    if request.user.is_anonymous:
        return HttpResponse(settings.FILE_MAX_SIZE_ANONYMOUS)
    else:
        return HttpResponse(FSUser.objects.get(user=request.user).storage_left)

