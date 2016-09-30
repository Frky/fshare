import hashlib
import sha3
import mimetypes
import json

from django.shortcuts import render, HttpResponse, get_object_or_404
from django.contrib.auth.decorators import login_required 
from django.core.urlresolvers import reverse
from django.utils.encoding import smart_str
from django.views.decorators.csrf import csrf_exempt

from website.models import File
from website.encryption import decrypt_file, decrypt_filename

def download(request, fid):
    """
        View of a file for download. If the file is protected, 
        no information is displayed about the file until the password
        has been entered.

    """
    ctxt = dict()
    ctxt["title"] = "Upload"
    tpl = "website/download.html"
    # Check password
    ok, val = check_pwd(request, fid, reverse('download', kwargs={ 'fid': fid}))
    if not ok:
        return val
    # Get the file description
    f = get_object_or_404(File, id=fid)
    # At this point, either the file is public or 
    # the correct password was provided
    if f.key is not None:
        # Set the password in context to pass it to get_file
        # view through GET parameter
        ctxt["key"] = val
        try:
            # Decrypt file name
            ctxt["fname"] = decrypt_filename(f.title, val, f.iv)
            # Decrypt file list
            ctxt["flist"] = json.loads(decrypt_filename(f.file_list, val, f.iv).decode("utf-8"))
        except Exception as e:
            print(e)
            ctxt["fname"] = f.title
            ctxt["flist"] = list()
    else:
        ctxt["fname"] = f.title
        ctxt["flist"] = json.loads(f.file_list)
    # If only one file (not an archive), remove flist
    if len(ctxt["flist"]) == 1 and ctxt["flist"][0] == ctxt["fname"].decode("utf-8"):
        ctxt["flist"] = None
    else:
        # Sort the list of files
        ctxt["flist"] = sorted(ctxt["flist"])
    # Set file meta in context
    ctxt["f"] = f
    return render(request, tpl, ctxt)


def get(request, fid):
    """
        Handle file download. @param fid is the id of the file to
        be downloaded. If the file is protected, the password given 
        as POST or GET parameter is checked before returning the file.

    """
    # Check password
    ok, val = check_pwd(request, fid, reverse('get', kwargs={ 'fid': fid}))
    if not ok:
        return val
    # Get file description
    f = File.objects.get(id=fid)
    # Increase number of downloads
    f.nb_dl += 1
    f.save()
    # Send file
    content = ""
    if f.iv is not None:
        content = decrypt_file(f, request.GET["key"])
        try:
            # Decrypt filename
            fname = decrypt_filename(f.title, val, f.iv)
        except Exception:
            fname = f.title
    else:
        fname = f.title
        with open(f.path, 'rb+') as fl:
            content = fl.read()
    response = HttpResponse(content_type=mimetypes.guess_type(f.title)[0], content=content.read(f.size))
    response['Content-Disposition'] = 'attachment; filename="%s"' % smart_str(fname)
    response['Content-Length'] = f.size
    response.set_cookie(key="fileReady", value=1, path="/dl")
    # If the file has reached the max number of dl
    # (reminder: max_dl set to 0 means no limit)
    if f.nb_dl >= f.max_dl and f.max_dl > 0:
        # We delete it
        f.delete()
    return response


#TODO (WIP)
@login_required(login_url="login")
def update(request, fid):
    """
        Update file content (iif key is None and user is owner)

    """
    # First, get the file from POST data
    files, file_names = get_files_from_req(request)
    f = get_object_or_404(File, id=fid)
    if req.user != f.owner:
        return HttpResponse("KO")
    form = UploadFileForm(request.POST, files, label_suffix='')
    form.save(request.user, file_names, f.id)
    return HttpResponse("OK")

    
@login_required(login_url="login")
def delete(request, fid):
    """
        Delete a file.
        This view performs the permission verifications.

    """
    # Get the file description
    f = get_object_or_404(File, id=fid)
    if f.owner != request.user:
        return HttpResponse("KO")
    f.delete()
    # Response 
    return HttpResponse("OK")


def check_pwd(request, fid, target):
    """
        Check if the file is protected by a key.
        If yes, check the password and redirect 
        to the password template if wrong.

    """
    # Get the file description
    f = get_object_or_404(File, id=fid)
    # If it is protected by a password
    if f.key is not None:
        # Try to get the password from GET
        if "key" in request.GET.keys():
            pwd = request.GET["key"]
        # Try to get the password from POST
        elif "key" in request.POST.keys():
            pwd = request.POST["key"]
        # If no password provided, return password view
        else:
            ctxt = dict()
            ctxt["target"] = target
            return (False, render(request, "website/enter_pwd.html", ctxt))
        # If the password is not correct, return an error
        if hashlib.sha3_512(pwd.encode("utf-8")).hexdigest() != f.key:
            ctxt = dict()
            ctxt["target"] = reverse('download', kwargs={ 'fid': fid})
            ctxt["wrong_pwd"] = True
            return (False, render(request, "website/enter_pwd.html", ctxt))
        return (True, pwd)
    return (True, "")


@csrf_exempt
def get_name(request, fid):
    """
        Return the clear name of the file 

    """
    # Get the file
    f = get_object_or_404(File, id=fid)
    # Get the key from parameter
    if "key" in request.POST.keys():
        key = request.POST["key"]
    elif "key" in request.GET.keys():
        key = request.GET["key"]
    else:
        return HttpResponse("")

    ok, val = check_pwd(request, fid, reverse('download', kwargs={ 'fid': fid}))
    if ok:
        return HttpResponse(decrypt_filename(f.title, key, f.iv))
    else:
        return HttpResponse("")

