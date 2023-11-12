import hashlib
import mimetypes
import json
from io import BytesIO
from zipfile import ZipFile

from django.shortcuts import render, HttpResponse, get_object_or_404
from django.contrib.auth.decorators import login_required 
from django.core.files.uploadedfile import SimpleUploadedFile, InMemoryUploadedFile
from django.urls import reverse
from django.utils.datastructures import MultiValueDict
from django.utils.encoding import smart_str
from django.views.decorators.csrf import csrf_exempt

from website.expiration import compute_ttl
from website.models import File
from website.forms import UploadFileForm
from website.utils import generate_random_name


def get_files_from_req(request):
    files = MultiValueDict()
    # If more than one file was uploaded
    if len(request.FILES.keys()) > 1:
        # Create a list containing all file names
        file_names = list()
        # Create a memory IO file
        in_mem = BytesIO()
        # Create a ZIP object in memory
        zipped = ZipFile(in_mem, "w")
        # Iteration over files
        for f in request.FILES.values():
            # Read content
            content = f.read()
            # Add it to ZIP archive
            zipped.writestr(f.name, content)
            file_names.append(f.name)
        # Close ZIP archive
        zipped.close()
        # Seek to beginning of the ZIP file 
        in_mem.seek(0)
        # Get ZIP size
        zip_size = len(in_mem.read())
        # Seek to beginning again
        in_mem.seek(0)
        # Create a InMemory ZIP file
        zip_file = InMemoryUploadedFile(
                                            in_mem, 
                                            None, 
                                            "FShare - {0}.zip".format(generate_random_name(10)), 
                                            "application/zip", 
                                            zip_size, 
                                            None, 
                                            None
                                        )
        files["file"] = zip_file
    else:
        # If only one file, zipped_files contains the 
        # unique file and file_names contains the name
        # of the file
        if "file[0]" in request.FILES.keys():
            files["file"] = request.FILES["file[0]"]
            file_names = [request.FILES["file[0]"].name]
        elif "file[]" in request.FILES.keys():
            files["file"] = request.FILES["file[]"]
            file_names = [request.FILES["file[]"].name]
    return files, file_names


def download(request, fid):
    """
        View of a file for download. If the file is protected, 
        no information is displayed about the file until the password
        has been entered.

    """
    ctxt = dict()
    ctxt["title"] = "Download"
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
            ctxt["fname"] = f.get_name(val)
            # Decrypt file list
            ctxt["flist"] = f.get_list(val)
        except KeyError as e:
            ctxt["fname"] = f.title
            ctxt["flist"] = list()
    else:
        ctxt["fname"] = f.title
        ctxt["flist"] = json.loads(f.file_list)
    # If only one file (not an archive), remove flist
    if len(ctxt["flist"]) == 1 and ctxt["flist"][0] == ctxt["fname"]:
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
    key = request.GET["key"]
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
        content = f.get_content(key)
        try:
            # Decrypt filename
            fname = f.get_name(key)
        except Exception:
            fname = f.title
    else:
        fname = f.title
        content = open(f.path, 'rb+')
    response = HttpResponse(content_type=mimetypes.guess_type(fname)[0], content=content.read(f.size))
    response['Content-Disposition'] = 'attachment; filename="%s"' % smart_str(fname)
    response['Content-Encoding'] = "None"
    response['Content-Length'] = f.size
    response.set_cookie(key="fileReady", value=1, path="/dl")
    # If the file has reached the max number of dl
    # (reminder: max_dl set to 0 means no limit)
    """
    if f.nb_dl >= f.max_dl and f.max_dl > 0:
        # We delete it
        f.delete()
        """
    return response


@login_required(login_url="login")
def update(request, fid):
    """
        Update file content 

    """
    # First, get the file from POST data
    files, file_names = get_files_from_req(request)
    f = get_object_or_404(File, id=fid)
    if request.user != f.owner:
        return HttpResponse("KO")
    post = {
        'max_dl': f.max_dl,
        'expiration_date': compute_ttl(f.expiration_date),
        'key': f.real_key,
    }
    form = UploadFileForm(
            post,
            files, 
            label_suffix='', 
            user=request.user, 
                )
    if form.is_valid(request.user):
        form.save(request.user, file_names, f.id)
        return HttpResponse("OK")
    else:
        return HttpResponse("KO")

    
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
    if ok or not ok:
        return HttpResponse(f.get_name(key))
    else:
        return HttpResponse("")

