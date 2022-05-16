from website.models import FSUser


def storage(request):
    """
        Add storage space relative information to context:
        - limit of storage space as defined by the permission class
            of the user
        - free storage left

    """
    ctxt = dict()
    if not request.user.is_authenticated or request.user.is_anonymous:
        return ctxt
    ctxt["storage_limit"] = FSUser.objects.get(user=request.user).storage_limit
    ctxt["storage_left"] = FSUser.objects.get(user=request.user).storage_left
    ctxt["storage_percent"] = FSUser.objects.get(user=request.user).storage_percent
    #TODO add free space left
    return ctxt


def permission(request):
    """
        Add a flag relative to user permission (admin or not).
        This flag is used to show (or not) link to cockpit in nav bar

    """
    ctxt = dict()
    if not request.user.is_authenticated or request.user.is_anonymous:
        ctxt["is_admin"] = False
    else:
        ctxt["is_admin"] = (FSUser.objects.get(user=request.user).permission.name == "admin")
    return ctxt
