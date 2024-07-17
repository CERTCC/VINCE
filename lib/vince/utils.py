import inspect
import pathlib
import mimetypes
import uuid
import re

# Utilities for VINCE to use that are generic


def get_ip(request):
    """GET IP address of a request object and find it using simple
    method of the first X-Forwarded-For header IP from proxy/web server
    or the REMOTE_ADDR environment setup by the appserver. Returns a
    string not an IP validated item/object.
    """
    try:
        if request.META.get("HTTP_X_FORWARDED_FOR"):
            return request.META.get("HTTP_X_FORWARDED_FOR").split(",")[0]
        elif request.META.get("REMOTE_ADDR"):
            return request.META.get("REMOTE_ADDR")
        else:
            return "Unknown"
    except Exception as e:
        return f"IP lookup Exception {e}"
    return "Unknown"


def deepGet(obj, idir):
    """Given an object of any kind find if it is a dictionary
    or a list or an abstract object or instance of a class
    that has a burried element.
    """
    x = obj
    for s in idir.split("."):
        if not x:
            return None
        if isinstance(x, dict) and s in x:
            x = x[s]
        elif isinstance(x, list) and s.isdigit() and int(s) < len(x):
            x = x[int(s)]
        elif hasattr(x, s):
            x = getattr(x, s)
            if callable(x) and not inspect.isclass(x):
                x = x()
        else:
            return None
    return x


def safe_filename(filename, file_uuid=str(uuid.uuid4()), mime_type="application/octet-stream"):
    filename = filename.replace("\r", " ").replace("\n", " ").strip()
    if re.search(r"[^\x00-\x7F]+", filename):
        # non-ascii filenames use uuid and extension
        if file_uuid == None:
            file_uuid = uuid.uuid4()
        file_extension = "".join(pathlib.Path(filename).suffixes)
        if file_extension:
            filename = file_uuid + file_extension
        elif mimetypes.guess_extension(mime_type):
            filename = file_uuid + mimetypes.guess_extension(mime_type)
        else:
            filename = file_uuid
    return filename


def is_uuid(inuuid):
    try:
        return uuid.UUID(inuuid)
    except Exception as e:
        return None
