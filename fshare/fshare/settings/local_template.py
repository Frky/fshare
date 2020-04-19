
from fshare.settings.base import *

# TODO set a good secret key here
SECRET_KEY = 'secret_key'

###
#   FSHARE custom settings
###
CONTACT = ''                    # email contact (displayed on home page)
MEDIA_ROOT = ''                 # directory where to store uploaded files
# settings for anonymous users
UPLOAD_DIRECTORY_ANONYMOUS = '/tmp'     # directory where to store uploaded files for anonymous users
FILE_MAX_SIZE_ANONYMOUS = 200 * 2**20   # 200 MB
FILE_MAX_DAYS_ANONYMOUS = 7
FILE_MAX_DL_ANONYMOUS = 1

###
#   FSHARE database settings
###
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db/fshare.sqlite3'),
    },  
}

###
#   Misc.
###
# TODO Change for production
DEBUG = True
