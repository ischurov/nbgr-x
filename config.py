# Create dummy secrey key so we can use sessions
SECRET_KEY = 'ahieph3VeiXooz2uwee3keesiequeeke'

# Create in-memory database
DATABASE_FILE = 'sample_db.sqlite'
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + DATABASE_FILE
SQLALCHEMY_ECHO = False

# Flask-Security config
SECURITY_URL_PREFIX = "/admin"
SECURITY_PASSWORD_HASH = "pbkdf2_sha512"
SECURITY_PASSWORD_SALT = "Faiqu0ohsaecii4ahquooPiwieB8geif"

# Flask-Security URLs, overridden because they don't put a / at the end
SECURITY_LOGIN_URL = "/login/"
SECURITY_LOGOUT_URL = "/logout/"
SECURITY_REGISTER_URL = "/register/"

SECURITY_POST_LOGIN_VIEW = "/"
SECURITY_POST_LOGOUT_VIEW = "/"
SECURITY_POST_REGISTER_VIEW = "/"

# Flask-Security features
SECURITY_REGISTERABLE = True
SECURITY_SEND_REGISTER_EMAIL = False

NBGRX_PREFIX = "/srv/nbgr-x"

ASSIGNMENTS_PROCESS_DIR = NBGRX_PREFIX+'/data/assignments_process'
# contains <course_name>/gradebook.db

ASSIGNMENTS_URL_PREFIX = "http://nbviewer.ipython.org/url/python.math-hse.info/static/assignments_release"
ASSIGNMENTS_RELEASE_DIR = NBGRX_PREFIX+'/static/assignments_release'
SUBMISSIONS_DIR = NBGRX_PREFIX+"/data/submissions"
BACKUP_DIR = NBGRX_PREFIX+"/data/backup"

MAC_OS = False
# So we need additional things to do with docker

IPYNB_LINK_TEMPLATE = "{url_prefix}/{course_name}/{ipynb_filename}"

# Local only
DEBUG = True
