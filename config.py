# Create dummy secrey key so we can use sessions
SECRET_KEY = 'ahieph3VeiXooz2uwee3keesiequeeke'

SERVER_NAME = "python.math-hse.info"

# Create in-memory database
DATABASE_FILE = '/Users/user/prj/nbgr-x/sample_db.sqlite'
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
# SECURITY_CONFIRMABLE = True
SECURITY_SEND_REGISTER_EMAIL = True

NBGRX_PREFIX = "/Users/user/prj/nbgr-x"

ASSIGNMENTS_PROCESS_DIR = NBGRX_PREFIX+'/data/assignments_process'
# contains <course_name>/gradebook.db
IPYNB_PREVIEW_PREFIX = ("http://nbviewer.jupyter.org/url/")
ASSIGNMENTS_URL_PREVIEW_PREFIX = (IPYNB_PREVIEW_PREFIX +
                                  "python.math-hse.info/static/"
                                  "assignments_release")
ASSIGNMENTS_URL_PREFIX = ("http://python.math-hse.info/static/"
                          "assignments_release")
ASSIGNMENTS_RELEASE_DIR = NBGRX_PREFIX+'/static/assignments_release'
SUBMISSIONS_DIR = NBGRX_PREFIX+"/data/submissions"
BACKUP_DIR = NBGRX_PREFIX+"/data/backup"

MAC_OS = False
# So we need additional things to do with docker

IPYNB_LINK_TEMPLATE = \
    "{url_prefix}/{course_name}/{assignment}/{ipynb_filename}"
#IPYNB_LINK_TEMPLATE = ""

# Local only
DEBUG = True

CELERY_BROKER_URL = 'amqp://guest:quaizahPhee7OhTh2wahbooshailee@localhost:5672//'

GRADING_TIMEOUT = 3 * 60
