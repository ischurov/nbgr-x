import os
from flask import (Flask, render_template, url_for, request, abort,
    redirect, Response, send_from_directory, jsonify)
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.security import (Security, SQLAlchemyUserDatastore,
                                UserMixin, RoleMixin, login_required,
                                current_user, roles_required)
from flask_security.utils import encrypt_password
from flask_mail import Mail
from flask_admin.contrib import sqla
from flask_admin import helpers as admin_helpers
from wtforms import DateTimeField
import flask_admin
from flask_security.forms import RegisterForm
from flask_wtf import Form
from wtforms import (BooleanField, StringField, TextAreaField, validators,
                     SelectField, TextAreaField, FieldList, FormField)
from wtforms.ext.sqlalchemy.fields import QuerySelectMultipleField, QuerySelectField
from flask_bootstrap import Bootstrap
from flask.ext.bower import Bower
from werkzeug import secure_filename
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms_components import read_only
from datetime import datetime
from sqlalchemy import desc
import json

import subprocess
import shutil
import re

from operator import attrgetter

import json

# from itertools import chain
# Create app

from celery import Celery

def make_celery(app):
    celery = Celery(app.import_name, broker=app.config['CELERY_BROKER_URL'])
    celery.conf.update(app.config)
    TaskBase = celery.Task
    class ContextTask(TaskBase):
        abstract = True
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return TaskBase.__call__(self, *args, **kwargs)
    celery.Task = ContextTask
    return celery


app = Flask(__name__)
MYPATH = os.path.dirname(os.path.realpath(__file__))
app.config.from_pyfile('config.py')
app.config.update(dict(
    MYPATH=MYPATH,
    PYTHON=os.path.join(MYPATH, "env", "bin", "python"),
    NBGRADER=os.path.join(MYPATH, "env", "bin", "nbgrader")))


celery = make_celery(app)

Bootstrap(app)
Bower(app)
# app.config['SECRET_KEY'] = 'secret'
# app.config['SQLALCHEMY_DATABASE_URI'] = \
#        'sqlite:////srv/data/nbgr-x/2015-16/students.sqlite'

# 'SECURITY_CONFIRMABLE',
# for field in ['SECURITY_REGISTERABLE','SECURITY_RECOVERABLE', 'SECURITY_LOGIN_WITHOUT_CONFIRMATION']:
#    app.config[field] = True

# After 'Create app'
# app.config['MAIL_TESTING'] = True
# app.config['MAIL_SERVER'] = 'smtp.example.com'
# app.config['MAIL_PORT'] = 465
# app.config['MAIL_USE_SSL'] = True
# app.config['MAIL_USERNAME'] = 'username'
# app.config['MAIL_PASSWORD'] = 'password'

mail = Mail(app)

# Create database connection object
db = SQLAlchemy(app)

# Define models
roles_users = db.Table('roles_users',
                       db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
                       db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

courses_users = db.Table('courses_users',
                         db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
                         db.Column('course_id', db.Integer(), db.ForeignKey('course.id')))



class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

    def __str__(self):
        return self.name


class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    active = db.Column(db.Boolean())
    year_begin = db.Column(db.Integer)
    name = db.Column(db.String(255), unique=True)
    description = db.Column(db.String(255))
    assignments = db.relationship('Assignment', backref='course',
                                  lazy='dynamic')
    peer_review_assignments = db.relationship('PeerReviewAssignment',
                                              backref='course',
                                              lazy='dynamic')

    def __str__(self):
        return self.name

    def assignments_process_dir(self):
        """
        This is 'course_id' folder in terms of nbgrader

        Here located:
        - gradebook
        - source assignments
        - released assignments

        :return: path
        """
        return os.path.join(app.config['ASSIGNMENTS_PROCESS_DIR'],
                            secure_filename(self.name))

    def assignments_release_dir(self):
        return os.path.join(app.config['ASSIGNMENTS_RELEASE_DIR'],
                            secure_filename(self.name))


    def assignments_process_jail(self):
        """
        this is jail where submission files are placed

        pathes is like

        assignments_process_jail/submission_id/submitted

        have to be mounted to

        course_id/submitted

        :return: path
        """
        return os.path.join(app.config['ASSIGNMENTS_PROCESS_DIR'],
                            'jail',
                            secure_filename(self.name))


    def gradebook_file(self):
        return os.path.join(
            self.assignments_process_dir(),
            "gradebook.db"
        )

    def backup_gradebook(self):
        backup_dir = os.path.join(
            app.config('BACKUP_DIR'),
            "gradebooks",
            secure_filename(self.name)
        )
        make_sure_path_exists(backup_dir)
        shutil.copyfile(
            self.gradebook_file(),
            os.path.join(
                backup_dir,
                datetime.today().isoformat()+".db"
            )
        )



class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, index=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    first_name = db.Column(db.String(255))
    last_name = db.Column(db.String(255))

    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))
    courses = db.relationship('Course', secondary=courses_users,
                              backref=db.backref('users', lazy='dynamic'))
    submissions = db.relationship('Submission', backref=db.backref('user'), lazy='dynamic')
    peer_review_submissions = db.relationship('PeerReviewSubmission',
                                              backref=db.backref('user'),
                                              lazy='dynamic')
    peer_review_reviews = db.relationship('PeerReviewReview',
                                          backref=db.backref('user'),
                                          lazy='dynamic')
    peer_review_review_requests = db.relationship(
        'PeerReviewReviewRequest', backref=db.backref('reviewer'),
        lazy='dynamic')



    def __str__(self):
        return "user"+str(self.id)


def try_and_save(file_obj, dir_name, filename):
    """
    Saves a file from a flask-wtform.filefield to a
    specified dir under specified filename
    If the dir does not exists, creates it

    :param file_obj: form.file.data to be .save()'ed
    :param dir_name: directory to save (created if not exists)
    :param filename: filename to save the file
    :return: os.path.join(dir, filename)
    """
    full_name = os.path.join(dir_name, filename)

    try:
        file_obj.save(full_name)
    except IOError as e:
        if e.errno == 2:
            make_sure_path_exists(dir_name)
            file_obj.save(full_name)
        else:
            raise
    return full_name

def get_message(user):
    try:
        with open(os.path.join(app.config['MYPATH'],
                               "messages.json")) as f:
            messages = json.load(f)
    except IOError:
        messages = {}
    return messages.get(user.email)

class Assignment(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    active = db.Column(db.Boolean())
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'))
    deadline = db.Column(db.DateTime)
    name = db.Column(db.String(255))
    description = db.Column(db.String(255))
    submissions = db.relationship('Submission', backref='assignment',
                                  lazy='dynamic')

    def __str__(self):
        return self.name

    def ipynb_link(self, preview=False):
        if preview:
            prefix = app.config['ASSIGNMENTS_URL_PREVIEW_PREFIX']
        else:
            prefix = app.config['ASSIGNMENTS_URL_PREFIX']
        return app.config['IPYNB_LINK_TEMPLATE'].format(
            url_prefix=prefix,
            ipynb_filename=self.ipynb_filename(),
            assignment=secure_filename(self.name),
            course_name=secure_filename(self.course.name),
        )

    def ipynb_process_dir(self, step):
        """
        Returns a path to assignment's dir (before or after processing)
        Note that 'release' here means internal release directory
        For world-readable 'release' directory,
        see ipynb_release_dir()
        :param stage: either 'source' or 'release'
        :return:
        """
        return os.path.join(self.course.assignments_process_dir(),
                            step,
                            secure_filename(self.name))

    def ipynb_release_dir(self):
        """
        Returns a path to the released assignment's dir
        (World-readable)
        :return: str
        """
        return os.path.join(self.course.assignments_release_dir(),
                            secure_filename(self.name))

    def ipynb_filename(self):
        """
        returns filename for ipynb (usually self.name+".ipynb")
        :return: str
        """
        return secure_filename(self.name + ".ipynb")


    def save_ipynb(self, ipynb_file):
        """
        Saves an assignment from the form
        :param ipynb_file: form.file.data-style ipynb-file
        :return: the full name of the ipynb-file
        """
        ipynb_filename = self.ipynb_filename()
        ipynb_dir = self.ipynb_process_dir('source')

        return try_and_save(ipynb_file, ipynb_dir, ipynb_filename)

    def process_ipynb(self, update = False, logfile = None, codestub="# YOUR CODE HERE"):
        """
        Processes assignment nb with nbgrader assign
        :param update: update already processed file (gives --force
        flag instead of --create)
        :param codestub: code stub string
        :return: nothing
        """
        os.chdir(self.course.assignments_process_dir())
        if update:
            mode = '--force'
        else:
            mode = '--create'

        command = [app.config['PYTHON'],
                         app.config['NBGRADER'],
                         "assign",
                         secure_filename(self.name),
                         mode,
                        '--ClearSolutions.code_stub="%s"' %
                         codestub]

        if logfile:
            log = open(logfile, "a")
            log.write(datetime.today().isoformat()+"\n")
            log.write(" ".join(command) + "\n\n")
        else:
            log = None

        subprocess.call(command,
                        stderr=log)
        if logfile:
            log.close()

        make_sure_path_exists(self.ipynb_release_dir())
        shutil.copyfile(
            os.path.join(
                self.ipynb_process_dir('release'),
                self.ipynb_filename()
            ),
            os.path.join(
                self.ipynb_release_dir(),
                self.ipynb_filename()
            )
        )



class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    assignment_id = db.Column(db.Integer, db.ForeignKey('assignment.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    timestamp = db.Column(db.DateTime())
    autograded_status = db.Column(db.String(32))
    autograded_log = db.Column(db.String(256))


    def __str__(self):
        return "submission{}".format(self.id)

    def dirpath(self):
        return os.path.join(app.config['SUBMISSIONS_DIR'],
                            secure_filename(self.assignment.course.name),
                            "submitted",
                            str(self.user_id),
                            secure_filename(self.assignment.name)
                            )

    def filename(self):
        return self.timestamp.isoformat()+".ipynb"

    def fullfilename(self):
        return os.path.join(self.dirpath(), self.filename())

    def process_root(self, step=None):
        """
        This is a path to directory in jail where submission processing is made.

        Example:

            {APD}/jail/{course_id}/{submission_id}/step

        Have to be mounted to course_id/step in docker

        If step is not presented, it's like ''

        :param step: nbgrader step
        :return: path
        """

        assignment = self.assignment
        course = assignment.course

        parts = [
            course.assignments_process_jail(), # {course_directory}
            str(self), # hack to process different assignments concurently
        ]
        if step:
            parts.append(step)
        root = os.path.join(*parts)
        return root

    def process_dir(self, step):
        """
        Returns individual process dir path to the submission like the following

        {APD}/jail/{course_id}/{submission_id}/step/{student_id}/{assignment_id}

        :param step: nbgrader step (like 'submitted', 'autograded', 'feedback')
        :return: path
        """
        user = self.user
        assignment = self.assignment

        submission_process_dir = os.path.join(
            self.process_root(step),
            str(user), # {student_id}
            secure_filename(assignment.name) # {assignment_id}
        )
        return submission_process_dir

    def feedback_file(self):
        return os.path.join(
            self.process_dir('feedback'),
            self.assignment.ipynb_filename().replace(".ipynb", ".html"))

# Peer Review

class PeerReviewAssignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    active = db.Column(db.Boolean())
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'))
    deadline = db.Column(db.DateTime)
    name = db.Column(db.String(255))
    description = db.Column(db.String(255))
    url = db.Column(db.String(255))

    submissions = db.relationship('PeerReviewSubmission',
                                  backref='assignment',
                                  lazy='dynamic')

    grading_criteria = db.relationship(
        'PeerReviewGradingCriterion',
        backref='assignment',
        lazy='dynamic')


    def __str__(self):
        return self.name

class PeerReviewSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    assignment_id = db.Column(db.Integer, db.ForeignKey(
        'peer_review_assignment.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    timestamp = db.Column(db.DateTime())
    reviews = db.relationship('PeerReviewReview',
                              backref='submission',
                              lazy='dynamic')
    review_requests = db.relationship('PeerReviewReviewRequest',
                                      backref='submission',
                                      lazy='dynamic')

    work = db.Column(db.String(255))
    comment_for_reviewer = db.Column(db.String(255))

    def __str__(self):
        return "peer_review_submission"+str(self.id)


class PeerReviewGradingCriterion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    assignment_id = db.Column(db.Integer, db.ForeignKey(
        'peer_review_assignment.id'))
    sort_index = db.Column(db.Integer)
    name = db.Column(db.String(255))
    description = db.Column(db.String(255))
    minimum = db.Column(db.Integer)
    maximum = db.Column(db.Integer)
    need_comment = db.Column(db.Boolean())
    review_items = db.relationship('PeerReviewReviewItem',
                              backref='PeerReviewGradingCriterion',
                              lazy='dynamic')

    def __str__(self):
        return self.name

class PeerReviewReview(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    submission_id = db.Column(db.Integer,
                              db.ForeignKey('peer_review_submission.id'))
    user_id = db.Column(db.Integer,
                        db.ForeignKey('user.id'))
    items = db.relationship('PeerReviewReviewItem',
                            backref='peer_review_review',
                            lazy='dynamic')

    review_requests = db.relationship('PeerReviewReviewRequest',
                                      backref='peer_review_review',
                                      lazy='dynamic')


    timestamp = db.Column(db.DateTime())

    def __str__(self):
        return "peer_review_review" + str(self.id)

class PeerReviewReviewItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    criterion_id = db.Column(db.Integer,
                             db.ForeignKey(
                                 "peer_review_grading_criterion.id"))
    review_id = db.Column(db.Integer,
                          db.ForeignKey("peer_review_review.id"))
    grade = db.Column(db.Integer)
    comment = db.Column(db.String(256))

    def __str__(self):
        return "peer_review_grade_item" + str(self.id)

class PeerReviewReviewRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reviewer_id = db.Column(db.Integer,
                            db.ForeignKey("user.id"))
    submission_id = db.Column(db.Integer,
                              db.ForeignKey("peer_review_submission.id"))
    review_id = db.Column(db.Integer,
                         db.ForeignKey("peer_review_review.id"))


# Setup Flask-Security

class ExtendedRegisterForm(RegisterForm):

    first_name = StringField('First Name', [validators.DataRequired()])
    last_name = StringField('Last Name', [validators.DataRequired()])
    #    active_courses = Course.query.filter_by(active = True).all()
    #    courses_choices = [(c.id, c.description) for c in active_courses]
    courses = QuerySelectMultipleField(
        'Courses',
        [validators.DataRequired()],
        query_factory=lambda: Course.query.filter_by(active=True),
        get_label='description')


user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore,
                    confirm_register_form=ExtendedRegisterForm,
                    register_form=ExtendedRegisterForm)

class MyModelView(sqla.ModelView):
    def is_accessible(self):
        if (not current_user.is_active() or
                not current_user.is_authenticated()):
            return False

        if current_user.has_role('superuser'):
            return True

        return False

    def _handle_view(self, name, **kwargs):
        """
        Override builtin _handle_view in order to redirect users
        when a view is not accessible.
        """
        if not self.is_accessible():
            if current_user.is_authenticated():
                # permission denied
                abort(403)
            else:
                # login
                return redirect(url_for('security.login',
                                        next=request.url))


@celery.task()
def autograde(submission_id):
    """
    Autogrades submission with given submission_id
    in the background

    :param submission_id: submission.id
    :return: None
    """

    submission = Submission.query.get(submission_id)

    submission.autograded_status = 'processing'
    db.session.commit()

    user = submission.user
    assignment = submission.assignment
    course = assignment.course

    steps =  ['submitted', 'autograded', 'feedback']
    for step in steps:
        make_sure_path_exists(submission.process_dir(step))

    ipynb_filename = os.path.join(
            submission.process_dir('submitted'),
            assignment.ipynb_filename()
    )

    shutil.copyfile(submission.fullfilename(), ipynb_filename)

    # FIX kernel name
    # Workaround for
    # https://github.com/Anaconda-Platform/nb_conda_kernels/issues/34

    with open(ipynb_filename) as fp:
        ipynb = json.load(fp)

    if ipynb['metadata']['kernelspec']['name'] != 'python3':
        ipynb['metadata']['kernelspec']['name'] = 'python3'
        with open(ipynb_filename, 'w') as fp:
            json.dump(ipynb, fp)

    # END FIX


    ts_format = "%Y-%m-%d %H:%M:%S %Z"

    with open(os.path.join(submission.process_dir('submitted'),
                           "timestamp.txt"), "w") as f:
        f.write(submission.timestamp.strftime(ts_format))

    shutil.copyfile(os.path.join(course.assignments_process_dir(),
        "gradebook.db"), os.path.join(submission.process_root(),
                                      "gradebook.db"))

    mountpoints = ['-v', submission.process_root()+":/assignments/"]
    for step in steps:
        make_sure_path_exists(submission.process_dir(step))

    env = os.environ
    if app.config['MAC_OS']:
        env_str = subprocess.check_output(
            ['bash', '-c', 'docker-machine env default'])
        for line in env_str.splitlines():
            m = re.match(r'export\s+(\w+)="([^"]+)"', line)
            if m:
                key = m.group(1)
                value = m.group(2)

                env[key] = value
                print "DEBUG: %s => %s" % (key, value)

    try:
        command = ['sudo',
            'docker', 'run', '--rm'] + mountpoints + [
            "jupyter/nbgrader",
            "autograde",
            secure_filename(assignment.name),
            "--student",
            str(user),
            "--create",
            '--force'
        ]

        print "DEBUG: " + " ".join(command)

        submission.autograded_log = subprocess.check_output(
            command, stderr=subprocess.STDOUT, env=env)

        submission.autograded_status = 'autograded'

        # TODO: we need better processing of this
        # timeout scenario (hanged kernel)

        if "Timeout waiting for IOPub output" in submission.autograded_log:
            submission.autograded_status = 'timeout'
        else:
            try:
                command = ['sudo',
                    'docker', 'run', '--rm'] + mountpoints + [
                    "jupyter/nbgrader",
                    "feedback",
                    secure_filename(assignment.name),
                    "--student",
                    str(user),
                    '--force'
                ]

                print "DEBUG: " + " ".join(command)

                subprocess.check_output(
                    command, stderr=subprocess.STDOUT, env=env)

            except subprocess.CalledProcessError as error:
                submission.autograded_status = 'error_on_feedback'
                submission.autograded_log = error.output

    except subprocess.CalledProcessError as error:
        submission.autograded_log = error.output
        submission.autograded_status = 'failed'



    db.session.commit()

@app.route("/assets/<path:path>")
def send_asset(path):
    return send_from_directory(os.path.join(MYPATH, 'assets'), path)

@login_required
@roles_required(['superuser'])
@app.route("/_auto_grade/<id>")
def do_pseudo_grade(id):
    submission = Submission.query.get_or_404(id)
    autograde.delay(submission.id)
    return redirect(url_for('get_feedback',
                            id=submission.id))

@login_required
@roles_required(['superuser'])
@app.route("/gradebook/<course_id>")
def show_gradebook(course_id):
    course = Course.query.get_or_404(course_id)
    assignments = course.assignments
    users = course.users.\
        order_by(User.last_name).\
        order_by(User.first_name)

    grades = {}
    for user in users:

        current_grades = {}
        grades[user.id] = current_grades

        for assignment in assignments:
            submission = user.submissions.\
                filter_by(assignment=assignment).\
                filter_by(autograded_status='autograded').\
                order_by(desc(Submission.id)).first()


            current_grades[assignment.id] = get_grade(submission)

    return render_template("gradebook.html",
                           assignments=assignments,
                           users=users,
                           grades=grades)

#THIS FUNCTION IS FOR DEBUG ONLY
#SHOULD BE REMOVED SOON
@login_required
@roles_required(['superuser'])
@app.route("/_gradebook/<course_id>")
def show_last_subm(course_id):
    course = Course.query.get_or_404(course_id)
    assignments = course.assignments
    users = course.users.\
        order_by(User.last_name).\
        order_by(User.first_name)

    grades = {}
    for user in users:

        current_grades = {}
        grades[user.id] = current_grades

        for assignment in assignments:
            submission = user.submissions.\
                filter_by(assignment=assignment).\
                order_by(desc(Submission.id)).first()


            current_grades[assignment.id] = submission

    return render_template("gradebook.html",
                           assignments=assignments,
                           users=users,
                           grades=grades)

def get_grade(submission):
    if submission is None:
        return
    try:
        with open(submission.feedback_file()) as f:
            resp = f.read()
    except IOError:
        return
    for line in resp.splitlines():
        if 'Score' in line:
            m = re.search(r'Score: (\d+\.\d+)', line)
            if not m:
                return
            return float(m.group(1))
    return

# Create a user to test with
# @app.before_first_request
def build_sample_db():
    db.create_all()
    with app.app_context():
        user_role = Role(name='user')
        super_user_role = Role(name='superuser')
        db.session.add(user_role)
        db.session.add(super_user_role)
        db.session.commit()

        user_datastore.create_user(email='admin', password=encrypt_password('admin'),
                                   first_name='Admin', roles=[user_role, super_user_role])

        db.session.commit()


# Views
#@app.route('/')
#@login_required
#def home():
#    return render_template('index.html')


class AssignmentForm(Form):
    active = BooleanField("Active", default=True)
    ipynb_file = FileField("Assignment ipynb file")
    deadline = DateTimeField("Deadline")
    description = StringField("Description")
    course = QuerySelectField(
        query_factory=lambda: Course.query.filter_by(active=True),
        get_label='description')
    name = StringField("Name",
                       validators=[validators.DataRequired()]
                       )


class AddAssignmentForm(AssignmentForm):

    def validate(self):
        rv = Form.validate(self)
        if not rv:
            return False

        assignment = Assignment.query.filter_by(course=self.course.data,
                                                name=self.name.data).first()

        if assignment:
            self.name.errors.append("This name is already used")
            return False

        if self.ipynb_file.data is None:
            self.ipynb_file.errors.append("Please, upload ipynb file")
            return False

        return True


class EditAssignmentForm(AssignmentForm):
    force_create = BooleanField("Recreate assignment", default=False)

    def __init__(self, *args, **kwargs):
        super(AssignmentForm, self).__init__(*args, **kwargs)
        read_only(self.name)
        read_only(self.course)

# FROM http://stackoverflow.com/a/14364249/3025981


def make_sure_path_exists(path):
    try:
        os.makedirs(path)
    except OSError:
        if not os.path.isdir(path):
            raise

# END FROM


@app.route('/add/assignment', methods=["GET", "POST"])
@roles_required('superuser')
def add_assignment():

    form = AddAssignmentForm()

    if request.method == 'POST' and form.validate():

        new_assignment = Assignment()
        form.populate_obj(new_assignment)

        new_assignment.save_ipynb(form.ipynb_file.data)

        new_assignment.process_ipynb(logfile="log.log")

        db.session.add(new_assignment)
        db.session.commit()

        return redirect(url_for('edit_assignment', id=new_assignment.id))

    return render_template('tweak_assignment.html', form=form, mode='add')


@app.route('/edit/assignment/<id>', methods=['GET', 'POST'])
@roles_required('superuser')
def edit_assignment(id):
    assignment = Assignment.query.get_or_404(id)
    form = EditAssignmentForm(obj=assignment)

    if request.method == 'POST' and form.validate():

        del form.course
        del form.name
        # Precaution: `course` and `name` are read-only
        # See http://stackoverflow.com/a/16576294/3025981 for details

        if form.ipynb_file.data:
            assignment.save_ipynb(form.ipynb_file.data)
            assignment.process_ipynb(update=not form.force_create.data,
                                     logfile='log.log')

        form.populate_obj(assignment)
        db.session.commit()
        return redirect(url_for('edit_assignment', id=id))
    return render_template('tweak_assignment.html',
                           form=form,
                           mode='edit',
                           assignment=assignment)

@app.route('/')
@app.route("/list/assignments")
@login_required
def list_assignments():
    submissions = current_user.submissions.all()
    courses = current_user.courses
    mycourses = []
    for course in courses:
        mycourse={'description': course.description,
                  'active': course.active, 'assignments': [],
                  'peer_review_assignments':
                      course.peer_review_assignments.all()}
        for assignment in course.assignments:
            mycourse['assignments'].append({
                'data':assignment,
                'submissions':
                    [s for s in submissions if s.assignment == assignment]
            })

        mycourses.append(mycourse)



    return render_template("list_assignments_ru.html",
                           mycourses=mycourses,
                           message=get_message(current_user))


class SubmitAssignmentForm(Form):
    ipynb_file = FileField("ipynb file",
                           validators=[FileRequired(),
                                       FileAllowed(['ipynb', 'json'],
                                                   'ipynb or json files only')])


@app.route("/submit/assignment/<id>", methods=['GET', 'POST'])
@login_required
def submit_assignment(id):

    assignment = Assignment.query.get_or_404(id)
    form = SubmitAssignmentForm()

    if form.validate_on_submit():

        submission = Submission()
        submission.assignment = assignment
        submission.user = current_user
        submission.timestamp = datetime.today()
        db.session.add(submission)
        db.session.commit()

        try_and_save(form.ipynb_file.data,
                     submission.dirpath(),
                     submission.filename())

        if assignment.deadline and submission.timestamp <= assignment.deadline:
            submission.autograded_status = 'sent-to-grading'
            db.session.commit()
            autograde.delay(submission.id)
        else:
            submission.autograded_status = 'late'
            db.session.commit()

        return redirect(url_for("list_assignments"))

    return render_template("submit_assignment.html",
                           form=form,
                           assignment=assignment)


@app.route("/get/submission_content/<id>")
@login_required
def get_submission_content(id):
    """
    Allows to get submission ipynb file
    for the uploader of this file

    :param id: submission id
    :return:
    """
    submission = Submission.query.get_or_404(id)

    if (current_user != submission.user and
            not current_user.has_role('superuser')):
        abort(403)
    with open(submission.fullfilename()) as f:
        resp = f.read()
    return Response(resp,
                    mimetype="application/json",
                    headers={"Content-disposition": "attachment"})

@app.route("/get/feedback/<id>")
@login_required
def get_feedback(id):
    submission = Submission.query.get_or_404(id)

    if (current_user != submission.user and
            not current_user.has_role('superuser')):
        abort(403)
    with open(submission.feedback_file()) as f:
        resp = f.read()
    return Response(resp,
                    mimetype="text/html")

@app.route("/json/autograded_status/<id>")
@login_required
def json_autograded_status(id):
    submission = Submission.query.get_or_404(id)
    if (current_user != submission.user and
            not current_user.has_role('superuser')):
        abort(403)
    return jsonify(status=submission.autograded_status,
                   log=submission.autograded_log)

class SubmitPeerReviewAssignmentForm(Form):
    work = StringField('Work', [validators.DataRequired()])
    comment_for_reviewer = TextAreaField('Comment to reviewer')

@app.route("/peer_review/submit/assignment/<id>", methods=['GET', 'POST'])
@login_required
def peer_review_submit_assignment(id):
    assignment = PeerReviewAssignment.query.get_or_404(id)
    form = SubmitPeerReviewAssignmentForm()
    if form.validate_on_submit():
        submission = PeerReviewSubmission()
        submission.user=current_user
        submission.assignment_id=assignment.id
        submission.timestamp=datetime.today()
        submission.work=form.work.data
        submission.comment_for_reviewer=form.comment_for_reviewer.data

        db.session.add(submission)
        db.session.commit()
        return redirect(url_for("list_assignments"))
    return render_template("peer_review_submit_assignment.html",
                           form=form,
                           assignment=assignment)

class PeerReviewReviewItemForm(Form):
    grade = SelectField('Grade', coerce=int)
    comment = TextAreaField(
        'Please, explain your grade (visible to the author)')

class PeerReviewReviewForm(Form):
    items = FieldList(FormField(PeerReviewReviewItemForm))

@app.route("/peer_review/submit/review/<id>", methods=['GET', 'POST'])
@login_required
def peer_review_submit_review(id):
    review_request = PeerReviewReviewRequest.query.get_or_404(id)
    if current_user != review_request.reviewer:
        abort(403)
    submission = review_request.submission
    assignment = submission.assignment
    criteria = sorted(assignment.grading_criteria.all(),
                      key=attrgetter('sort_index'))
    form = PeerReviewReviewForm(items=[{} for _ in criteria])
    for criterion, item in zip(criteria, form.items.entries):
        item.grade.choices = [(str(i), str(i)) for i in
                              range(criterion.minimum,
                                    criterion.maximum + 1)]

    return render_template("peer_review_submit_review.html",
                           form=form,
                           criteria=criteria,
                           assignment=assignment,
                           submission=submission,
                           request=review_request,
                           criteria_formitems=zip(criteria, form.items))


### FIXME
### THIS IS UGLY ONE-TIMER HARD-CODED FUNCTION
### WILL BE REMOVED
@app.route("/_show_my_grades")
@login_required
def show_my_grades():
    import json

    with open("/srv/nbgr-x/grades.json") as f:
        sheet = json.load(f)

    header = sheet.pop(0)
    grades = None
    for row in sheet:
        if row[0].lower().strip() == current_user.email.lower().strip():
            grades = row[1:]
            break
    if grades:
        table = zip(header[1:], grades)
    else:
        table = None
    return render_template("show_my_grades.html", table=table,
                           email=current_user.email)

# Create admin
admin = flask_admin.Admin(
    app,
    'nbgr-x',
    base_template='my_master.html',
    template_mode='bootstrap3',
)

# Add model views
admin.add_view(MyModelView(Role, db.session))
admin.add_view(MyModelView(User, db.session))
admin.add_view(MyModelView(Course, db.session))
admin.add_view(MyModelView(Assignment, db.session))
admin.add_view(MyModelView(Submission, db.session))
admin.add_view(MyModelView(PeerReviewAssignment, db.session))
admin.add_view(MyModelView(PeerReviewSubmission, db.session))
admin.add_view(MyModelView(PeerReviewGradingCriterion, db.session))
admin.add_view(MyModelView(PeerReviewReview, db.session))
admin.add_view(MyModelView(PeerReviewReviewItem, db.session))
admin.add_view(MyModelView(PeerReviewReviewRequest, db.session))

# define a context processor for merging flask-admin's template context into the
# flask-security views.
@security.context_processor
def security_context_processor():
    return dict(
        admin_base_template=admin.base_template,
        admin_view=admin.index_view,
        h=admin_helpers,
    )



if __name__ == '__main__':
    #    app_dir = os.path.realpath(os.path.dirname(__file__))
    #    database_path = os.path.join(app_dir, app.config['DATABASE_FILE'])
    #    if not os.path.exists(database_path):
    #        build_sample_db()
    db.create_all()
    db.session.commit()
    app.run()
