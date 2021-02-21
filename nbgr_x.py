from __future__ import print_function
import os
from flask import (
    Flask,
    render_template,
    url_for,
    request,
    abort,
    redirect,
    Response,
    send_from_directory,
    jsonify,
)
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.security import (
    Security,
    SQLAlchemyUserDatastore,
    UserMixin,
    RoleMixin,
    login_required,
    current_user,
    roles_required,
)
from flask_security.utils import encrypt_password
from flask_mail import Mail
from flask_admin.contrib import sqla
from flask_admin import helpers as admin_helpers
from wtforms import DateTimeField
import flask_admin
from flask_security.forms import RegisterForm
from flask_wtf import Form
from wtforms import (
    BooleanField,
    StringField,
    TextAreaField,
    validators,
    SelectField,
    TextAreaField,
    FieldList,
    FormField,
    ValidationError,
)
import wtforms
from wtforms.ext.sqlalchemy.fields import (
    QuerySelectMultipleField,
    QuerySelectField,
)
from flask_bootstrap import Bootstrap
from flask.ext.bower import Bower
from werkzeug import secure_filename
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms_components import read_only
from datetime import datetime
from sqlalchemy import desc

import subprocess
import shutil
import re

import itertools
import random

import codecs

import json
import uuid
import filetype

# from itertools import chain
# Create app

from celery import Celery


def make_celery(app):
    celery = Celery(
        app.import_name, broker=app.config["CELERY_BROKER_URL"]
    )
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
app.config.from_pyfile("config.py")
app.config.update(
    dict(
        MYPATH=MYPATH,
        PYTHON=os.path.join(MYPATH, "env", "bin", "python"),
        NBGRADER=os.path.join(MYPATH, "env", "bin", "nbgrader"),
    )
)

celery = make_celery(app)

Bootstrap(app)
Bower(app)

mail = Mail(app)

# Create database connection object
db = SQLAlchemy(app)

# Define models
roles_users = db.Table(
    "roles_users",
    db.Column("user_id", db.Integer(), db.ForeignKey("user.id")),
    db.Column("role_id", db.Integer(), db.ForeignKey("role.id")),
)

courses_users = db.Table(
    "courses_users",
    db.Column("user_id", db.Integer(), db.ForeignKey("user.id")),
    db.Column("course_id", db.Integer(), db.ForeignKey("course.id")),
)


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
    assignments = db.relationship(
        "Assignment", backref="course", lazy="dynamic"
    )
    peer_review_assignments = db.relationship(
        "PeerReviewAssignment", backref="course", lazy="dynamic"
    )

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
        return os.path.join(
            app.config["ASSIGNMENTS_PROCESS_DIR"],
            secure_filename(self.name),
        )

    def assignments_release_dir(self):
        return os.path.join(
            app.config["ASSIGNMENTS_RELEASE_DIR"],
            secure_filename(self.name),
        )

    def assignments_process_jail(self):
        """
        this is jail where submission files are placed

        pathes is like

        assignments_process_jail/submission_id/submitted

        have to be mounted to

        course_id/submitted

        :return: path
        """
        return os.path.join(
            app.config["ASSIGNMENTS_PROCESS_DIR"],
            "jail",
            secure_filename(self.name),
        )

    def gradebook_file(self):
        return os.path.join(self.assignments_process_dir(), "gradebook.db")

    def backup_gradebook(self):
        backup_dir = os.path.join(
            app.config("BACKUP_DIR"),
            "gradebooks",
            secure_filename(self.name),
        )
        make_sure_path_exists(backup_dir)
        shutil.copyfile(
            self.gradebook_file(),
            os.path.join(backup_dir, datetime.today().isoformat() + ".db"),
        )


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, index=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    first_name = db.Column(db.String(255))
    last_name = db.Column(db.String(255))

    roles = db.relationship(
        "Role",
        secondary=roles_users,
        backref=db.backref("users", lazy="dynamic"),
    )
    courses = db.relationship(
        "Course",
        secondary=courses_users,
        backref=db.backref("users", lazy="dynamic"),
    )
    submissions = db.relationship(
        "Submission", backref=db.backref("user"), lazy="dynamic"
    )
    peer_review_submissions = db.relationship(
        "PeerReviewSubmission", backref=db.backref("user"), lazy="dynamic"
    )
    peer_review_reviews = db.relationship(
        "PeerReviewReview", backref=db.backref("user"), lazy="dynamic"
    )
    peer_review_review_requests = db.relationship(
        "PeerReviewReviewRequest",
        backref=db.backref("reviewer"),
        lazy="dynamic",
    )

    def __str__(self):
        return "user" + str(self.id)


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
        with open(
            os.path.join(app.config["MYPATH"], "messages.json")
        ) as f:
            messages = json.load(f)
    except IOError:
        messages = {}
    return messages.get(user.email)


class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    active = db.Column(db.Boolean())
    course_id = db.Column(db.Integer, db.ForeignKey("course.id"))
    deadline = db.Column(db.DateTime)
    name = db.Column(db.String(255))
    description = db.Column(db.String(255))
    submissions = db.relationship(
        "Submission", backref="assignment", lazy="dynamic"
    )

    def __str__(self):
        return self.name

    def ipynb_link(self, preview=False):
        if preview:
            prefix = app.config["ASSIGNMENTS_URL_PREVIEW_PREFIX"]
        else:
            prefix = app.config["ASSIGNMENTS_URL_PREFIX"]
        return app.config["IPYNB_LINK_TEMPLATE"].format(
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
        return os.path.join(
            self.course.assignments_process_dir(),
            step,
            secure_filename(self.name),
        )

    def ipynb_release_dir(self):
        """
        Returns a path to the released assignment's dir
        (World-readable)
        :return: str
        """
        return os.path.join(
            self.course.assignments_release_dir(),
            secure_filename(self.name),
        )

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
        ipynb_dir = self.ipynb_process_dir("source")

        return try_and_save(ipynb_file, ipynb_dir, ipynb_filename)

    def process_ipynb(
        self, update=False, logfile=None, codestub="# YOUR CODE HERE"
    ):
        """
        Processes assignment nb with nbgrader assign
        :param update: update already processed file (gives --force
        flag instead of --create)
        :param codestub: code stub string
        :return: nothing
        """
        os.chdir(self.course.assignments_process_dir())
        if update:
            mode = "--force"
        else:
            mode = "--create"

        # command = [
        #     app.config["PYTHON"],
        #     app.config["NBGRADER"],
        #     "assign",
        #     secure_filename(self.name),
        #     mode,
        #     '--ClearSolutions.code_stub="%s"' % codestub,
        # ]
        mountpoints = ["-v", self.course.assignments_process_dir() + ":/assignments/"]
        command = (
            [
                "sudo",
                "docker",
                "run",
                "--rm",
            ]
            + mountpoints
            + [
                "jupyter/nbgrader",
                "generate_assignment",
                secure_filename(self.name),
                mode,
                '--ClearSolutions.code_stub="%s"' % codestub,
            ]
        )

        if logfile:
            log = open(logfile, "a")
            log.write(datetime.today().isoformat() + "\n")
            log.write(" ".join(command) + "\n\n")
        else:
            log = None

        subprocess.call(command, stderr=log)
        if logfile:
            log.close()

        make_sure_path_exists(self.ipynb_release_dir())
        shutil.copyfile(
            os.path.join(
                self.ipynb_process_dir("release"), self.ipynb_filename()
            ),
            os.path.join(self.ipynb_release_dir(), self.ipynb_filename()),
        )


class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    assignment_id = db.Column(db.Integer, db.ForeignKey("assignment.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    timestamp = db.Column(db.DateTime())
    autograded_status = db.Column(db.String(32))
    autograded_log = db.Column(db.String(256))

    def __str__(self):
        return "submission{}".format(self.id)

    def dirpath(self):
        return os.path.join(
            app.config["SUBMISSIONS_DIR"],
            secure_filename(self.assignment.course.name),
            "submitted",
            str(self.user_id),
            secure_filename(self.assignment.name),
        )

    def filename(self):
        return self.timestamp.isoformat() + ".ipynb"

    def fullfilename(self):
        return os.path.join(self.dirpath(), self.filename())

    def process_root(self, step=None):
        """
        This is a path to directory in jail where submission processing
        is made.

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
            course.assignments_process_jail(),  # {course_directory}
            str(self),  # hack to process different assignments concurently
        ]
        if step:
            parts.append(step)
        root = os.path.join(*parts)
        return root

    def process_dir(self, step):
        """
        Returns individual process dir path to the submission
        like the following

        {APD}/jail/{course_id}/{submission_id}/
        step/{student_id}/{assignment_id}

        :param step: nbgrader step (like 'submitted', 'autograded',
                'feedback')
        :return: path
        """
        user = self.user
        assignment = self.assignment

        submission_process_dir = os.path.join(
            self.process_root(step),
            str(user),  # {student_id}
            secure_filename(assignment.name),  # {assignment_id}
        )
        return submission_process_dir

    def feedback_file(self):
        return os.path.join(
            self.process_dir("feedback"),
            self.assignment.ipynb_filename().replace(".ipynb", ".html"),
        )


# Peer Review


class PeerReviewAssignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    active = db.Column(db.Boolean())
    course_id = db.Column(db.Integer, db.ForeignKey("course.id"))
    deadline = db.Column(db.DateTime)
    name = db.Column(db.String(255))
    description = db.Column(db.String(255))
    url = db.Column(db.String(255))

    submissions = db.relationship(
        "PeerReviewSubmission", backref="assignment", lazy="dynamic"
    )

    grading_criteria = db.relationship(
        "PeerReviewGradingCriterion", backref="assignment", lazy="dynamic"
    )

    def __str__(self):
        return self.name

    def storage_dir(self):
        return os.path.join(
            app.config["SUBMISSIONS_DIR"],
            secure_filename(self.course.name),
            "peer_review_store",
            secure_filename(self.name),
        )


def median(numbers):
    sorted_numbers = sorted(numbers)
    if len(numbers) % 2 == 1:
        return sorted_numbers[len(sorted_numbers) // 2]
    else:
        return (
            sorted_numbers[len(sorted_numbers) // 2]
            + sorted_numbers[len(sorted_numbers) // 2 - 1]
        ) / 2.


class PeerReviewSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    assignment_id = db.Column(
        db.Integer, db.ForeignKey("peer_review_assignment.id")
    )
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    timestamp = db.Column(db.DateTime())
    reviews = db.relationship(
        "PeerReviewReview", backref="submission", lazy="dynamic"
    )
    review_requests = db.relationship(
        "PeerReviewReviewRequest", backref="submission", lazy="dynamic"
    )

    work = db.Column(db.String(255))
    comment_for_reviewer = db.Column(db.String(255))

    def __str__(self):
        return "peer_review_submission" + str(self.id)

    def grade(self):
        reviews = self.reviews.all()
        if not reviews:
            return None
        return median([r.sum() for r in reviews if r])

    def work_parts(self):
        m = re.match("local:([^ ]+)( \+ (.*))?", self.work)
        parts = {}
        if not m:
            return {"external": self.work}
        localfile = m.group(1)
        _, extension = os.path.splitext(localfile)
        parts["download"] = url_for(
            "get_peer_review_submission_content",
            assignment_id=self.assignment.id,
            filename=localfile,
        )
        if extension in [".ipynb", ".json"]:
            global_path = url_for(
                "get_peer_review_submission_content",
                assignment_id=self.assignment.id,
                filename=localfile,
                _external=True,
            )
            parts["preview"] = app.config[
                "IPYNB_PREVIEW_PREFIX"
            ] + global_path.replace("http://", "")

        if m.group(3):
            parts["external"] = m.group(3)
        return parts


class PeerReviewGradingCriterion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    assignment_id = db.Column(
        db.Integer, db.ForeignKey("peer_review_assignment.id")
    )
    sort_index = db.Column(db.Integer)
    name = db.Column(db.String(255))
    description = db.Column(db.String(255))
    minimum = db.Column(db.Integer)
    maximum = db.Column(db.Integer)
    need_comment = db.Column(db.Boolean())
    review_items = db.relationship(
        "PeerReviewReviewItem", backref="criterion", lazy="dynamic"
    )

    def __str__(self):
        return self.name


class PeerReviewReview(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    submission_id = db.Column(
        db.Integer, db.ForeignKey("peer_review_submission.id")
    )
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))

    comment_for_author = db.Column(db.String(256))
    comment_for_teacher = db.Column(db.String(256))

    items = db.relationship(
        "PeerReviewReviewItem", backref="review", lazy="dynamic"
    )

    review_request = db.relationship(
        "PeerReviewReviewRequest", backref="review", uselist=False
    )

    timestamp = db.Column(db.DateTime())

    def __str__(self):
        return "peer_review_review" + str(self.id)

    def sum(self):
        return sum(item.grade for item in self.items)


class PeerReviewReviewItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    criterion_id = db.Column(
        db.Integer, db.ForeignKey("peer_review_grading_criterion.id")
    )
    review_id = db.Column(
        db.Integer, db.ForeignKey("peer_review_review.id")
    )
    grade = db.Column(db.Integer)
    comment = db.Column(db.String(256))

    def __str__(self):
        return "peer_review_grade_item" + str(self.id)


class PeerReviewReviewRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reviewer_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    submission_id = db.Column(
        db.Integer, db.ForeignKey("peer_review_submission.id")
    )
    review_id = db.Column(
        db.Integer, db.ForeignKey("peer_review_review.id")
    )


# Setup Flask-Security


class ExtendedRegisterForm(RegisterForm):

    first_name = StringField("First Name", [validators.DataRequired()])
    last_name = StringField("Last Name", [validators.DataRequired()])
    #    active_courses = Course.query.filter_by(active = True).all()
    #    courses_choices = [(c.id, c.description) for c in active_courses]
    courses = QuerySelectMultipleField(
        "Courses",
        [validators.DataRequired()],
        query_factory=lambda: Course.query.filter_by(active=True),
        get_label="description",
    )


user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(
    app,
    user_datastore,
    confirm_register_form=ExtendedRegisterForm,
    register_form=ExtendedRegisterForm,
)


class MyModelView(sqla.ModelView):
    def is_accessible(self):
        if (
            not current_user.is_active()
            or not current_user.is_authenticated()
        ):
            return False

        if current_user.has_role("superuser"):
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
                return redirect(
                    url_for("security.login", next=request.url)
                )


@celery.task()
def autograde(submission_id):
    """
    Autogrades submission with given submission_id
    in the background

    :param submission_id: submission.id
    :return: None
    """

    submission = Submission.query.get(submission_id)

    submission.autograded_status = "processing"
    db.session.commit()

    user = submission.user
    assignment = submission.assignment
    course = assignment.course

    steps = ["submitted", "autograded", "feedback"]
    for step in steps:
        make_sure_path_exists(submission.process_dir(step))

    ipynb_filename = os.path.join(
        submission.process_dir("submitted"), assignment.ipynb_filename()
    )

    shutil.copyfile(submission.fullfilename(), ipynb_filename)

    # FIX kernel name
    # Workaround for
    # https://github.com/Anaconda-Platform/nb_conda_kernels/issues/34

    with open(ipynb_filename) as fp:
        ipynb = json.load(fp)

    if ipynb["metadata"]["kernelspec"]["name"] != "python3":
        ipynb["metadata"]["kernelspec"]["name"] = "python3"
        with open(ipynb_filename, "w") as fp:
            json.dump(ipynb, fp)

    # END FIX

    ts_format = "%Y-%m-%d %H:%M:%S %Z"

    with open(
        os.path.join(submission.process_dir("submitted"), "timestamp.txt"),
        "w",
    ) as f:
        f.write(submission.timestamp.strftime(ts_format))

    shutil.copyfile(
        os.path.join(course.assignments_process_dir(), "gradebook.db"),
        os.path.join(submission.process_root(), "gradebook.db"),
    )

    mountpoints = ["-v", submission.process_root() + ":/assignments/"]
    for step in steps:
        make_sure_path_exists(submission.process_dir(step))

    env = os.environ
    if app.config["MAC_OS"]:
        env_str = subprocess.check_output(
            ["bash", "-c", "docker-machine env default"]
        )
        for line in env_str.splitlines():
            m = re.match(r'export\s+(\w+)="([^"]+)"', line)
            if m:
                key = m.group(1)
                value = m.group(2)

                env[key] = value
                print("DEBUG: %s => %s" % (key, value))

    # Update notebook
    command = (
        [
            "sudo",
            "docker",
            "run",
            "--rm",
        ]
        + mountpoints
        + [
            "jupyter/nbgrader",
            "update",
            os.path.join("submitted",
                         str(user),
                         secure_filename(assignment.name),
                         secure_filename(assignment.name) + ".ipynb")
        ]
    )

    subprocess.check_output(
        command, stderr=subprocess.STDOUT, env=env
    )

    # End update notebook

    try:
        # need timeout command
        command = (
            [
                "sudo",
                "timeout",
                "-s",
                "9",
                str(app.config["GRADING_TIMEOUT"]),
                "docker",
                "run",
                "--rm",
            ]
            + mountpoints
            + [
                "jupyter/nbgrader",
                "autograde",
                secure_filename(assignment.name),
                "--student",
                str(user),
                "--create",
                "--force",
            ]
        )

        print("DEBUG: " + " ".join(command))

        submission.autograded_log = subprocess.check_output(
            command, stderr=subprocess.STDOUT, env=env
        )

        submission.autograded_status = "autograded"

        # TODO: we need better processing of this
        # timeout scenario (hanged kernel)

        if "Timeout waiting for IOPub output" in submission.autograded_log:
            # nbgrader killed process by itself
            submission.autograded_status = "timeout"
        else:
            try:
                command = (
                    [
                        "sudo",
                        "timeout",
                        "-s",
                        "9",
                        str(app.config["GRADING_TIMEOUT"]),
                        "docker",
                        "run",
                        "--rm",
                    ]
                    + mountpoints
                    + [
                        "jupyter/nbgrader",
                        "feedback",
                        secure_filename(assignment.name),
                        "--student",
                        str(user),
                        "--force",
                    ]
                )

                print("DEBUG: " + " ".join(command))

                subprocess.check_output(
                    command, stderr=subprocess.STDOUT, env=env
                )

            except subprocess.CalledProcessError as error:
                submission.autograded_status = "error_on_feedback"
                submission.autograded_log = error.output

    except subprocess.CalledProcessError as error:
        if error.returncode in [124, 137]:
            # https://stackoverflow.com/a/29649720/3025981
            submission.autograded_status = "timeout"
        else:
            submission.autograded_log = "returncode: {}, {}".format(
                error.returncode, error.output
            )
            submission.autograded_status = "failed"

    db.session.commit()


@app.route("/assets/<path:path>")
def send_asset(path):
    return send_from_directory(os.path.join(MYPATH, "assets"), path)


@app.route("/_auto_grade/<id>")
@roles_required("superuser")
def do_pseudo_grade(id):
    submission = Submission.query.get_or_404(id)
    autograde.delay(submission.id)
    return redirect(url_for("get_feedback", id=submission.id))


@app.route("/gradebook/<course_id>")
@roles_required("superuser")
def show_gradebook(course_id):
    assignments, users, grades = get_gradebook(course_id)
    return render_template(
        "gradebook.html",
        assignments=assignments,
        users=users,
        grades=grades,
    )


@app.route("/gradebook/<course_id>/json")
@roles_required("superuser")
def json_gradebook(course_id):
    assignments, users, grades = get_gradebook(course_id)
    columns = ["id", "last_name", "first_name", "email"] + [
        assignment.name for assignment in assignments
    ]
    table = [
        [user.id, user.last_name, user.first_name, user.email]
        + [grades[user.id][assignment.id][1] for assignment in assignments]
        for user in users
    ]
    return jsonify(columns=columns, table=table)


def get_gradebook(course_id):
    course = Course.query.get_or_404(course_id)
    assignments = course.assignments
    users = course.users.order_by(User.last_name).order_by(User.first_name)

    grades = {}
    for user in users:

        current_grades = {}
        grades[user.id] = current_grades

        for assignment in assignments:
            submission = (
                user.submissions.filter_by(assignment=assignment)
                .filter_by(autograded_status="autograded")
                .order_by(desc(Submission.id))
                .first()
            )

            current_grades[assignment.id] = (
                submission,
                get_grade(submission),
            )
    return assignments, users, grades


# THIS FUNCTION IS FOR DEBUG ONLY
# SHOULD BE REMOVED SOON
@app.route("/_gradebook/<course_id>")
@roles_required("superuser")
def show_last_subm(course_id):
    course = Course.query.get_or_404(course_id)
    assignments = course.assignments
    users = course.users.order_by(User.last_name).order_by(User.first_name)

    grades = {}
    for user in users:

        current_grades = {}
        grades[user.id] = current_grades

        for assignment in assignments:
            submission = (
                user.submissions.filter_by(assignment=assignment)
                .order_by(desc(Submission.id))
                .first()
            )

            current_grades[assignment.id] = submission

    return render_template(
        "gradebook.html",
        assignments=assignments,
        users=users,
        grades=grades,
    )


def get_grade(submission):
    if submission is None:
        return
    try:
        with open(submission.feedback_file()) as f:
            resp = f.read()
    except IOError:
        return
    for line in resp.splitlines():
        if "Score" in line:
            m = re.search(r"Score: (\d+\.\d+)", line)
            if not m:
                return
            return float(m.group(1))
    return


# Create a user to test with
# @app.before_first_request
def build_sample_db():
    db.create_all()
    with app.app_context():
        user_role = Role(name="user")
        super_user_role = Role(name="superuser")
        db.session.add(user_role)
        db.session.add(super_user_role)
        db.session.commit()

        user_datastore.create_user(
            email="admin",
            password=encrypt_password("admin"),
            first_name="Admin",
            roles=[user_role, super_user_role],
        )

        db.session.commit()


class AssignmentForm(Form):
    active = BooleanField("Active", default=True)
    ipynb_file = FileField("Assignment ipynb file")
    deadline = DateTimeField("Deadline")
    description = StringField("Description")
    course = QuerySelectField(
        query_factory=lambda: Course.query.filter_by(active=True),
        get_label="description",
    )
    name = StringField("Name", validators=[validators.DataRequired()])


class AddAssignmentForm(AssignmentForm):
    def validate(self):
        rv = Form.validate(self)
        if not rv:
            return False

        assignment = Assignment.query.filter_by(
            course=self.course.data, name=self.name.data
        ).first()

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


@app.route("/add/assignment", methods=["GET", "POST"])
@roles_required("superuser")
def add_assignment():

    form = AddAssignmentForm()

    if request.method == "POST" and form.validate():

        new_assignment = Assignment()
        form.populate_obj(new_assignment)

        new_assignment.save_ipynb(form.ipynb_file.data)

        new_assignment.process_ipynb(logfile="log.log")

        db.session.add(new_assignment)
        db.session.commit()

        return redirect(url_for("edit_assignment", id=new_assignment.id))

    return render_template("tweak_assignment.html", form=form, mode="add")


@app.route("/edit/assignment/<id>", methods=["GET", "POST"])
@roles_required("superuser")
def edit_assignment(id):
    assignment = Assignment.query.get_or_404(id)
    form = EditAssignmentForm(obj=assignment)

    if request.method == "POST" and form.validate():

        del form.course
        del form.name
        # Precaution: `course` and `name` are read-only
        # See http://stackoverflow.com/a/16576294/3025981 for details

        if form.ipynb_file.data:
            assignment.save_ipynb(form.ipynb_file.data)
            assignment.process_ipynb(
                update=not form.force_create.data, logfile="log.log"
            )

        form.populate_obj(assignment)
        db.session.commit()
        return redirect(url_for("edit_assignment", id=id))
    return render_template(
        "tweak_assignment.html",
        form=form,
        mode="edit",
        assignment=assignment,
    )


@app.route("/")
@app.route("/list/assignments")
@login_required
def list_assignments():
    submissions = current_user.submissions.all()
    peer_review_submissions = current_user.peer_review_submissions.all()
    peer_review_review_requests = (
        current_user.peer_review_review_requests.all()
    )
    courses = current_user.courses
    mycourses = []
    for course in courses:
        mycourse = {
            "description": course.description,
            "active": course.active,
            "assignments": [],
            "peer_review_assignments": [],
        }
        for assignment in course.assignments:
            mycourse["assignments"].append(
                (
                    assignment,
                    [s for s in submissions if s.assignment == assignment],
                )
            )

        for assignment in course.peer_review_assignments:
            submission = next(
                (
                    s
                    for s in peer_review_submissions
                    if s.assignment == assignment
                ),
                None,
            )

            reviews = submission.reviews.all() if submission else []

            requests = [
                r
                for r in peer_review_review_requests
                if r.submission.assignment == assignment
            ]

            free = not any(r.review is None for r in requests)

            (
                mycourse["peer_review_assignments"].append(
                    (assignment, submission, reviews, requests, free)
                )
            )

        mycourses.append(mycourse)

    return render_template(
        "list_assignments_ru.html",
        mycourses=mycourses,
        message=get_message(current_user),
        now=datetime.now(),
        user=current_user,
    )


class SubmitAssignmentForm(Form):
    ipynb_file = FileField(
        "ipynb file",
        validators=[
            FileRequired(),
            FileAllowed(["ipynb", "json"], "ipynb or json files only"),
        ],
    )


@app.route("/submit/assignment/<id>", methods=["GET", "POST"])
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

        try_and_save(
            form.ipynb_file.data,
            submission.dirpath(),
            submission.filename(),
        )

        if (
            assignment.deadline
            and submission.timestamp <= assignment.deadline
        ):
            submission.autograded_status = "sent-to-grading"
            db.session.commit()
            autograde.delay(submission.id)
        else:
            submission.autograded_status = "late"
            db.session.commit()

        return redirect(url_for("list_assignments"))

    return render_template(
        "submit_assignment.html", form=form, assignment=assignment
    )


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

    if current_user != submission.user and not current_user.has_role(
        "superuser"
    ):
        abort(403)
    with open(submission.fullfilename()) as f:
        resp = f.read()
    return Response(
        resp,
        mimetype="application/x-ipynb+json",
        headers={"Content-disposition": "attachment; filename=" + id + ".ipynb"},
    )


@app.route("/get/feedback/<id>")
@login_required
def get_feedback(id):
    submission = Submission.query.get_or_404(id)

    if current_user != submission.user and not current_user.has_role(
        "superuser"
    ):
        abort(403)
    with codecs.open(submission.feedback_file(), encoding="utf-8") as f:
        lines = f.readlines()
    for i, line in enumerate(lines):
        if "Score" in line:
            lines[i] = re.sub(
                r"(?=\(Score: (\d+\.\d+))",
                r"by "
                + submission.user.first_name
                + " "
                + submission.user.last_name
                + " ",
                line,
            )
            break

    return Response("".join(lines), mimetype="text/html")


@app.route("/json/autograded_status/<id>")
@login_required
def json_autograded_status(id):
    submission = Submission.query.get_or_404(id)
    if current_user != submission.user and not current_user.has_role(
        "superuser"
    ):
        abort(403)
    return jsonify(
        status=submission.autograded_status, log=submission.autograded_log
    )


class SubmitPeerReviewAssignmentForm(Form):
    url = StringField("External URL (if work is hosted somewhere)")

    file = FileField(
        "ipynb or zip file",
        validators=[
            FileAllowed(
                ["ipynb", "json", "zip"], "ipynb or zip files only"
            )
        ],
    )

    comment_for_reviewer = TextAreaField("Comment to reviewer")

    # def validate(self, extra_validators=None):
    #     if not Form.validate(self):
    #         return False
    #     if not self.url.data.strip() and not self.file.data:
    #         raise ValidationError("Submission is empty!")
    #     return True


@app.route("/peer_review/submit/assignment/<id>", methods=["GET", "POST"])
@login_required
def peer_review_submit_assignment(id):
    assignment = PeerReviewAssignment.query.get_or_404(id)
    form = SubmitPeerReviewAssignmentForm()
    submission = assignment.submissions.filter_by(
        user=current_user
    ).first()

    if form.validate_on_submit():
        if assignment.deadline and datetime.today() > assignment.deadline:
            return render_template("toolate.html")
        if not submission:
            submission = PeerReviewSubmission()
            submission.user = current_user
            submission.assignment_id = assignment.id
        submission.timestamp = datetime.today()

        if form.file.data:
            _, extension = os.path.splitext(form.file.data.filename)
            filename = secure_filename(uuid.uuid4().hex + extension)
            # make unique filename but keep extension of the original
            # upload file
            try_and_save(
                form.file.data, assignment.storage_dir(), filename
            )

            if not form.url.data.strip():
                submission.work = "local:" + filename
            else:
                submission.work = "local:{} + {}".format(
                    filename, form.url.data
                )
        else:
            if submission.work:
                m = re.match("(local:[^ ]+)( \+ (.*))?", submission.work)
                if m:
                    submission.work = m.group(1)
            if submission.work:
                submission.work += " + " + form.url.data
            else:
                submission.work = form.url.data

        submission.comment_for_reviewer = form.comment_for_reviewer.data

        db.session.add(submission)
        db.session.commit()
        return redirect(url_for("list_assignments"))

    if submission:
        form.url.data = re.sub("local:[^ ]+( \+ )?", "", submission.work)
        form.comment_for_reviewer.data = submission.comment_for_reviewer
    if form.is_submitted() and not form.validate():
        message = "Form not submitted!"
    else:
        message = None
    return render_template(
        "peer_review_submit_assignment.html",
        form=form,
        assignment=assignment,
        message=message,
        submission=submission,
    )


@app.route(
    "/peer_review/get/submission_content/<assignment_id>/<filename>"
)
def get_peer_review_submission_content(assignment_id, filename):
    assignment = PeerReviewAssignment.query.get_or_404(assignment_id)
    full_filename = os.path.join(
        assignment.storage_dir(), secure_filename(filename)
    )
    try:
        _, ext = os.path.splitext(filename)
        if ext in [".ipynb", ".json"]:
            mimetype = "application/x-ipynb+json"
        elif ext == ".zip":
            mimetype = "application/zip"
        else:
            mimetype = "application/octet-stream"
        with open(full_filename) as f:
            resp = f.read()
        return Response(
            resp,
            mimetype=mimetype,
            headers={
                "Content-disposition": "attachment; filename=" + filename
            },
        )
    except IOError:
        abort(404)


class PeerReviewReviewItemForm(wtforms.Form):
    # must inherit from wtforms.Form
    # see http://stackoverflow.com/a/15651474/3025981
    grade = SelectField(
        "Grade",
        coerce=int,
        validators=[
            validators.InputRequired(),
            validators.NumberRange(0, 100),
        ],
    )
    comment = TextAreaField(
        "Please, explain your grade (visible to the author)",
        validators=[validators.DataRequired()],
    )


class PeerReviewReviewForm(Form):
    items = FieldList(FormField(PeerReviewReviewItemForm))
    comment_for_author = TextAreaField(
        "Comment for the author on the whole work (optional)"
    )
    comment_for_teacher = TextAreaField(
        "Comment for the teacher on the whole work"
        " (optional, not visible to the author)"
    )


@app.route("/peer_review/submit/review/<id>", methods=["GET", "POST"])
@login_required
def peer_review_submit_review(id):
    review_request = PeerReviewReviewRequest.query.get_or_404(id)
    if current_user != review_request.reviewer:
        abort(403)
    if review_request.review:
        # review already submitted, cannot change
        return redirect(
            url_for(
                "peer_review_get_review",
                id=review_request.review.id,
                message="alreadysubmitted",
            )
        )

    submission = review_request.submission
    assignment = submission.assignment
    criteria = assignment.grading_criteria.order_by(
        PeerReviewGradingCriterion.sort_index
    ).all()
    form = PeerReviewReviewForm(items=[{} for _ in criteria])
    for criterion, item in zip(criteria, form.items.entries):
        item.grade.choices = [
            (criterion.minimum - 1, "-- Select grade --")
        ] + [
            (i, str(i))
            for i in range(criterion.minimum, criterion.maximum + 1)
        ]
        item.grade.validators = [
            validators.InputRequired(),
            validators.NumberRange(
                min=criterion.minimum, max=criterion.maximum
            ),
        ]

    if request.method == "POST" and form.validate():
        review = PeerReviewReview()
        review.review_request = review_request
        review.submission = review_request.submission
        review.user = current_user
        review.timestamp = datetime.now()
        review.comment_for_author = form.comment_for_author.data
        review.comment_for_teacher = form.comment_for_teacher.data
        for criterion, form_item in zip(criteria, form.items):
            review_item = PeerReviewReviewItem()
            review_item.review = review
            review_item.criterion = criterion
            review_item.grade = form_item.grade.data
            review_item.comment = form_item.comment.data
            db.session.add(review_item)
        db.session.add(review)
        db.session.commit()
        return redirect(url_for("list_assignments"))

    return render_template(
        "peer_review_submit_review.html",
        form=form,
        criteria=criteria,
        assignment=assignment,
        submission=submission,
        request=review_request,
        criteria_formitems=zip(criteria, form.items),
    )


@app.route("/peer_review/get/review/<id>")
@login_required
def peer_review_get_review(id):
    review = PeerReviewReview.query.get_or_404(id)
    if current_user not in [
        review.user,
        review.submission.user,
    ] and not current_user.has_role("superuser"):
        abort(403)
    messages = {
        "submitted": "Your review submitted",
        "alreadysubmitted": "Your review already submitted, cannot change it",
    }
    return render_template(
        "peer_review_get_review.html",
        review=review,
        user=current_user,
        message=messages.get(request.args.get("message")),
    )


@app.route("/peer_review/get/assignment/<id>")
@login_required
def peer_review_get_assignment(id):
    assignment = PeerReviewAssignment.query.get_or_404(id)
    return render_template(
        "peer_review_get_assignment.html", assignment=assignment
    )


def peer_review_create_request(assignment, reviewer):
    submissions = assignment.submissions.all()
    free_submissions = [
        s
        for s in submissions
        if s.user != reviewer
        and reviewer not in [r.reviewer for r in s.review_requests]
    ]

    def number_of_reviewers(submission):
        return len(submission.review_requests.all())

    # TODO: rewrite it using SQL
    submissions_to_choose = list(
        next(
            itertools.groupby(
                sorted(free_submissions, key=number_of_reviewers),
                key=number_of_reviewers,
            ),
            (None, []),
        )[1]
    )

    if submissions_to_choose:
        submission = random.choice(submissions_to_choose)
        request = PeerReviewReviewRequest()
        request.reviewer = reviewer
        request.submission = submission
        return request


@app.route("/peer_review/ask_for_new_request/<assignment_id>")
@login_required
def peer_review_ask_for_new_request(assignment_id):
    assignment = PeerReviewAssignment.query.get_or_404(assignment_id)
    reviewer = current_user
    reviewer_is_busy = any(
        r.review is None
        for r in reviewer.peer_review_review_requests
        if r.submission.assignment == assignment
    )
    if (
        reviewer_is_busy
        or datetime.today() < assignment.deadline
        or assignment.course not in current_user.courses
    ):
        return redirect(url_for("list_assignments"))

    request = peer_review_create_request(assignment, reviewer)
    if not request:
        return redirect(url_for("list_assignments"))
    db.session.add(request)
    db.session.commit()
    return redirect(url_for("list_assignments"))


### FIXME
### THIS IS UGLY ONE-TIMER HARD-CODED FUNCTION
### WILL BE REMOVED
@app.route("/_show_my_grades")
@login_required
def show_my_grades():
    import json

    with open("/srv/nbgr-x/grades.json") as f:
        grades = json.load(f)

    table = grades.get(current_user.email)
    return render_template(
        "show_my_grades.html", table=table, email=current_user.email
    )


# Create admin
admin = flask_admin.Admin(
    app,
    "nbgr-x",
    base_template="my_master.html",
    template_mode="bootstrap3",
)

# Add model views

for entity in [
    Role,
    User,
    Course,
    Assignment,
    Submission,
    PeerReviewAssignment,
    PeerReviewSubmission,
    PeerReviewGradingCriterion,
    PeerReviewReview,
    PeerReviewReviewItem,
    PeerReviewReviewRequest,
]:

    admin.add_view(MyModelView(entity, db.session))

# define a context processor for merging flask-admin's template context
# into the flask-security views.
@security.context_processor
def security_context_processor():
    return dict(
        admin_base_template=admin.base_template,
        admin_view=admin.index_view,
        h=admin_helpers,
    )


if __name__ == "__main__":
    #    app_dir = os.path.realpath(os.path.dirname(__file__))
    #    database_path = os.path.join(app_dir, app.config['DATABASE_FILE'])
    #    if not os.path.exists(database_path):
    #        build_sample_db()
    db.create_all()
    db.session.commit()
    app.run()
