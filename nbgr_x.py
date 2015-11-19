import os
from flask import Flask, render_template, url_for, request, abort,\
    redirect, Response
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.security import Security, SQLAlchemyUserDatastore, \
    UserMixin, RoleMixin, login_required, current_user, roles_required
from flask_security.utils import encrypt_password
from flask_mail import Mail
from flask_admin.contrib import sqla
from flask_admin import helpers as admin_helpers
from wtforms import DateTimeField
import flask_admin
from flask_security.forms import RegisterForm
from flask_wtf import Form
from wtforms import BooleanField, StringField, PasswordField, SelectMultipleField, validators
from wtforms.ext.sqlalchemy.fields import QuerySelectMultipleField, QuerySelectField
from flask_bootstrap import Bootstrap
from flask.ext.bower import Bower
from werkzeug import secure_filename
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms_components import read_only
from datetime import datetime

from itertools import chain
# Create app
app = Flask(__name__)

app.config.from_pyfile('config.py')
Bootstrap(app)
Bower(app)
# app.config['SECRET_KEY'] = 'secret'
# app.config['SQLALCHEMY_DATABASE_URI'] = \
#        'sqlite:////srv/data/nbgr-x/2015-16/students.sqlite'
app.config['DEBUG'] = True

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

    def __str__(self):
        return self.name


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

    def __str__(self):
        return self.email


class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    active = db.Column(db.Boolean())
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'))
    ipynb = db.Column(db.String(255))
    deadline = db.Column(db.DateTime)
    name = db.Column(db.String(255))
    description = db.Column(db.String(255))
    submissions = db.relationship('Submission', backref='assignment', lazy='dynamic')

    def __str__(self):
        return self.name

    def ipynb_link(self):
        return "%s/%s/%s" % (app.config['IPYNB_URL_PREFIX'],
                             secure_filename(self.course.name),
                             self.ipynb)


class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    assignment_id = db.Column(db.Integer, db.ForeignKey('assignment.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    timestamp = db.Column(db.DateTime())

    def __str__(self):
        return str(self.id)

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

# Setup Flask-Security


class ExtendedRegisterForm(RegisterForm):

    first_name = StringField('First Name', [validators.DataRequired()])
    last_name = StringField('Last Name', [validators.DataRequired()])
    #    active_courses = Course.query.filter_by(active = True).all()
    #    courses_choices = [(c.id, c.description) for c in active_courses]
    courses = QuerySelectMultipleField(
        query_factory=lambda: Course.query.filter_by(active=True),
        get_label='description')


user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore,
                    confirm_register_form=ExtendedRegisterForm,
                    register_form=ExtendedRegisterForm)


class MyModelView(sqla.ModelView):
    def is_accessible(self):
        if not current_user.is_active() or not current_user.is_authenticated():
            return False

        if current_user.has_role('superuser'):
            return True

        return False

    def _handle_view(self, name, **kwargs):
        """
        Override builtin _handle_view in order to redirect users when a view is not accessible.
        """
        if not self.is_accessible():
            if current_user.is_authenticated():
                # permission denied
                abort(403)
            else:
                # login
                return redirect(url_for('security.login', next=request.url))


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
@app.route('/')
@login_required
def home():
    return render_template('index.html')


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
    def __init__(self):
        super(AssignmentForm, self).__init__()
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


def save_assignment_ipynb(form):
    """
    Saves an assignment from the form
    :param form: the form to get assignment data from
    :return: the full name of the ipynb-file
    """

    ipynb_filename = secure_filename(form.name.data + ".ipynb")
    ipynb_dir = os.path.join(app.config['IPYNB_DIR'],
                             secure_filename(form.course.data.name))
    return try_and_save(form.ipynb_file.data, ipynb_dir, ipynb_filename)


@app.route('/add/assignment', methods=["GET", "POST"])
@roles_required('superuser')
def add_assignment():

    form = AddAssignmentForm()

    if request.method == 'POST' and form.validate():
        ipynb_filename = save_assignment_ipynb(form)

        new_assignment = Assignment()
        form.populate_obj(new_assignment)
        new_assignment.ipynb = ipynb_filename

        db.session.add(new_assignment)
        db.session.commit()
        return redirect(url_for('home'))

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
            save_assignment_ipynb(form)
        form.populate_obj(assignment)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('tweak_assignment.html',
                           form=form,
                           mode='edit',
                           assignment=assignment)


@app.route("/list/assignments")
@login_required
def list_assignments():
    submissions = current_user.submissions.all()
    courses = current_user.courses
    for course in courses:
        for assignment in course.assignments:
            assignment.submissions = [s for s in submissions if s.assignment == assignment]

    return render_template("list_assignments.html",
                           courses=courses)


class SubmitAssignmentForm(Form):
    ipynb_file = FileField("ipynb file",
                           validators=[FileRequired(),
                                       FileAllowed(['ipynb'],
                                                   'ipynb files only')])


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

        try_and_save(form.ipynb_file.data,
                     submission.dirpath(),
                     submission.filename()
                     )

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

    if current_user != submission.user:
        abort(403)
    return Response(open(submission.fullfilename()).read(),
                    mimetype="application/json",
                    headers={"Content-disposition": "attachment"})

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
    app_dir = os.path.realpath(os.path.dirname(__file__))
    database_path = os.path.join(app_dir, app.config['DATABASE_FILE'])
    if not os.path.exists(database_path):
        build_sample_db()
    app.run()
