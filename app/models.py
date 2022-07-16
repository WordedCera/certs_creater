from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from app import db


class CertsQuts(db.Model):
    __tablename__ = 'cert_guts'
    id = db.Column(db.INTEGER(), primary_key=True)
    certs_id = db.Column(db.INTEGER(), db.ForeignKey('certs.id'), unique=True)
    cn = db.Column(db.TEXT(), nullable=True)
    creation_date = db.Column(db.DateTime(), nullable=True)
    exp_date = db.Column(db.DateTime(), nullable=True)
    alt_names = db.Column(db.TEXT(), nullable=True)

    def __repr__(self) -> str:
        return f'certs_id: {self.certs_id}, cn: {self.cn}'


class Certs(db.Model):
    __tablename__ = 'certs'
    id = db.Column(db.INTEGER(), primary_key=True)
    name = db.Column(db.TEXT())
    csr = db.Column(db.TEXT())
    key = db.Column(db.TEXT())
    pem = db.Column(db.TEXT(), nullable=True)
    auth_attr = db.Column(db.TEXT())
    email_specified = db.Column(db.TEXT())
    user_id = db.Column(db.Integer(), db.ForeignKey('users.id'))
    key_storage = db.Column(db.Boolean(), default=True)
    tasks_id = db.Column(db.Integer(), db.ForeignKey('tasks.id'))

    def __repr__(self) -> str:
        return f'certificate name: {self.name}'


class Users(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.Text())
    name = db.Column(db.String(80))
    email = db.Column(db.String(120), unique=True, nullable=False)
    ops_group_id = db.Column(db.Integer(), db.ForeignKey('ops_group.id'))
    role = db.Column(db.String(10))

    def __init__(self, username, password, name, email, ops_group_id, role):
        self.username = username
        self.password = generate_password_hash(password)
        self.name = name
        self.email = email
        self.ops_group_id = ops_group_id
        self.role = role

    def __repr__(self):
        return f'<User {self.username}>'

    def verify_password(self, pwd):
        return check_password_hash(self.password, pwd)


class Audit(db.Model):
    __tablename__ = 'audit'
    id = db.Column(db.INTEGER(), primary_key=True)
    last_login = db.Column(db.DateTime())
    scenario = db.Column(db.Text())
    user_id = db.Column(db.Integer(), db.ForeignKey('users.id'))
    actions = db.Column(db.Text())
    outcome = db.Column(db.Text())

    def __repr__(self) -> str:
        return f'user_id: {self.user_id}, last login {self.last_login}'


class OpsGroup(db.Model):
    __tablename__ = 'ops_group'
    id = db.Column(db.INTEGER(), primary_key=True)
    name = db.Column(db.Text())

    def __repr__(self) -> str:
        return f'ops_group name: {self.name}'


class Tasks(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.INTEGER(), primary_key=True)
    status = db.Column(db.Boolean())
    task_id = db.Column(db.Integer())

    def __repr__(self) -> str:
        return f'({self.task_id}, {self.status}), {self.id}'


class ServerMon(db.Model):
    __tablename__ = 'server_mon'
    id = db.Column(db.INTEGER(), primary_key=True)
    hostname = db.Column(db.Text())
    port = db.Column(db.Integer())
    ops_group_id = db.Column(db.Integer(), db.ForeignKey('ops_group.id'))
    service = db.Column(db.Text())

    def __repr__(self) -> str:
        return f'[{self.id},{self.hostname},{self.port}, \
                    {self.ops_group_id}, {self.service}]'
