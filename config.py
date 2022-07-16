import os
import datetime
from distutils.util import strtobool

appdir = os.path.abspath(os.path.dirname(__file__))



SERVER_SECONDS_TASKS_SCHEDULE = os.environ.get('SERVER_SECONDS_TASK_SCHEDULE') or 5
CERTS_PATH = os.environ.get('CERTS_PATH') or "ca/"
SERVER_MINUTES_TASK_SCHEDULE = os.environ.get('SERVER_MINUTES_TASK_SCHEDULE') or 2
ROUTE_REGISTER_ADMIN = strtobool(os.getenv('ROUTE_REGISTER_ADMIN') or 'False')


class BaseConfig(object):
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class DevelopmentConfig(BaseConfig):
    DATABASE_PASSWORD=os.environ.get('DATABASE_PASSWORD')
    DATABASE_USER=os.environ.get('DATABASE_USER')
    DATABASE_PORT=os.environ.get('DATABASE_PORT')
    DATABASE_URL=os.environ.get('DATABASE_URL')
    DATABASE_DB=os.environ.get('DATABASE_DB')
    DEVELOPMENT_DATABASE_URI=f'postgresql+psycopg2://{DATABASE_USER}:{DATABASE_PASSWORD}@{DATABASE_URL}:{DATABASE_PORT}/{DATABASE_DB}'
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = DEVELOPMENT_DATABASE_URI or \
        'postgresql+psycopg2://certs_backend:qwerty@localhost:5432/certs_backend'
    SQLALCHEMY_ECHO = False
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY') or 'super-secret'
    JWT_EXPIRED_TIME = os.getenv('JWT_EXPIRED_TIME') or 60
    JWT_ACCESS_TOKEN_EXPIRES = datetime.timedelta(minutes=int(JWT_EXPIRED_TIME))
