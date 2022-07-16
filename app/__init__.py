from flask import Flask
from flask_jwt_extended import JWTManager
from config import DevelopmentConfig
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from prometheus_flask_exporter import PrometheusMetrics, NO_PREFIX
import logging
from healthcheck import HealthCheck, EnvironmentDump

gunicorn_logger = logging.getLogger('gunicorn.error')

app = Flask(__name__)
metrics = PrometheusMetrics(app, defaults_prefix=NO_PREFIX)
health = HealthCheck()
envdump = EnvironmentDump()

app.config.from_object(DevelopmentConfig)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)

app.logger.handlers = gunicorn_logger.handlers
app.logger.setLevel(gunicorn_logger.level)

from app import models, routes
