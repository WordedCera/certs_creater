# import multiprocessing
import os
from gunicorn import glogging
import sys

glogging.Logger.error_fmt = '{"logLevel":"%(levelname)s","Timestamp":"%(asctime)s","Class_Name":"%(module)s","Method_name":"%(funcName)s","process_id":%(process)d,"message":"%(message)s"}'

max_requests = os.environ.get('GUNICORN_SERVER_MAX_REQUEST') or 1000
max_requests_jitter = 50
bind = os.environ.get('GUNICORN_SERVER_BIND') or '0.0.0.0:9443'
worker_class = 'gevent'
capture_output = False
access_log_format = '{"logLevel":"INFO","Timestamp":"%(t)s","Class_Name":"server","Request":"%(r)s","Status": "%(s)s""User-Agent": "%(a)s"}'
accesslog = "gunicorn.access.log"
errorlog = "-"
loglevel = os.environ.get('LOGGER_LEVEL') or 'INFO'
# workers = multiprocessing.cpu_count() * 2 + 1
workers = os.environ.get('GUNICORN_SERVER_WORKERS') or 4
