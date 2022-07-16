import logging
import os
import sys

std = logging.StreamHandler(sys.stdout)
fld = logging.FileHandler('gunicorn.access.log', 'a')

ls = os.environ.get('LOGGER_LEVEL') or 'INFO'
levelFunc = getattr(logging, ls)
logger = logging.getLogger(__name__)
logging.basicConfig(level=levelFunc,
                    format='{"logLevel":"%(levelname)s","Timestamp":"[%(asctime)s]","Class_Name":"%(module)s",'
                           '"Method_name":"%(funcName)s","process_id":%(process)d,"message":"%(message)s"}',
                    handlers=[fld,
                              std])
logger = logging.getLogger('Schedulers logger')
