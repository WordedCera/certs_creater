import json
import sys
import requests
from datetime import datetime

sys.path.insert(0, '/opt/app-root/src')

from config import CERTS_PATH
from typing import Any, List, NamedTuple
from app.models import Certs, CertsQuts, Tasks
from support_classes.certs import KeyCsrGenerator as kg
from app import db, app
from support_classes.requests_modul import ReqVars
from support_classes.logging_for_schedulers import logger


class UnfulfilledTasks(NamedTuple):
    id: int
    task_id: int


headers = ReqVars(app.logger, url=URL, tok=TOKEN)


def _set_task_completed(task_id: int) -> None:
    """set completed status for tasks"""
    status_task = Tasks.query.filter_by(id=task_id).first()
    status_task.status = True
    db.session.commit()


def _insert_pub_certs_in_db(tasks_id: int, published_cert: str) -> None:
    """insert in db published cert for task"""
    data = Certs.query.filter_by(tasks_id=tasks_id).first()
    data.pem = published_cert
    db.session.commit()
    listed_guts = kg(logger=logger, pem=published_cert).getCertInfo()
    try:
        quts = CertsQuts(
            certs_id=data.id, cn=listed_guts['dn']['CN'],
            creation_date=datetime.fromtimestamp(int(listed_guts['not_before'])),
            exp_date=datetime.fromtimestamp(int(listed_guts['not_after'])),
            alt_names=listed_guts['dns'])
        db.session.add(quts)
        db.session.commit()
    except Exception:
        pass


def _sending_reques(task_id: int):
    """sending request in some job return response"""
    response = requests.get(f'{headers.url}api/tasks/{some_job_task_id}',
                            headers=headers.h,
                            verify=f'{CERTS_PATH}client.pem',
                            cert=(f'{CERTS_PATH}client.pem', f'{CERTS_PATH}kluch.key'))
    return response


def _check_unfulfilled_tasks() -> list:
    """get from db list unfulfilled tasks """
    unfulfilled_tasks = Tasks.query.filter_by(status=False).all()
    tasks_list: List[Any] = []
    for task in unfulfilled_tasks:
        data = UnfulfilledTasks(task_id=task.task_id,
                                id=task.id)
        tasks_list.append(data)
    logger.info(f'Backlogs received {len(tasks_list)}')
    return tasks_list


def check_tasks_in() -> None:
    """cyclically check tasks in some job"""
    tasks_list = _check_unfulfilled_tasks()
    for task in tasks_list:
        logger.info(f'Start check status task {task.task_id} in SOME JOB')
        # try:
        response = _sending_request(task.task_id)
        if response.status_code:
            if json.loads(response.text)["status"] != 'success':
                logger.info(f'Tasks {task.task_id} unfulfilled')
                continue
            data = json.loads(response.text)['payload']['success_answer_json']
            pub_cert = data['published_cert']
            _insert_pub_certs_in_db(task.id, pub_cert)
            _set_task_completed(task.id)
            logger.info(f'Tasks {task.task_id} success')
