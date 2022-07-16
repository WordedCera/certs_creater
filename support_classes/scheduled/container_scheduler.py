import json
import sys
from typing import Any, List, NamedTuple
sys.path.insert(0, '/opt/app-root/src')
from app import db
from app.models import Certs, Tasks
from support_classes.certs import StoreCreater
from support_classes.enc_dec import EncDec
from support_classes.logging_for_schedulers import logger
from support_classes.scheduled.task_scheduler import _sending_request


class ContainerTasks(NamedTuple):
    id: int
    task_id: int
    key: str


def _get_task_container() -> List:
    """get from db tasks with
    sign jks or p12"""
    container_list = db.session.query(Certs, Tasks).join(Tasks) \
        .filter(Tasks.container_status == False) \
        .filter(Tasks.status == True).all()
    tasks_list: List[Any] = []
    for certs, tasks in container_list:
        data = ContainerTasks(
            task_id=tasks.task_id,
            id=tasks.id, key=certs.key)
        tasks_list.append(data)
    return tasks_list


def _set_status_for_task_container(task_id: int) -> None:
    """set completed status for tasks"""
    status_task = Tasks.query.filter_by(id=task_id).first()
    status_task.container_status = True
    db.session.commit()


def _get_parameters_for_container(task_id: int) -> str:
    parameters = Certs.query.filter_by(tasks_id=task_id).first()
    return parameters.password, parameters.jks, parameters.p12


def _store_creator(
        published_cert: str, key: str, ca_chain: list, password: str,
        task_id: int, jks: bool, p12: bool) -> None:
    container = StoreCreater(
        key=key, pem=published_cert, cachain=ca_chain,
        password=password, task_id=task_id, jks=jks, p12=p12)
    container.keystoreCreater()


def _ca_chain_creator(root_cert: str, intermediate_cert: str) -> List:
    ca_chain: List[Any] = [root_cert, intermediate_cert]
    return ca_chain


def _decode_key(key: str, password_secret) -> str:
    encrypt = EncDec(logger=logger,
                     password=password_secret,
                     cell=key)
    decrypt = encrypt.decryptCell()
    return decrypt


def create_certs_container() -> None:
    tasks_list = _get_task_container()
    for task in tasks_list:
        response = _sending_request(task.task_id)
        if response.status_code:
            data = json.loads(response.text)['payload']['success_answer_json']
            published_cert = data['published_cert']
            intermediate_cert = data['intermediate_cert']
            root_cert = data['root_cert']
            ca_chain = _ca_chain_creator(root_cert, intermediate_cert)
            pass_container, jks, p12 = _get_parameters_for_container(task.id)
            _store_creator(
                published_cert=published_cert,
                key=_decode_key(task.key),
                ca_chain=ca_chain, password=pass_container,
                task_id=task.task_id, jks=jks, p12=p12)
            _set_status_for_task_container(task.id)
            logger.info(f'Container from task_id:{task.id} succesful created')
