import json
import sys
from typing import Any, List, NamedTuple
import requests
sys.path.insert(0, '/opt/app-root/src')

from config import CERTS_PATH
from app import db
from app.models import Certs, Tasks
from support_classes.certs import StoreCreater
from support_classes.enc_dec import EncDec
from support_classes.requests_modul import ReqVars
from app import db, app

headers = ReqVars(app.logger)

class ContainerTasks(NamedTuple):
    id: int
    task_id: int
    key: str

def _sending_request(task_id: int):
    """sending request in some jobs return response"""
    response = requests.get(f'{headers.url}api/tasks/{task_id}',
                            headers=headers.h,
                            verify=f'{CERTS_PATH}client.pem',
                            cert=(f'{CERTS_PATH}client.pem', f'{CERTS_PATH}kluch.key'))
    return response


def _set_status_for_task_container(task_id: int) -> None:
    """set completed status for tasks"""
    status_task = Tasks.query.filter_by(id=task_id).first()
    status_task.container_status = True
    db.session.commit()

def _store_creator(
        published_cert: str, key: str, ca_chain: list, password: str,
        task_id: int, jks: bool, p12: bool) -> None:
    container = StoreCreater(
        key=key, pem=published_cert, cachain=ca_chain,
        password=password, task_id=task_id, jks=jks, p12=p12)
    list_of_bytes = container.keystoreCreater()
    
    return list_of_bytes


def _ca_chain_creator(root_cert: str, intermediate_cert: str) -> List:
    ca_chain: List[Any] = [root_cert, intermediate_cert]
    return ca_chain


def _decode_key(key: str, password_secret: str) -> str:
    encrypted = EncDec(logger=app.logger,
                     password=password_secret,
                     cell=key)
    decrypt = encrypted.decryptCell()
    return decrypt


def create_certs_container(task_id: str, password: str, jks: bool = False, p12: bool = False) -> None:
    response = _sending_request(task_id)
    task = db.session.query(Certs.key, Tasks.id).join(Tasks).filter(Tasks.task_id == int(task_id)).first()
    if response.status_code:
        data = json.loads(response.text)['payload']['success_answer_json']
        published_cert = data['published_cert']
        intermediate_cert = data['intermediate_cert']
        root_cert = data['root_cert']
        ca_chain = _ca_chain_creator(root_cert, intermediate_cert)
        pass_container, jks, p12 = password, jks, p12
        list_of_files = _store_creator(
            published_cert=published_cert,
            key=_decode_key(task.key),
            ca_chain=ca_chain, password=pass_container,
            task_id=task_id, jks=jks, p12=p12)
        _set_status_for_task_container(task.id)
        app.logger.info(f'Container from task_id:{task.id} succesful created')
        print(list_of_files)
        return list_of_files
    else:
        return None
