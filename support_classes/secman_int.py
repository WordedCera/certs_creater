import requests
import json
from config import SECMAN_SECRET_ID, SECMAN_ROLE_ID, SECMAN_VAULT_NAMESPACE,\
    SECMAN_URL, PKKEY_SECRET_URI, PKKEY_SECRET_NAME, CERTS_PATH


# from logging_for_schedulers import logger

class SecManInt:
    """SecMan integration class"""

    def __init__(self, logger):
        self.data = {'secret_id': SECMAN_SECRET_ID,
                     'role_id': SECMAN_ROLE_ID}
        self.headers = {
            'X-Vault-Namespace': SECMAN_VAULT_NAMESPACE,
            'Content-Type': 'application/json'
        }
        self.secret: str = PKKEY_SECRET_URI
        self.sec_man_url: str = SECMAN_URL
        self.secret_name: str = PKKEY_SECRET_NAME
        self.logger = logger

    def authSec(self) -> str:
        """SecMan authorization token requester"""
        try:
            r = requests.post(
                f'{self.sec_man_url}v1/auth/approle/login',
                data=json.dumps(self.data),
                headers=self.headers, verify=f'{CERTS_PATH}client.pem',
                cert=(f'{CERTS_PATH}client.pem', f'{CERTS_PATH}kluch.key'))
            if r.status_code == requests.status_codes.codes.ok:
                client_token = json.loads(r.text)["auth"]["client_token"]
                self.logger.info('Success with requesting SecMan for token')
            elif r.status_code != requests.status_codes.codes.ok:
                self.logger.error(f'Error on SecMan connection for token: {r.status_code} {r.text}')
                return False
            return client_token
        except Exception as e:
            self.logger.error(f'exception occured with SecMan connection for token {e}')
            return False

    def getSecret(self) -> str:
        """SecMan secret getter"""
        client_token = self.authSec()
        self.headers['X-Vault-Token'] = client_token
        try:
            r = requests.get(
                f'{self.sec_man_url}v1/{self.secret}', headers=self.headers,
                verify=f'{CERTS_PATH}client.pem',
                cert=(f'{CERTS_PATH}client.pem', f'{CERTS_PATH}kluch.key'))
            if r.status_code == requests.status_codes.codes.ok:
                secret = json.loads(r.text)["data"][self.secret_name]
                self.logger.info('Success with requesting SecMan for secret')
            elif r.status_code != requests.status_codes.codes.ok:
                self.logger.error(f'Error on SecMan connection for secret: {r.status_code} {r.text}')
                return False
            return secret
        except Exception as e:
            self.logger.error(f'exception occured with SecMan connection for secret {e}')
            return False
