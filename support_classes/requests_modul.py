import json

import requests
from app import app
from config import CERTS_PATH


class ReqVars:
    """Base class with settigs for request"""

    def __init__(self, logger, tok, url):
        self.h: dict = {'charset': 'utf-8', 'User-agent': 'Mozilla/5.0',
                        'Content-Type': 'application/json',
                        'accept': 'application/json',
                        'Authorization': tok}
        self.url: str = url
        self.logger = logger


class JsonProcessors(ReqVars):
    """Class with settings for formation json data"""

    def __init__(self, logger, tok, ci: str = None, csr: str = None,
                 email: str = None, cert_type: str = None, url: str = '',
                 cert_du: str = None, val: str = None, ca_type: str = None):
        super().__init__(logger, tok, url)
        self.ci = ci
        self.csr = csr
        self.email = email
        self.cert_type = cert_type
        self.cert_du = cert_du
        self.val = val
        self.ca_type = ca_type

    def forCSRjsonProcessor(self) -> json:
        self.logger.info('Starting json processor for CSR')
        try:
            data: dict = {"service": "tls_cert", "start_at": "now", "items": [{"invstend_ci_stend": self.ci}],
                          "params": {"ca_info": {"ca_type": self.ca_type}, "cert_info":
                              {"csr": self.csr,
                               "email": self.email,
                               "certificate_type": self.cert_type,
                               "certificate_duration": self.cert_du},
                                     "no_add_validation": self.val}}
        except Exception as e:
            self.logger.error(f'Error with json parsing: {str(e)}')
            return None

        self.logger.info('Done json parsing')
        return json.dumps(data)


class DataSender(JsonProcessors):
    """Class with request method"""

    def csrSender(self):
        data = JsonProcessors.forCSRjsonProcessor(self)
        try:
            self.logger.info(f'Starting request to {self.url}')
            r = requests.post(
                self.url + 'api/tasks.json', timeout=10, data=data,
                headers=self.h, verify=f'{CERTS_PATH}client.pem',
                cert=(f'{CERTS_PATH}client.pem', f'{CERTS_PATH}kluch.key'))
            if r.status_code == requests.status_codes.codes.ok:
                id = json.loads(r.text)["id"]
                self.logger.info('Success with requesting some job')
            elif r.status_code != requests.status_codes.codes.ok:
                self.logger.error(f'Error on some job connection: {r.status_code} {r.text}')
                return False
            return id
        except Exception as e:
            self.logger.error(f'exception occured with some job connection {e}')
            return False


# if __name__ == '__main__':

