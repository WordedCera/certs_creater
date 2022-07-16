import json
import random
import string
import threading

import requests


class Randomizer:
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    num = string.digits

    def __init__(self, lower, upper, num):
        self.cli_ser = ['client', 'server']
        self.names = ['NginX', 'kafka', 'some_service', 'service']
        self.subject_exists = [True, False]
        self.auth = ['clientAuth', 'serverAuth', 'clientAuth, serverAuth']
        self.country = ['RU','UA','GB']
        self.state_of_province = ['Moscow', 'Bryansk', 'Baghdad']
        self.dnses_exists = [True, False]
        self.dns = ['one','companydevices', 'rbank', 'hellos']
        self.all_symbols = lower + upper + num
        self.segment = ['some segment 1', 'some segment']

    def randomChooser(self, dns_quantity=4):
        name = random.choice(self.cli_ser) + random.choice(self.names)
        autho = random.choice(self.auth)
        segment = random.choice(self.segment)
        subject_exists = random.choice(self.subject_exists)
        country, organization, st, location, organization_unit = '','','','',''
        if subject_exists is True:
            country = random.choice(self.country)
            organization = 'Ola'
            st = random.choice(self.state_of_province)
            location = st
            organization_unit = "00CA"
        existence = random.choice(self.dnses_exists)
        dns_dict: dict = {}
        if existence is True:
            for i in range(1, dns_quantity+1):
                d = random.choice(self.dns)
                dn = d + str(i) + '.ru'
                cou = f"dns{i}"
                dns_dict[cou] = dn
        np = random.sample(self.all_symbols, 10)
        password = ""
        for s in np:
            password += s
        return name, autho, subject_exists, country, organization, location, \
            organization_unit, segment, st, existence, password, dns_dict

    def jsonCreater(self):
        name, autho, subject_exists, country, organiztion, location, \
            organization_unit, segment, st, existence, password, \
            dns_dict = self.randomChooser(dns_quantity=4)
        jsonchik: dict = {}
        jsonchik["user_id"] = 657
        jsonchik["cert_name"] = name
        jsonchik["segment"] = segment
        jsonchik["commonName"] = name
        jsonchik["authorization"] = autho
        if subject_exists is True:
            jsonchik["subject"] = {
                    "subject_exists": subject_exists,
                    "country": country,
                    "organization": organiztion,
                    "state_of_province": st,
                    "location": location,
                    "organization_unit": organization_unit
                }
        else:
            jsonchik["subject"] = {
                    "subject_exists": subject_exists
                }
        jsonchik["dnses_exists"] = existence
        if existence is True:
            jsonchik['dnses'] = {}
            for keys, values in dns_dict.items():
                jsonchik['dnses'][keys] = values
        jsonchik["password_encrypted"] = password
        jsonchik["email_specified"] = 'someemail@some.com'
        return json.dumps(jsonchik)


class ThreadingRequests:
    def __init__(self):
        self.h: dict = {
            'charset': 'utf-8', 'User-agent': 'Mozilla/5.0',
            'Content-Type': 'application/json',
            'accept': 'application/json'
        }
        self.data: json = Randomizer(
            Randomizer.lower, Randomizer.upper, Randomizer.num).jsonCreater()

    def thread_function(self, url):
        r = requests.post(url + '/api', data=self.data, headers=self.h)
        return print(r.text)


if __name__ == '__main__':
    url = 'http://127.0.0.1:8080'
    th = ThreadingRequests()
    thread1 = threading.Thread(target=th.thread_function, args=(url,))
    thread2 = threading.Thread(target=th.thread_function, args=(url,))

    thread1.start()
    thread2.start()
