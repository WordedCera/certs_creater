import datetime
from typing import Union
from io import BytesIO
import jks
from OpenSSL import crypto


class KeyCsrGenerator:
    """Certificate generating class"""
    def __init__(self, logger, auth='clientAuth, serverAuth', C='RU',
                 O='SOME ORGANIZATION', ST='Moscow',
                 L='Moscow', OU='00CA', CN='Devices', dnsec=None, pem=None
                 ):
        self.auth = auth
        self.C = C
        self.O = O
        self.ST = ST
        self.L = L
        self.OU = OU
        self.CN = CN
        self.dnses = dnsec
        self.logger = logger
        self.pem: str = pem
        self.date_format = "%Y%m%d%H%M%SZ"
        self.encoding = None

    def generatekey(self) -> bytes:
        self.logger.debug("Generating Key")
        type_1 = crypto.TYPE_RSA
        key = crypto.PKey()
        key.generate_key(type_1, 4096)
        self.logger.info("Generated key successfully")
        return key

    def generateCsr(self) -> Union[str, bytes]:
        """Generate key, csr and return"""
        self.logger.info("Generating Csr")
        base_constraints = ([
            crypto.X509Extension(b"keyUsage", False, b"Digital Signature, Non Repudiation, Key Encipherment"),
            crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
            crypto.X509Extension(b"extendedKeyUsage", False, bytes(self.auth, 'UTF-8'))
        ])
        req = crypto.X509Req()
        sans_list = []
        if self.dnses is not None:
            self.logger.info("There are an alternative names")
            for san in self.dnses:
                sans_list.append("DNS: {0}".format(san))
            sans_list = ", ".join(sans_list).encode()
            base_constraints.append(crypto.X509Extension(b"subjectAltName", False, sans_list))
        req.add_extensions(base_constraints)
        req.get_subject().countryName = self.C
        req.get_subject().stateOrProvinceName = self.ST
        req.get_subject().localityName = self.L
        req.get_subject().organizationName = self.O
        req.get_subject().organizationalUnitName = self.OU
        req.get_subject().CN = self.CN
        key = self.generatekey()
        req.set_pubkey(key)
        req.sign(key, "sha256")
        csr: str = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req).decode('UTF-8')
        key: bytes = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
        self.logger.info("Generated csr")
        return csr, key

    def getCertInfo(self) -> dict:
        pem = crypto.load_certificate(crypto.FILETYPE_PEM, self.pem)
        iterat = pem.get_extension_count()
        listed = []
        for i in range(iterat):
            try:
                line = pem.get_extension(i).__str__()
            except:
                pass
            listed.append(line)
        cn = pem.get_subject()
        result = {'dns': x for x in listed if x.startswith('DNS')} or {'dns': 'None'}
        result.update({'auth': x for x in listed if x.startswith('TLS')})
        dct = dict((x.decode('utf-8'), y.decode('UTF-8')) for x, y in tuple(cn.get_components()))
        result.update({'dn': dct})
        not_before = datetime.datetime.strptime(pem.get_notBefore().decode('UTF-8'), self.date_format)
        not_after = datetime.datetime.strptime(pem.get_notAfter().decode('UTF-8'), self.date_format)
        result.update({'not_before': not_before.timestamp()})
        result.update({'not_after': not_after.timestamp()})
        if result:
            return result
        else:
            return False


class StoreCreater:
    """Created certificate container type jks, p12"""
    def __init__(
            self, task_id: int, key: str = None, pem: str = None,
            cachain: list = None, password: str = None,
            jks: bool = False, p12: bool = False):
        self.key = key
        self.pem = pem
        self.cachain = cachain
        self.password = password
        self.task_id = task_id
        self.jks = jks
        self.p12 = p12

    def keystoreCreater(self) -> dict:
        """Сreator of jks, p12 container"""
        p12data, keystore, truststore = None, None, None
        cer = crypto.load_certificate(crypto.FILETYPE_PEM, self.pem)
        privkey = crypto.load_privatekey(crypto.FILETYPE_PEM, self.key)
        p12 = crypto.PKCS12()
        cert_alias = cer.get_subject().CN.lower().replace(" ", "_")
        dict_certs = []
        ca_certs = []
        ca_certs2 = []
        for ca in self.cachain:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca)
            commonname = ca_cert.get_subject().CN.lower().replace(" ", "_")
            list_cert = {"cert": ca_cert, "alias": commonname}
            dict_certs.append(list_cert)
            ca_certs.append(ca_cert)
            ca_cert = crypto.dump_certificate(crypto.FILETYPE_ASN1, ca_cert)
            ca_certs2.append(ca_cert)
        if self.p12 is True:
            p12.set_privatekey(privkey)
            p12.set_certificate(cer)
            p12.set_friendlyname(bytes(cert_alias, 'UTF-8'))
            p12.set_ca_certificates(ca_certs)
            p12data = p12.export(bytes(self.password, 'UTF-8'))
            p12store = BytesIO()
            p12store.name = 'p12keystore.p12'
            p12store.write(p12data)
            p12store.seek(0)
        dumped_cert = crypto.dump_certificate(crypto.FILETYPE_ASN1, cer)
        dumped_key = crypto.dump_privatekey(crypto.FILETYPE_ASN1, privkey)
        if self.jks is True:
            pke = jks.PrivateKeyEntry.new(cert_alias, [dumped_cert, *ca_certs2], dumped_key, 'rsa_raw')
            store = jks.KeyStore.new('jks', [pke])
            keystore = BytesIO()
            store1 = store.saves(self.password)
            keystore.write(store1)
            keystore.seek(0)
        trust = jks.TrustedCertEntry()
        trusted = []
        for i in dict_certs:
            tr = crypto.dump_certificate(crypto.FILETYPE_ASN1, i['cert'])
            trusted.append(trust.new(i['alias'], tr))
        store = jks.KeyStore.new('jks', trusted)
        truststore = BytesIO()
        store1 = store.saves(self.password)
        truststore.write(store1)
        truststore.seek(0)
        if p12store == None:
            return {'keystore.jks': keystore, 'truststore.jks': truststore}
        elif keystore == None:
            return {'keystore.p12': p12store, 'truststore.jks': truststore}
        else:
            return {'keystore.jks': keystore, 'keystore.p12': p12store, 'truststore.jks': truststore}


# if __name__ == '__main__':
    # generator = KeyCsrGenerator(logger,
    #     CN='00CAPROMETHEUS', C='RU', auth='clientAuth', O='Devices',
    #     ST='Moscow', L='Moscow', OU='00CA'
    # ) 
    # csr, key = generator.generateCsr()
    # with open('new.csr', 'w') as f:
    #     f.write(csr)
    # # with open('key.key', 'wb') as f:
    # #     f.write(key)
    # process = StoreCreater(
    #     key='certs/kluch.key', pem='certs/client.pem', password='123456',
    #     cachain=['certs/EXT_iss.pem', 'certs/EXT_root.pem']
    # # )
    # # process.keystoreCreater()
    # with open('1.pem', 'r') as f: 
    #     s = f.read()
    #     f.close()
    # kg = KeyCsrGenerator(logger, pem=s)
    # iter_names = kg.getCertInfo()
    # print(iter_names)
