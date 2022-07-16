import socket
from OpenSSL import SSL
from prometheus_client import start_http_server, Gauge, Counter
import time
from datetime import timezone, datetime
import certifi
from logging_main import logger
from DB_worker import DBwork

start_http_server(1456)

class PrometheusMetrics:
    g = Gauge('cert_expired_seconds', 'any', ['CN', 'path', 'app', 'ops_group'])
    up = Gauge('up', 'any', ['status', 'path', 'app', 'ops_group'])
    counte = Counter('logback_events', 'Counter of logger events', ['level', 'path', 'app', 'opsg_roup'])

class PrometheusWriter(PrometheusMetrics):
    def __init__(self):
        super().__init__()
        self.scrape_list = []
    
    def prometheusCertChecker(self):
        for lists in self.scrape_list:
            hostname = lists[1]
            port = int(lists[3])
            service = lists[4]
            ops_group = lists[2]

            context = SSL.Context(method=SSL.TLSv1_2_METHOD)
            context.load_verify_locations(cafile=certifi.where())
            conn = SSL.Connection(context, socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            conn.set_tlsext_host_name(hostname.encode('UTF-8'))

            conn.settimeout(5)

            try:
                status = 'available'
                conn.connect(hostname, port)
                self.up.labels(status, hostname, service, ops_group).set(1)

            except Exception as e:
                logger.error(str(e))
                status = 'unavailable'
                self.up.labels(status, hostname, service, ops_group).set(1)
                continue
            
            conn.setblocking(1)

            try:
                conn.do_handshake()
            except Exception as e:
                logger.error(str(e))
                continue

            conn.set_tlsext_host_name(hostname.encode())
            for nums, cert in enumerate(conn.get_peer_cert_chain()):
                dn = cert.get_subject().get_components()
                cn = dn[-1]
                cn = cn[1].decode('UTF-8', 'ignore')
                t = datetime.strptime(cert.get_notAfter().decode('UTF-8', 'ignore'), '%Y%m%d%H%M%SZ')
                u = t.timestamp()*1000
                self.g.labels(cn, hostname, service, ops_group).set(u)

            conn.close()

if __name__ == '__main__':
    db = DBwork()
    db.select = "select * from schemaname.table"
    list_of_tuples = db.selectorDB()
    list_of = [list(x) for x in list_of_tuples]
    pw = PrometheusWriter()
    pw.scrape_list = list_of
    pw.prometheusCertChecker()