import os
import socket
import sys
import time
from datetime import datetime
import certifi
from OpenSSL import SSL
from prometheus_client import Counter, Gauge, start_http_server

sys.path.insert(1, '/opt/app-root/src')
from app import db
from app.models import Certs, CertsQuts, OpsGroup, ServerMon, Users
from support_classes.logging_for_schedulers import logger

start_http_server(1456)


class PrometheusMetrics:
    g = Gauge(
        'cert_expired_seconds', 'any', ['CN', 'path', 'app', 'ops_group'])
    up = Gauge(
        'up', 'any', ['status', 'path', 'app', 'ops_group'])
    count = Counter(
        'logback_events', 'Counter of logger events',
        ['level', 'path', 'app', 'ops_group'])


class PrometheusWriter(PrometheusMetrics):
    def __init__(self):
        super().__init__()
        self.scrape_list = []

    def prometheusCertChecker(self) -> None:
        logger.info('Start of work with data from DB')
        for lists in self.scrape_list:
            hostname = lists.hostname
            port = lists.port
            ops_group = lists.name
            service = lists.service
            try:
                context = SSL.Context(method=SSL.TLSv1_2_METHOD)
                context.load_verify_locations(
                    cafile=certifi.where(),
                    capath='/certs/chain_pem.txt')
                conn = SSL.Connection(context, socket=socket.socket(socket.AF_INET, socket.SOCK_STREAM))
                conn.set_tlsext_host_name(hostname.encode('UTF-8'))
                self.count.labels('INFO', 'olo', hostname, service).inc(1)
                conn.settimeout(5)
                status = "available"
                self.up.labels(status, hostname, service, ops_group).set(1)
                conn.connect((hostname, port))
                logger.info(f'Got connection and context to {hostname}:{port} on {service}')
            except Exception as e:
                logger.error(f'Issue with the connection to {hostname}:{port} on {service}: {str(e)}')
                status = "unavailable"
                self.up.labels(status, hostname, service, ops_group).set(1)

            conn.setblocking(1)
            try:
                conn.do_handshake()
                conn.set_tlsext_host_name(hostname.encode())
                for nums, cert in enumerate(conn.get_peer_cert_chain()):
                    dn = cert.get_subject().get_components()
                    cn = dn[-1]
                    cn = cn[1].decode("utf-8", "ignore")
                    t = datetime.strptime(cert.get_notAfter().decode("utf-8", "ignore"), '%Y%m%d%H%M%SZ')
                    u = t.timestamp() * 1000
                    self.g.labels(cn, hostname, service, ops_group).set(u)
            except Exception as e:
                logger.error(f'Issue with handshake with {hostname}:{port} on {service}: {str(e)}')

            conn.close()
        
    def certsDBMonitor(self) -> None:
        try:
            list_of_lists = db.session.query(
                Certs.name,
                CertsQuts.cn,
                CertsQuts.exp_date,
                OpsGroup.name) \
                    .filter(CertsQuts.certs_id == Certs.id,
                            Certs.user_id == Users.id,
                            Users.ops_group_id == OpsGroup.id).all()
            logger.info('Successul DB select (CertsQuts)')
        except Exception as e:
            logger.error(f'Issue with DB {str(e)}')
        if list_of_lists:
            for line in list_of_lists:
                name = line[0]
                cn = line[1]
                u = line[2].timestamp()
                ops_group = line[3]
                self.g.labels(cn, 'certs_backend_db', name, ops_group).set(u)
        else:
            logger.info('There is nothing to monitor')


def _callerFunc():
    try:
        list_of_lists = db.session.query(
            ServerMon.hostname,
            ServerMon.port,
            ServerMon.service,
            OpsGroup.name).filter(ServerMon.ops_group_id == OpsGroup.id).all()

        logger.info('Successul DB select (CertsQuts)')
    except Exception as e:
        logger.error(f'Issue with DB {str(e)}')
    if list_of_lists:
        pw = PrometheusWriter()
        pw.scrape_list = list_of_lists
        pw.prometheusCertChecker()
        pw.certsDBMonitor()
    else:
        logger.info('There is nothing to monitor')
