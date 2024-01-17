import json
import os
import random
import re
import socket
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, List

try:
    from utils import http_client, sockets
except:
    import pathlib
    import sys

    sys.path.append(pathlib.Path(__file__).parent.parent.__str__())
    from utils import http_client, sockets


class EchoServiceBase:
    def __init__(self) -> None:
        self.netloc = ''
        self.cli = http_client.new(
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            }
        )

    def get_random_id(self):
        return {'netloc': self.netloc, 'random_id': os.urandom(8).hex()}

    def get_results(self, random_id: str, timeout: float = 30) -> List[Dict]:
        raise NotImplementedError


class RequestHandler(BaseHTTPRequestHandler):
    results = {}

    def handle_one_request(self) -> None:
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline = ''
                self.request_version = ''
                self.command = ''
                self.send_error(HTTPStatus.REQUEST_URI_TOO_LONG)
                return
            if not self.raw_requestline:
                self.close_connection = True
                return
            if not self.parse_request():
                # An error code has been sent, just exit
                return
        except TimeoutError as e:
            # a read or a write timed out.  Discard this connection
            self.log_error("Request timed out: %r", e)
            self.close_connection = True
            return

        body = ''
        if 'content-length' in self.headers:
            body = self.rfile.read(int(self.headers['content-length'])).decode('utf-8')
        r_rid = re.search(
            '[^\n]*random[-_]?id[-_:\s\'"]{0,5}([0-9a-f]{0,16})[^\n]*',
            '{}{}{}'.format(self.raw_requestline.decode('utf-8'), self.headers, body),
            re.I,
        )
        if r_rid:
            self.results[r_rid.group(1)] = {
                'ip': '{}:{}'.format(self.client_address[0], self.client_address[1]),
                'info': r_rid.group(),
                'time': time.time(),
            }
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(b'status 200, success.')
        # return super().handle_one_request()


class LocalSocket(EchoServiceBase):
    def __init__(self, host: str = '0.0.0.0', port: int = 3380) -> None:
        super(LocalSocket, self).__init__()
        self.host = host
        self.port = port
        self.netloc = '{}:{}'.format(host, port)
        self.socket = sockets.new(self.host, self.port)
        self.results = {}

    def start_service(self):
        # self.httpd = HTTPServer((self.host, self.port), RequestHandler)
        # thread = threading.Thread(target=self.httpd.serve_forever)
        # thread.daemon = True
        # thread.start()
        self.socket.set_end_message(
            '''HTTP/1.1 200 OK
Content-Type: text/html;charset=UTF-8

success'''
        )
        self.socket.run()

        def save_info():
            while True:
                info = self.socket.wait_request()
                r_rid = re.search(
                    '[^\n]*random[-_]?id[-_:\s\'"]{0,5}([0-9a-f]{0,16})[^\n]*',
                    info[2].decode('utf-8'),
                    re.I,
                )
                if r_rid:
                    key = r_rid.group(1)
                    data = {
                        'from': '{}:{}'.format(info[0], info[1]),
                        'info': r_rid.group(),
                        'time': time.time(),
                    }
                    if key in self.results:
                        self.results[key].append(data)
                    else:
                        self.results[key] = [data]

        thr = threading.Thread(target=save_info)
        thr.daemon = True
        thr.start()

    def get_results(self, random_id: str, timeout: float = 30) -> List[Dict]:
        s_time = time.time()
        while time.time() - s_time < timeout:
            if random_id in self.results:
                return self.results[random_id]
            time.sleep(1)
        return []

    def is_found(self, random_id: str, timeout: float = 30) -> bool:
        if self.get_results(random_id, timeout):
            return True
        return False


class DnslogOrg(EchoServiceBase):
    def __init__(self) -> None:
        super(DnslogOrg, self).__init__()
        self.domains_able = ['dnslog.store.', 'dns.dnslogs.online.']
        self.domain = ''
        self.netloc = ''
        self.token = ''

    def start_service(self):
        index_last = len(self.domains_able) - 1
        for index, domain in enumerate(self.domains_able):
            data = {'domain': domain}
            err, response = self.cli.r_super('https://dnslog.org/new_gen', 'POST', data)
            if err:
                if index == index_last:
                    raise ConnectionError(err.__str__())
                continue
            j_response = response.json()
            self.netloc = j_response['domain']
            self.domain = domain
            self.token = j_response['token']
            break

    def get_results(self, random_id: str, timeout: float = 30) -> List[Dict]:
        data = {'domain': self.domain}
        s_time = time.time()
        ret = []
        while time.time() - s_time < timeout:
            err, response = self.cli.r_super('https://dnslog.org/{}'.format(self.token), 'POST', data=data)
            if err:
                continue
            j_response = response.json()
            print(10002, j_response)
            if not response.json():
                continue

            for key in j_response:
                if random_id in j_response[key]['subdomain']:
                    ret.append(
                        {
                            'from': j_response[key]['ip'],
                            'info': j_response[key]['subdomain'],
                            'time': time.mktime(time.strptime(j_response[key]['time'], '%Y-%m-%d %H:%M:%S')),
                        }
                    )
            if ret:
                return ret
            time.sleep(1)
        return []

    def is_found(self, random_id: str, timeout: float = 30) -> bool:
        if self.get_results(random_id, timeout):
            return True
        return False


class DnslogCn(EchoServiceBase):
    def __init__(self) -> None:
        super(DnslogCn, self).__init__()
        self.domains_able = ['dnslog.cn']
        self.domain = ''
        self.netloc = ''

    def start_service(self):
        index_last = len(self.domains_able) - 1
        for index, domain in enumerate(self.domains_able):
            params = {'t': random.random()}
            err, response = self.cli.r_super('http://dnslog.cn/getdomain.php?t=0.27484175904205843', params=params)
            if err:
                if index == index_last:
                    raise ConnectionError(err.__str__())
                continue
            self.netloc = response.text
            self.domain = domain
            break

    def get_results(self, random_id: str, timeout: float = 30) -> List[Dict]:
        s_time = time.time()
        ret = []
        while time.time() - s_time < timeout:
            params = {'t': random.random()}
            err, response = self.cli.r_super('http://dnslog.cn/getrecords.php', params=params)
            if err:
                continue
            j_response = response.json()
            if not response.json():
                continue

            for it in j_response:
                if random_id in it[0]:
                    ret.append(
                        {
                            'from': it[1],
                            'info': it[0],
                            'time': time.mktime(time.strptime(it[2], '%Y-%m-%d %H:%M:%S')),
                        }
                    )
            if ret:
                return ret
            time.sleep(1)
        return []

    def is_found(self, random_id: str, timeout: float = 30) -> bool:
        if self.get_results(random_id, timeout):
            return True
        return False


class CeyeIo(EchoServiceBase):
    def __init__(self) -> None:
        super(DnslogCn, self).__init__()
        self.domains_able = ['dnslog.cn']
        self.domain = ''
        self.netloc = ''

    def start_service(self):
        pass

    def get_results(self, random_id: str, timeout: float = 30) -> List[Dict]:
        pass

    def is_found(self, random_id: str, timeout: float = 30) -> bool:
        if self.get_results(random_id, timeout):
            return True
        return False


if __name__ == '__main__':
    # nc = DnslogOrg()
    # nc.start_service()
    # info = nc.get_random_id()
    # print(info)
    # cli = http_client.new().r_super('http://{}'.format(info['netloc']))
    # print(nc.get_results(info['random_id'], timeout=5))
    # print(nc.is_found(info['random_id'], timeout=5))
    # cli = http_client.new().r_super('http://{}.{}'.format(info['random_id'], info['netloc']))
    # print(nc.get_results(info['random_id']))
    # print(nc.is_found(info['random_id']))

    # nc = LocalSocket('127.0.0.1')
    # nc.start_service()
    # info = nc.get_random_id()
    # print(info)
    # cli = http_client.new().r_super('http://{}'.format(info['netloc']))
    # print(nc.get_results(info['random_id']))
    # print(nc.is_found(info['random_id']))
    # cli = http_client.new().r_super('http://{}/random-id-{}'.format(info['netloc'], info['random_id']))
    # print(nc.get_results(info['random_id']))
    # print(nc.is_found(info['random_id']))

    nc = DnslogCn()
    nc.start_service()
    info = nc.get_random_id()
    print(info)
    cli = http_client.new().r_super('http://{}'.format(info['netloc']))
    print(nc.get_results(info['random_id'], timeout=5))
    print(nc.is_found(info['random_id'], timeout=5))
    cli = http_client.new().r_super('http://{}.{}'.format(info['random_id'], info['netloc']))
    print(nc.get_results(info['random_id']))
    print(nc.is_found(info['random_id']))
