import os
import random
import re
import threading
import time
from typing import Dict, List, Union

try:
    from utils import http_client, sockets
except:
    import pathlib
    import sys

    sys.path.append(pathlib.Path(__file__).parent.parent.__str__())
    from utils import http_client, sockets


class EchoServiceBase:
    _type = None

    def __init__(self) -> None:
        self.netloc = None

    def start_service(self):
        pass

    def get_random_id(self, pre_id: str = '') -> Union[None, Dict]:
        if not self.netloc:
            raise RuntimeError('use the start_service() function to start the service first.')
        return {'netloc': self.netloc, 'rid': '{}rid{}'.format(pre_id, os.urandom(8).hex())}

    def get_results(self, random_id: str, timeout: float = 8) -> List[Dict]:
        raise NotImplementedError

    def is_found(self, random_id: str, timeout: float = 30) -> bool:
        raise NotImplementedError

    @staticmethod
    def find_rid(content: str):
        return re.search(
            r'[^\n]*(r(?:andom)?[-_]?id[-_:\s\'"]{0,5}[0-9a-f]{0,16})[^\n]*',
            content,
            re.I,
        )


class LocalSocket(EchoServiceBase):
    _type = 'TCP'

    def __init__(self, host: str = '0.0.0.0', port: int = 3380) -> None:
        super(LocalSocket, self).__init__()
        self.host = host
        self.port = port
        self.netloc = '{}:{}'.format(host, port)
        self.socket = sockets.new(self.host, self.port)
        self.results = {}

    def start_service(self):
        self.socket.set_end_message(
            '''HTTP/1.1 200 OK
Content-Type: text/html;charset=UTF-8

success'''
        )
        self.socket.run()

        def save_info():
            while True:
                info = self.socket.wait_request()
                r_rid = self.find_rid(info[2].decode('utf-8'))
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
    _type = 'DNS'

    def __init__(self) -> None:
        super(DnslogOrg, self).__init__()
        self.domains_able = ['dnslog.store.', 'dns.dnslogs.online.']
        self.domain = ''
        self.netloc = None
        self.token = ''
        self.cli = http_client.new(
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            },
            timeout=8,
        )

    def start_service(self):
        index_last = len(self.domains_able) - 1
        for index, domain in enumerate(self.domains_able):
            data = {'domain': domain}
            err, response = self.cli.rq('https://dnslog.org/new_gen', 'POST', data, timeout=3)
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
            err, response = self.cli.rq('https://dnslog.org/{}'.format(self.token), 'POST', data=data, timeout=3)
            if err:
                continue
            j_response = response.json()
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
    _type = 'DNS'

    def __init__(self) -> None:
        super(DnslogCn, self).__init__()
        self.domains_able = ['dnslog.cn']
        self.domain = ''
        self.netloc = None
        self.cli = http_client.new(
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            },
            timeout=8,
        )

    def start_service(self):
        index_last = len(self.domains_able) - 1
        for index, domain in enumerate(self.domains_able):
            params = {'t': random.random()}
            err, response = self.cli.rq(
                'http://dnslog.cn/getdomain.php?t=0.27484175904205843', params=params, timeout=3
            )
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
            time.sleep(1)
            params = {'t': random.random()}
            err, response = self.cli.rq('http://dnslog.cn/getrecords.php', params=params, timeout=3)
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
        return []

    def is_found(self, random_id: str, timeout: float = 30) -> bool:
        if self.get_results(random_id, timeout):
            return True
        return False


class CeyeIo(EchoServiceBase):
    def __init__(self) -> None:
        super(CeyeIo, self).__init__()
        self.domains_able = ['ceye.io']
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
    nc = LocalSocket('127.0.0.1')
    nc.start_service()
    info = nc.get_random_id()
    print(info)
    cli = http_client.new().rq('http://{}'.format(info['netloc']))
    print(nc.get_results(info['rid'], timeout=5))
    print(nc.is_found(info['rid'], timeout=5))
    cli = http_client.new().rq('http://{}/{}'.format(info['netloc'], info['rid']))
    print(nc.get_results(info['rid']))
    print(nc.is_found(info['rid']))

    # nc = DnslogOrg()
    # nc.start_service()
    # info = nc.get_random_id()
    # print(info)
    # cli = http_client.new().rq('http://{}'.format(info['netloc']))
    # print(nc.get_results(info['rid'], timeout=5))
    # print(nc.is_found(info['rid'], timeout=5))
    # cli = http_client.new().rq('http://{}.{}'.format(info['rid'], info['netloc']))
    # print(nc.get_results(info['rid']))
    # print(nc.is_found(info['rid']))

    # nc = DnslogCn()
    # nc.start_service()
    # info = nc.get_random_id()
    # print(info)
    # cli = http_client.new().rq('http://{}'.format(info['netloc']))
    # print(nc.get_results(info['rid'], timeout=5))
    # print(nc.is_found(info['rid'], timeout=5))
    # cli = http_client.new().rq('http://{}.{}'.format(info['rid'], info['netloc']))
    # print(nc.get_results(info['rid']))
    # print(nc.is_found(info['rid']))
