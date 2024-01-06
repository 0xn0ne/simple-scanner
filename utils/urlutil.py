#!/bin/python3
# _*_ coding:utf-8 _*_
#
# url_handler.py
# uri 解析、query、param 处理与转换
# 参考：https://www.browserling.com/tools/url-parse

import pathlib
import re
from typing import Any, Dict
from urllib.parse import quote

PRTCL2PORT = {
    'ftp': '21',
    'ssh': '22',
    'telnet': '23',
    'dns': '53',
    'tftp': '69',
    'http': '80',
    'pop': '109',
    'pop2': '109',
    'pop3': '110',
    'sftp': '115',
    'imap': '143',
    'snmp': '143',
    'imap3': '220',
    'ldap': '389',
    'https': '443',
    'smb': '445',
    'syslog': '514',
    'ldaps': '636',
    'imaps': '993',
    'pop3s': '995',
    'socks4': '1080',
    'socks5': '1080',
    'openvpn': '1194',
    'sqlserver': '1433',
    'oracle': '1521',
    'mqtt': '1883',
    'mysql': '3306',
    'rdp': '3389',
    'postgresql': '5432',
    'redis': '6379',
    't3': '7001',
    'ajp13': '8009',
    'mongodb': '27017',
}


class DictStr(dict):
    def __setitem__(self, key: str, value: str):
        super().__setitem__(str(key), str(value))


class Url:
    def __init__(self, url: str = None):
        '''
        :param url: 需要解析的url
        http://usr:pwd@eg.cc/id.txt;p1=6;p2=3?q1=&q2=3&q3=6#h1
        URL(protocol=http, username=usr, password=pwd, netloc=eg.cc:80, host=eg.cc, port=80, path=/id.txt, params={'p1': '6', 'p2': '3'}, query={'q1': '', 'q2': '3', 'q3': '6'}, fragment=h1)
        '''
        (
            self.protocol,
            self.username,
            self.password,
            self.netloc,
            self.host,
            self.port,
            self.path,
            self.params,
            self.query,
            self.fragment,
        ) = ('', '', '', '', '', '', '/', DictStr(), DictStr(), '')

        if not url:
            return
        self = self.from_str(url, is_verify=False)

    @property
    def port2int(self):
        return int(self.port)

    @property
    def netloc(self):
        if self.port:
            if self.protocol and self.protocol in PRTCL2PORT and self.port == PRTCL2PORT[self.protocol]:
                return self.host
            return '{}:{}'.format(self.host, self.port)
        return self.host

    @netloc.setter
    def netloc(self, host: str, port: str = None):
        if ':' in host:
            host_spl = host.split(':')
            self.host = host_spl[0]
            self.port = host_spl[1]
            return

        self.host = host
        if port:
            self.port = port
        elif self.protocol:
            self.port = PRTCL2PORT[self.protocol]

    @staticmethod
    def get_default_port(protocol: str):
        return PRTCL2PORT[protocol]

    @classmethod
    def new_from_str(cls, url: str, is_verify: bool = True):
        new_url = cls()
        new_url.from_str(url, is_verify)
        return new_url

    @classmethod
    def new_from_dict(cls, info: Dict[str, Any], is_verify: bool = True):
        new_url = cls()
        new_url.from_dict(info, is_verify)
        return new_url

    def from_str(self, url: str, is_verify: bool = True):
        r_prtcl = re.search(r'(.+)://', url)
        if r_prtcl:
            self.protocol = r_prtcl.group(1)
            url = url[r_prtcl.end() :]

        r_auth = re.search(r'([^:@/\?]{,64})(?::([^:@/\?]{,128}))?@', url)

        if r_auth:
            self.username = r_auth.group(1)
            self.password = r_auth.group(2) or ''
            url = url[r_auth.end() :]

        r_netloc = re.search(r'([0-9a-zA-Z][-0-9a-zA-Z]{,63}(?:\.[0-9a-zA-Z][-0-9a-zA-Z]{,63})+(?::(\d{1,5}))?)', url)
        if is_verify and not (r_prtcl or r_netloc):
            raise ValueError('incorrect url "{}", missing protocol or host.'.format(url))

        if r_netloc:
            self.netloc = r_netloc.group(1)
            url = url[r_netloc.end() :]

        r_path = re.search(r'/[^#\?;&]+', url)
        if r_path:
            self.path = r_path.group()
            url = url[r_path.end() :]

        r_params = re.findall(r';([^;?#&]+?)=([^;?#&]*)', url)
        if r_params:
            self.params = DictStr(r_params)

        r_query = re.findall(r'[?&]([^;?#&]+?)=([^;?#&]*)', url)
        if r_query:
            self.query = DictStr(r_query)

        r_fragment = re.search(r'#([^;?#&]+)', url)
        if r_fragment:
            self.fragment = r_fragment.group(1)

    def from_dict(self, info: Dict[str, Any], is_verify: bool = True):
        if is_verify and (not 'protocol' in info or not info['protocol'] or not 'host' in info or not info['host']):
            raise ValueError('incorrect url "{}", missing protocol or host.'.format(info))
        for key in info:
            if key not in self.__dict__:
                continue
            setattr(self, key, info[key])

    def origin(self):
        if self.username and not self.password:
            base = '{}://{}@{}'.format(self.protocol, self.username, self.netloc)
        elif self.username and self.password:
            base = '{}://{}:{}@{}'.format(self.protocol, self.username, self.password, self.netloc)
        else:
            base = '{}://{}'.format(self.protocol, self.netloc)
        return base

    def query2str(self, is_encode=True):
        if not self.query:
            return ''
        string_list = []
        for k in self.query:
            string_list.append(f'{k}={quote(self.query[k]) if is_encode else self.query[k]}')

        return '&'.join(string_list)

    def resource(self, is_encode=True):
        base = self.path
        if self.params:
            for k in self.params:
                base += f';{k}={quote(self.params[k]) if is_encode else self.params[k]}'
        if self.query:
            base += '?{}'.format(self.query2str(is_encode))
        if self.fragment:
            base += f'#{self.fragment}'
        return base

    def string(self, is_encode: bool = True):
        return self.origin() + self.resource(is_encode)

    def join(self, join_str: str):
        if '://' in join_str:
            return self.new_from_str(join_str)
        join_result = pathlib.PurePosixPath(self.path).joinpath(join_str).__str__()
        return self.new_from_str(self.origin() + join_result)

    def __str__(self):
        return f'URL(protocol={self.protocol}, username={self.username}, password={self.password}, netloc={self.netloc}, host={self.host}, port={self.port}, path={self.path}, params={self.params}, query={self.query}, fragment={self.fragment})'


def new(*args, **kwargs) -> Url:
    return Url(*args, **kwargs)


if __name__ == '__main__':
    assert (
        Url.new_from_str('eg.cc', is_verify=False).__str__()
        == 'URL(protocol=, username=, password=, netloc=eg.cc, host=eg.cc, port=, path=/, params={}, query={}, fragment=)'
    )
    assert (
        Url.new_from_str('127.0.0.1', is_verify=False).__str__()
        == 'URL(protocol=, username=, password=, netloc=127.0.0.1, host=127.0.0.1, port=, path=/, params={}, query={}, fragment=)'
    )
    assert (
        Url.new_from_str('eg.cc:80', is_verify=False).__str__()
        == 'URL(protocol=, username=, password=, netloc=eg.cc:80, host=eg.cc, port=80, path=/, params={}, query={}, fragment=)'
    )
    assert (
        Url.new_from_str('usr:pwd@eg.cc:80', is_verify=False).__str__()
        == 'URL(protocol=, username=usr, password=pwd, netloc=eg.cc:80, host=eg.cc, port=80, path=/, params={}, query={}, fragment=)'
    )
    assert (
        Url.new_from_str('http://eg.cc:80').__str__()
        == 'URL(protocol=http, username=, password=, netloc=eg.cc, host=eg.cc, port=80, path=/, params={}, query={}, fragment=)'
    )
    assert (
        Url.new_from_str('http://usr:pwd@eg.cc:80').__str__()
        == 'URL(protocol=http, username=usr, password=pwd, netloc=eg.cc, host=eg.cc, port=80, path=/, params={}, query={}, fragment=)'
    )
    assert (
        Url.new_from_str('http://usr@eg.cc:80').__str__()
        == 'URL(protocol=http, username=usr, password=, netloc=eg.cc, host=eg.cc, port=80, path=/, params={}, query={}, fragment=)'
    )
    assert (
        Url.new_from_str('http://usr:pwd@eg.cc:80').__str__()
        == 'URL(protocol=http, username=usr, password=pwd, netloc=eg.cc, host=eg.cc, port=80, path=/, params={}, query={}, fragment=)'
    )
    assert (
        Url.new_from_str('http://usr:pwd@eg.cc/id.txt').__str__()
        == 'URL(protocol=http, username=usr, password=pwd, netloc=eg.cc, host=eg.cc, port=80, path=/id.txt, params={}, query={}, fragment=)'
    )
    assert (
        Url.new_from_str('http://usr:pwd@eg.cc/id.txt;p1=6;p2=3').__str__()
        == "URL(protocol=http, username=usr, password=pwd, netloc=eg.cc, host=eg.cc, port=80, path=/id.txt, params={'p1': '6', 'p2': '3'}, query={}, fragment=)"
    )
    assert (
        Url.new_from_str('http://eg.cc/id.txt?q1=&q2=3&q3=6').__str__()
        == "URL(protocol=http, username=, password=, netloc=eg.cc, host=eg.cc, port=80, path=/id.txt, params={}, query={'q1': '', 'q2': '3', 'q3': '6'}, fragment=)"
    )
    assert (
        Url.new_from_str('http://eg.cc/id.txt#h1').__str__()
        == "URL(protocol=http, username=, password=, netloc=eg.cc, host=eg.cc, port=80, path=/id.txt, params={}, query={}, fragment=h1)"
    )
    assert (
        Url.new_from_str('http://usr:pwd@eg.cc/id.txt;p1=6;p2=3?q1=&q2=3&q3=6#h1').__str__()
        == "URL(protocol=http, username=usr, password=pwd, netloc=eg.cc, host=eg.cc, port=80, path=/id.txt, params={'p1': '6', 'p2': '3'}, query={'q1': '', 'q2': '3', 'q3': '6'}, fragment=h1)"
    )

    assert (
        Url.new_from_dict(
            {'protocol': 'socks5h', 'host': '127.0.0.1', 'port': '8080', 'username': 'admin', 'path': '/admin'}
        ).__str__()
        == 'URL(protocol=socks5h, username=admin, password=, netloc=127.0.0.1:8080, host=127.0.0.1, port=8080, path=/admin, params={}, query={}, fragment=)'
    )
    assert (
        Url.new_from_dict({'host': '127.0.0.1', 'port': '8080'}, is_verify=False).__str__()
        == 'URL(protocol=, username=, password=, netloc=127.0.0.1:8080, host=127.0.0.1, port=8080, path=/, params={}, query={}, fragment=)'
    )

    url = new('http://eg.cc/i.txt?')
    assert url.netloc == 'eg.cc'
    assert url.query2str() == ''
    url = new('http://eg.cc:1080/i.txt?q1=&q2=3&q3=6')
    assert url.query2str() == 'q1=&q2=3&q3=6'
    assert url.resource() == '/i.txt?q1=&q2=3&q3=6'
    assert url.origin() == 'http://eg.cc:1080'
    assert url.string() == 'http://eg.cc:1080/i.txt?q1=&q2=3&q3=6'
    assert url.join('http://ww.cc/s.txt').string() == 'http://ww.cc/s.txt'
    assert url.join('/new.txt').string() == 'http://eg.cc:1080/new.txt'
    assert url.join('abc/new.txt').string() == 'http://eg.cc:1080/i.txt/abc/new.txt'
