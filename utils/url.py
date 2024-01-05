#!/bin/python3
# _*_ coding:utf-8 _*_
#
# url_handler.py
# uri 解析、query、param 处理与转换

import re
from typing import Any, Dict
from urllib.parse import quote

__SCHEME_TO_PORT__ = {
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


class DictString(dict):
    def __setitem__(self, key, value):
        super().__setitem__(key, str(value))


class Url:
    def __init__(self, url: str, is_errors: bool = False):
        '''
        :param url: 需要解析的url
        https://example.com:8952/nothing.py;param1=v1;param2=v2?query1=v1&query2=v2#frag
        scheme=https, netloc=example.com:8952, path=/nothing.py, params=param1=v1;param2=v2,
        query=query1=v1&query2=v2, fragment=frag, host=example.com, port=8952
        '''
        (
            self.scheme,
            self.netloc,
            self.path,
            self.params,
            self.query,
            self.fragment,
            self.host,
            self.port,
            self.username,
            self.password,
        ) = (
            '',
            '',
            '',
            DictString(),
            DictString(),
            '',
            '',
            '',
            '',
            '',
        )

        try:
            self.scheme, user_pass, self.netloc, self.path = re.search(
                r'(.+)://([^\\/]*:[^\\/]*@)?([^\\/]+)(/[^;?#]*)?', url
            ).groups()
            if not self.path:
                self.path = '/'
            if user_pass:
                self.username, self.password = re.search(r'([^@:]+):([^@:]+)', user_pass).groups()

            self.host, self.port = re.search(r'([^:]+):?(\d+)?', self.netloc).groups()
            if not self.port:
                self.port = self.get_default_port(self.scheme)
        except AttributeError:
            if not is_errors:
                raise ValueError('Incorrect Url "{}"'.format(url))

        r_params = re.findall(r';([^?#]+?)=([^?#;]+)', url)
        if r_params:
            self.params = DictString(r_params)
        else:
            self.params = DictString()

        r_query = re.findall(r'[?&]([^;?#]+?)=([^;?#&]+)', url)
        if r_query:
            self.query = DictString(r_query)
        else:
            self.query = DictString()

        r_fragment = re.search(r'#([^;?#]+)', url)
        if r_fragment:
            self.fragment = r_fragment.group(1)

    @property
    def i_port(self):
        return int(self.port)

    @property
    def netloc(self):
        return '{}:{}'.format(self.host, self.port)

    @netloc.setter
    def netloc(self, host: str, port: str = None):
        if ':' in host:
            host_spl = host.split(':')
            self.host = host_spl[0]
            self.port = host_spl[1]
        else:
            self.host = host
            self.port = __SCHEME_TO_PORT__[self.scheme] if self.scheme in __SCHEME_TO_PORT__ else ''
        if port:
            self.port = port

    @classmethod
    def get_default_port(cls, scheme: str):
        return __SCHEME_TO_PORT__[scheme]

    @classmethod
    def from_dict(cls, info: Dict[str, Any]):
        new_url = cls('', True)
        for key in info:
            if key not in new_url.__dict__:
                continue
            setattr(new_url, key, info[key])
        return new_url

    def endpoint(self):
        if self.username and not self.password:
            base = '{}://{}@{}'.format(self.scheme, self.username, self.netloc)
        elif self.username and self.password:
            base = '{}://{}:{}@{}'.format(self.scheme, self.username, self.password, self.netloc)
        else:
            base = '{}://{}'.format(self.scheme, self.netloc)
        return base

    def full_path(self, is_encode=True):
        base = self.path
        if self.params:
            for k in self.params:
                base += f';{k}={quote(self.params[k]) if is_encode else self.params[k]}'
        base += self.full_query(is_encode)
        if self.fragment:
            base += f'#{self.fragment}'
        return base

    def full_query(self, is_encode=True):
        if not self.query:
            return ''
        string_list = []
        for k in self.query:
            string_list.append(f'{k}={quote(self.query[k]) if is_encode else self.query[k]}')

        return '?' + '&'.join(string_list)

    def full_url(self, is_encode: bool = True):
        return self.endpoint() + self.full_path(is_encode)

    def __str__(self):
        return f"URL(scheme={self.scheme}, netloc={self.netloc}, path={self.path}, params={self.params}, query={self.query}, fragment={self.fragment}, hostname={self.host}, port={self.port}, username={self.username}, password={self.password})"


def new(*args, **kwargs) -> Url:
    return Url(*args, **kwargs)


if __name__ == '__main__':
    u = new('https://example.com:8952/nothing.py;param1=v1;param2=v2?query1=v1&query2=v2#frag')
    assert u.endpoint() == 'https://example.com:8952'
    assert u.path == '/nothing.py'
    assert u.full_url() == 'https://example.com:8952/nothing.py;param1=v1;param2=v2?query1=v1&query2=v2#frag'
    assert (
        u.full_url(is_encode=False)
        == 'https://example.com:8952/nothing.py;param1=v1;param2=v2?query1=v1&query2=v2#frag'
    )

    u = new('https://example.com:8952/nothing.py?query1=val$@!{}wef e()<>&query2=你好吗#frag')
    assert (
        u.full_url()
        == 'https://example.com:8952/nothing.py?query1=val%24%40%21%7B%7Dwef%20e%28%29%3C%3E&query2=%E4%BD%A0%E5%A5%BD%E5%90%97#frag'
    )
    assert u.full_url(is_encode=False) == 'https://example.com:8952/nothing.py?query1=val$@!{}wef e()<>&query2=你好吗#frag'

    u = new('https://login:p4ssw0rd@example.com:8952/nothing.py#frag')
    assert u.endpoint() == 'https://login:p4ssw0rd@example.com:8952'
    assert u.username == 'login'
    assert u.password == 'p4ssw0rd'
    u = new('socks5://127.0.0.1:1080/#/something/abc.jpg')
    assert u.endpoint() == 'socks5://127.0.0.1:1080'
    assert u.full_url() == 'socks5://127.0.0.1:1080/#/something/abc.jpg'

    u = Url.from_dict({'scheme': 'socks5', 'host': '127.0.0.1', 'port': '8080', 'username': 'admin'})
    assert u.full_url() == 'socks5://admin@127.0.0.1:8080'

    # ERROR URL
    try:
        u = new('')
        raise SyntaxError('A "ValueError" error should have been raised, but it did not')
    except ValueError as err:
        pass

    u = new('', is_errors=True)
