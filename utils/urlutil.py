#!/bin/python3
# _*_ coding:utf-8 _*_
#
# url_handler.py
# uri 解析、query、param 处理与转换
# 参考：https://www.browserling.com/tools/url-parse

import pathlib
import re
from typing import Any, Callable, Dict, Self
from urllib.parse import quote

PRTC2PORT = {
    'ftp': 21,
    'ssh': 22,
    'telnet': 23,
    'dns': 53,
    'tftp': 69,
    'http': 80,
    'pop': 109,
    'pop2': 109,
    'pop3': 110,
    'sftp': 115,
    'imap': 143,
    'snmp': 143,
    'imap3': 220,
    'ldap': 389,
    'https': 443,
    'smb': 445,
    'syslog': 514,
    'ldaps': 636,
    'imaps': 993,
    'pop3s': 995,
    'socks4': 1080,
    'socks5': 1080,
    'openvpn': 1194,
    'sqlserver': 1433,
    'oracle': 1521,
    'mqtt': 1883,
    'mysql': 3306,
    'rdp': 3389,
    'postgresql': 5432,
    'redis': 6379,
    't3': 7001,
    'ajp13': 8009,
    'mongodb': 27017,
}


class DictStr(dict):
    def __setitem__(self, key: str, value: str):
        super().__setitem__(str(key), str(value))


class Url:
    def __init__(self, url: str = None):
        """解析URL中的信息，并创建URL对象
        如：传入 http://usr:pwd@eg.cc/id.txt;p1=6;p2=3?q1=&q2=3&q3=6#h1 字符串解析结果为 <__main__.Url object at 0x1af298070e0, protocol=http, username=usr, password=pwd, host=eg.cc, port=80, path=/id.txt, params={'p1': '6', 'p2': '3'}, query={'q1': '', 'q2': '3', 'q3': '6'}, fragment=h1>

        Args:
            url (str, optional): 需要解析的URL，不传入的情况下建立空对象，默认：None
        """
        (
            self.protocol,
            self.username,
            self.password,
            # host和port的结合体，如eg.com:80
            self.netloc,
            self.host,
            self.port,
            self.path,
            self.params,
            self.query,
            self.fragment,
        ) = ('', '', '', '', '', 0, '/', DictStr(), DictStr(), '')

        if not url:
            return
        self = self.from_string(url, is_verify=False)

    @property
    def s_port(self):
        return str(self.port)

    @property
    def netloc(self):
        if self.port:
            if self.protocol and self.protocol in PRTC2PORT and self.port == PRTC2PORT[self.protocol]:
                return self.host
            return '{}:{}'.format(self.host, self.port)
        return self.host

    @netloc.setter
    def netloc(self, host: str, port: int = None):
        if ':' in host:
            host_spl = host.split(':')
            self.host = host_spl[0]
            self.port = int(host_spl[1])
            return

        self.host = host
        if port:
            self.port = port
        elif self.protocol:
            self.port = PRTC2PORT[self.protocol]

    @staticmethod
    def get_default_port(protocol: str):
        return PRTC2PORT[protocol]

    @classmethod
    def new_from_string(cls, url: str, is_verify: bool = True) -> Self:
        ret = cls()
        ret.from_string(url, is_verify)
        return ret

    @classmethod
    def new_from_dict(cls, info: Dict[str, Any], is_verify: bool = True) -> Self:
        ret = cls()
        ret.from_dict(info, is_verify)
        return ret

    def from_string(self, url: str, is_verify: bool = True):
        """方便内部调用，直接解析字符串并赋值到当前的URL对象中

        Args:
            url (str): URL字符串，如http://eg.com/eg.txt、socks5://eg.com:8080、ftp://usr:pwd@eg.com/
            is_verify (bool, optional): 是否对URL验证，默认：True

        Raises:
            ValueError: 验证URL失败时抛出
        """
        r_prtcl = re.search(r'(.+?)://', url)
        if r_prtcl:
            self.protocol = r_prtcl.group(1)
            url = url[r_prtcl.end() :]

        r_auth = re.search(r'([^:@/\?]{,64})(?::([^:@/\?]{,128}))?@', url)

        if r_auth:
            self.username = r_auth.group(1)
            self.password = r_auth.group(2) or ''
            url = url[r_auth.end() :]

        r_netloc = re.search(r'([\w-]{,63}(?:\.[\w-]{,63})+(?::(\d{1,5}))?)', url)
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
        """方便内部调用，直接解析字符串并赋值到当前的URL对象中

        Args:
            info (Dict[str, Any]): 记录URL信息的MAP，如{'protocol': 'http', 'protocol'}、socks5://eg.com:8080、ftp://usr:pwd@eg.com/
            is_verify (bool, optional): 是否对URL验证，默认：True

        Raises:
            ValueError: 验证URL失败时抛出
        """
        if is_verify and (not 'protocol' in info or not info['protocol'] or not 'host' in info or not info['host']):
            raise ValueError('incorrect url "{}", missing protocol or host.'.format(info))
        for key in info:
            if key not in self.__dict__:
                continue
            setattr(self, key, info[key])

    def get_origin(self) -> str:
        if self.username and not self.password:
            base = '{}://{}@{}'.format(self.protocol, self.username, self.netloc)
        elif self.username and self.password:
            base = '{}://{}:{}@{}'.format(self.protocol, self.username, self.password, self.netloc)
        else:
            base = '{}://{}'.format(self.protocol, self.netloc)
        return base

    def get_resource(self, is_encode=True) -> str:
        base = self.path
        if self.params:
            for k in self.params:
                base += f';{k}={quote(self.params[k]) if is_encode else self.params[k]}'
        if self.query:
            base += '?{}'.format(self.query2str(is_encode))
        if self.fragment:
            base += f'#{self.fragment}'
        return base

    def get_full(self, is_encode: bool = True) -> str:
        return self.get_origin() + self.get_resource(is_encode)

    def query2str(self, is_encode=True) -> str:
        if not self.query:
            return ''
        string_list = []
        for k in self.query:
            string_list.append(f'{k}={quote(self.query[k]) if is_encode else self.query[k]}')

        return '&'.join(string_list)

    def join(self, join_str: str) -> Self:
        if '://' in join_str:
            return self.new_from_string(join_str)
        join_result = pathlib.PurePosixPath(self.path).joinpath(join_str).__str__()
        return self.new_from_string(self.get_origin() + join_result)

    def __repr__(self):
        s_attrs = ''
        for i in self.__dict__:
            if isinstance(i, Callable) or i.startswith('_'):
                continue
            s_attrs += f', {i}={getattr(self, i)}'
        ret = '<{}.{} object at {}{}>'.format(self.__module__, type(self).__name__, hex(id(self)), s_attrs)
        return ret


def new(*args, **kwargs) -> Url:
    return Url(*args, **kwargs)


if __name__ == '__main__':
    assert (
        'protocol=, username=, password=, host=eg.cc, port=, path=/, params={}, query={}, fragment='
        in Url.new_from_string('eg.cc', is_verify=False).__str__()
    )
    assert (
        'protocol=, username=, password=, host=127.0.0.1, port=80, path=/, params={}, query={}, fragment='
        in Url.new_from_string('127.0.0.1:80', is_verify=False).__str__()
    )
    assert (
        'protocol=, username=usr, password=pwd, host=eg.cc, port=80, path=/, params={}, query={}, fragment='
        in Url.new_from_string('usr:pwd@eg.cc:80', is_verify=False).__str__()
    )
    assert (
        '''protocol=http, username=usr, password=pwd, host=eg.cc, port=80, path=/id.txt, params={'p1': '6', 'p2': '3'}, query={'q1': '', 'q2': '3', 'q3': '6'}, fragment=h1'''
        in Url.new_from_string('http://usr:pwd@eg.cc/id.txt;p1=6;p2=3?q1=&q2=3&q3=6#h1').__str__()
    )

    assert (
        'protocol=socks5h, username=admin, password=, host=127.0.0.1, port=8080, path=/admin, params={}, query={}, fragment='
        in Url.new_from_dict(
            {'protocol': 'socks5h', 'host': '127.0.0.1', 'port': '8080', 'username': 'admin', 'path': '/admin'}
        ).__str__()
    )
    assert (
        'protocol=, username=, password=, host=127.0.0.1, port=8080, path=/, params={}, query={}, fragment='
        in Url.new_from_dict({'host': '127.0.0.1', 'port': '8080'}, is_verify=False).__str__()
    )

    url = new('http://eg.cc:8080/i.txt?')
    assert url.netloc == 'eg.cc:8080'
    url = new('http://eg.cc/i.txt?')
    assert url.query2str() == ''
    url = new('http://eg.cc:1080/i.txt?q1=&q2=3&q3=6')
    assert url.query2str() == 'q1=&q2=3&q3=6'
    assert url.get_resource() == '/i.txt?q1=&q2=3&q3=6'
    assert url.get_origin() == 'http://eg.cc:1080'
    assert url.get_full() == 'http://eg.cc:1080/i.txt?q1=&q2=3&q3=6'
    assert url.join('http://ww.cc/s.txt').get_full() == 'http://ww.cc/s.txt'
    assert url.join('/new.txt').get_full() == 'http://eg.cc:1080/new.txt'
    assert url.join('abc/new.txt').get_full() == 'http://eg.cc:1080/i.txt/abc/new.txt'
