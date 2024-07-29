#!/bin/python3
# _*_ coding:utf-8 _*_
#
# httpcli.py
# http 请求工具，Python 本身并不支持 socks 代理如果需要使用 socks 代理则安装 pysocks、requests[socks]，
# requests_toolbelt 为 WebKitFormBoundary 编码使用
# 依赖安装：pip install requests pysocks requests[socks]
# browser_cookie3 文档：https://github.com/borisbabic/browser_cookie3

import http.cookiejar
import logging
import random
import re
import ssl
import time
from typing import Any, Dict, List, Tuple

from requests import Request, Response, Session, adapters, exceptions

DEFAULT_USER_AGENT_LNX = [
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux i686; rv:127.0) Gecko/20100101 Firefox/127.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 OPR/112.0.0.0',
]
DEFAULT_USER_AGENT_MAC = [
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.2592.87',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:127.0) Gecko/20100101 Firefox/127.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 OPR/112.0.0.0',
]
DEFAULT_USER_AGENT_WIN = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.3',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 OPR/112.0.0.0',
]
DEFAULT_USER_AGENT_MOB = [
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/126.0.6478.108 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 EdgiOS/126.2592.86 Mobile/15E148 Safari/605.1.15',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/127.0 Mobile/15E148 Safari/605.1.15',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.122 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 10; HD1913) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.122 Mobile Safari/537.36 EdgA/126.0.2592.80',
    'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.122 Mobile Safari/537.36 EdgA/126.0.2592.80',
]
DEFAULT_USER_AGENT = DEFAULT_USER_AGENT_LNX + DEFAULT_USER_AGENT_MAC + DEFAULT_USER_AGENT_WIN
DEFAULT_HEADERS = {
    'User-Agent': DEFAULT_USER_AGENT[random.randint(0, len(DEFAULT_USER_AGENT) - 1)],
    'Referer': 'https://www.google.com',
}


def cookie_str2list(cookies: str) -> List:
    return re.findall(r'([^; ]+)=([^; ]+)', cookies)


def cookie_str2dict(cookies: str) -> Dict:
    ret = {}
    for row in cookie_str2list(cookies):
        ret[row[0]] = row[1]
    return ret


class HttpClient(Session):
    log: logging.Logger
    headers: Dict

    def __init__(
        self,
        headers: Dict[str, str] = None,
        tries: int = 3,
        timeout: float = 3,
    ) -> None:
        super(HttpClient, self).__init__()
        self.timeout = timeout
        if headers:
            self.headers.update(headers)
        else:
            self.headers.update(DEFAULT_HEADERS)

        self.mount('http://', adapters.HTTPAdapter(max_retries=tries))
        self.mount('https://', adapters.HTTPAdapter(max_retries=tries))

    def rq(
        self,
        url: str,
        method: str = 'GET',
        data: Dict = None,
        json: Dict = None,
        params: Dict = None,
        headers: Dict = None,
        cookies: Dict = None,
        timeout: float = None,
        allow_redirects: bool = True,
        hooks: List = None,
        files=None,
        auth=None,
        *args,
        **kwargs
    ) -> Tuple[Exception | Any, Response | Any]:
        try:
            response = self.request(
                method,
                url,
                headers=headers,
                files=files,
                data=data,
                params=params,
                auth=auth,
                hooks=hooks,
                json=json,
                cookies=cookies,
                timeout=timeout or self.timeout,
                allow_redirects=allow_redirects,
                *args,
                **kwargs
            )
            return None, response
        except exceptions.RequestException as error:
            return error, None

    def retry(
        self,
        response_or_request: Response | Request,
        timeout: float = None,
        allow_redirects: bool = True,
    ) -> Tuple[Exception | None, Response | None]:
        request = response_or_request.request if isinstance(response_or_request, Response) else response_or_request

        kwargs = {
            'method': request.method,
            'URL': request.url,
            'DATA': request.body,
            'headers': request.headers,
            'hooks': request.hooks,
            'timeout': timeout or self.timeout,
            'allow_redirects': allow_redirects,
        }
        return self.rq(**kwargs)

    def set_cookies(self, cookies: str | List | Dict | http.cookiejar.CookieJar, domain: str = '*'):
        if isinstance(cookies, Dict):
            for key in cookies:
                self.cookies.set(key, cookies[key], domain=domain)
        elif isinstance(cookies, str):
            for row in cookie_str2list(cookies):
                self.cookies.set(row[0], row[1], domain=domain)
        elif isinstance(cookies, http.cookiejar.CookieJar):
            self.cookies.update(cookies)
        else:
            for row in cookies:
                self.cookies.set(row[0], row[1])

    def cookies2dict(self, is_drop: bool = False) -> Dict[str, List | str]:
        ret = {}
        for key, value in self.cookies.iteritems():
            if is_drop:
                ret[key] = value
                continue
            if key in ret:
                ret[key].append(value)
            else:
                ret[key] = [value]
        return ret

    def set_proxies(self, proxies):
        """
        格式为，{需要代理的协议: 代理服务器链接}，在使用 SOCKS5 代理的时候建议使用 SOCKS5H，
        因为 SOCKS5 在设备本地解析域名，而 SOCKS5H 则由 SOCKS5 代理所部署的服务器解析域名
        eg. proxies = {'http': 'https://127.0.0.1:443'} or proxies = {'https': 'socks5h://127.0.0.1:8080'}
        """

        self.proxies.update(proxies)
        return

    def is_https(self, addr: str, port: int, *args, **kwargs) -> str | bool:
        """geven 模块打 monkey 补丁后 sockets 模块没有 timeout 这个选项，无效的HTTPS证书会返回失败

        Args:
            addr (str): 目标地址
            port (int): 目标端口

        Returns:
            Union[str, bool]: 如果是SSL端口会返回SSL公钥信息，否则返回 False
        """
        try:
            return ssl.get_server_certificate((addr, port), *args, **kwargs)
        except ssl.SSLError:
            return False

    def get_user_agent_random(self, user_agent_list: List[str] = DEFAULT_USER_AGENT):
        return random.choice(user_agent_list)


if __name__ == '__main__':
    cli = HttpClient()

    err, ret = cli.rq('https://why-are-there-so-many-domian-name-in-the-world.com/')
    print(err, ret)

    # cli.set_cookies('PS=72349223; JS=55329342; AS=96234812')
    # ret = cli.post(
    #     'https://httpbin.org/post', params={'hey': 'man'}, cache={'hello': 'you'}
    # )
    # print(ret.status_code, ret.text)
    # print(cli.get('http://httpbin.org/get', params={'hey': 'man'}))
    # print(cli.cookies2dict())

    # print(cookie_str2dict('PS=72349223; JS=55329342; AS=96234812'))

    # print(cli.get_cookie_by_browser())
    # print(cli.get_cookie_by_browser(domain_name='httpbin.org'))
    # print(cli.get_cookie_by_browser(browser='chrome'))

    # def after_request(
    #     error: Exception, response: requests.Response
    # ) -> Tuple[Union[Exception, Any], Union[requests.Response, Any]]:
    #     if error:
    #         return error, response
    #     if response.status_code >= 300:
    #         return ConnectionError('status code {}, conection error!'.format(response.status_code)), response
    #     for key in response.headers:
    #         response.headers[key.lower()] = response.headers[key]
    #     if 'json' not in response.headers['content-type']:
    #         return ValueError(response.text), response
    #     return error, response.json()

    # err, ret = cli.rq('https://httpbin.org/get')
    # print(err.__str__(), ret)
    # err, ret = cli.rq('https://httpbin.org/status/304')
    # if err:
    #     print('error:', err.__str__())
    # print(err.__str__(), ret.status_code, ret.text)
    # err, ret = cli.retry(ret)
    # print(err.__str__(), ret.status_code, ret.text)

    # # Performance testing
    # # In a strange case, the session.request default method is slower than the httpcli.rq wrapper method.
    # session = requests.session()
    # s_time = time.time()
    # for i in range(10):
    #     ret = session.request('GET', 'https://httpbin.org/get')
    # print('request, total time(s):', time.time() - s_time)
    # # request, total time(s): 4.60796594619751

    # s_time = time.time()
    # for i in range(10):
    #     err, ret = cli.rq('https://httpbin.org/get')
    # print('r_super, total time(s):', time.time() - s_time)
    # # r_super, total time(s): 4.034818649291992

    print(cli.is_https('httpbin.org', 80))
