#!/bin/python3
# _*_ coding:utf-8 _*_
#
# http_client.py
# http 请求工具，Python 本身并不支持 socks 代理如果需要使用 socks 代理则安装 pysocks、requests[socks]，

import http.cookiejar
import logging
import re
import ssl
import time
from typing import Any, Dict, List, Tuple, Union

import requests


def cookie_str2list(cookies: str) -> List:
    return re.findall(r'([^; ]+)=([^; ]+)', cookies)


def cookie_str2dict(cookies: str) -> Dict:
    ret = {}
    for row in cookie_str2list(cookies):
        ret[row[0]] = row[1]
    return ret


class HttpClient(requests.Session):
    def __init__(
        self,
        headers: Dict = None,
        tries: int = 5,
        timeout: float = 120,
    ) -> None:
        super(HttpClient, self).__init__()
        # timeout 必须赋值否则在多线程场景下 None 值的属性会被删除
        self.timeout = timeout
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, '
            'like Gecko) Chrome/96.0.4664.55 Safari/537.36',
            'Referer': 'https://www.google.com',
        }
        if headers:
            self.headers.update(headers)
        self.mount('http://', requests.adapters.HTTPAdapter(max_retries=tries))
        self.mount('https://', requests.adapters.HTTPAdapter(max_retries=tries))

        def prepare_request(request: requests.Request):
            ret = self.before_request(request)
            if isinstance(ret, requests.Request):
                return super(HttpClient, self).prepare_request(request)
            return ret

        self.prepare_request = prepare_request

    def before_request(self, request: requests.Request) -> Union[requests.Request, requests.PreparedRequest]:
        return request

    @staticmethod
    def after_request(
        err: Union[Exception, Any], response: Union[requests.Response, Any]
    ) -> Tuple[Union[Exception, Any], Union[requests.Response, Any]]:
        return err, response

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
    ) -> Tuple[Union[Exception, Any], Union[requests.Response, Any]]:
        try:
            res = self.request(
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
            return self.after_request(None, res)
        except requests.exceptions.RequestException as error:
            return self.after_request(error, None)

    # def try_rq(
    #     self,
    #     request: requests.Request,
    #     timeout=None,
    #     allow_redirects=True,
    #     proxies=None,
    #     stream=None,
    #     verify=None,
    #     cert=None,
    # ) -> requests.Response:
    #     prep = self.prepare_request(request)

    #     send_kwargs = {
    #         "timeout": timeout,
    #         "allow_redirects": allow_redirects,
    #     }
    #     send_kwargs.update(self.merge_environment_settings(prep.url, proxies or {}, stream, verify, cert))

    #     # Send the request.
    #     return self.send(prep, **send_kwargs)

    def retry(
        self, response: requests.Response, timeout: float = None, allow_redirects: bool = True
    ) -> Tuple[Union[Exception, Any], Union[requests.Response, Any]]:
        kwargs = {
            'method': response.request.method,
            'url': response.request.url,
            'data': response.request.body,
            'headers': response.request.headers,
            'hooks': response.request.hooks,
            'timeout': timeout or self.timeout,
            'allow_redirects': allow_redirects,
        }
        try:
            return self.after_request(None, self.request(**kwargs))
        except requests.exceptions.RequestException as error:
            return self.after_request(error, None)

    def set_cookies(
        self,
        cookies: Union[str, List, Dict, http.cookiejar.CookieJar],
        domain: str = '*',
    ):
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

    def cookies2dict(self, is_drop: bool = False) -> Dict[str, Union[List, str]]:
        ret: Dict[str, Union[List, str]] = {}
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

    def is_https(self, addr, port, timeout=3, *args, **kwargs) -> Union[str, bool]:
        try:
            return ssl.get_server_certificate((addr, port), timeout=timeout, *args, **kwargs)
        except ssl.SSLError:
            return False


def new(
    headers: Dict = None,
    tries: int = 5,
    timeout: float = None,
):
    return HttpClient(headers, tries, timeout)


if __name__ == '__main__':
    cli = new()

    # err, ret = cli.rq(
    #     'https://why-are-there-so-many-domian-name-in-the-world.com/'
    # )
    # print(err, ret)

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

    def after_request(
        error: Exception, response: requests.Response
    ) -> Tuple[Union[Exception, Any], Union[requests.Response, Any]]:
        if error:
            return error, response
        if response.status_code >= 300:
            return ConnectionError('status code {}, conection error!'.format(response.status_code)), response
        for key in response.headers:
            response.headers[key.lower()] = response.headers[key]
        if 'json' not in response.headers['content-type']:
            return ValueError(response.text), response
        return error, response.json()

    cli.after_request = after_request

    err, ret = cli.rq('https://httpbin.org/get')
    print(err.__str__(), ret)
    err, ret = cli.rq('https://httpbin.org/status/304')
    if err:
        print('error:', err.__str__())
    print(err.__str__(), ret.status_code, ret.text)
    err, ret = cli.retry(ret)
    print(err.__str__(), ret.status_code, ret.text)

    # Performance testing
    # In a strange case, the session.request default method is slower than the httpclinet.r_super wrapper method.
    session = requests.session()
    s_time = time.time()
    for i in range(10):
        ret = session.request('GET', 'https://httpbin.org/get')
    print('request, total time(s):', time.time() - s_time)
    # request, total time(s): 4.60796594619751

    s_time = time.time()
    for i in range(10):
        err, ret = cli.rq('https://httpbin.org/get')
    print('r_super, total time(s):', time.time() - s_time)
    # r_super, total time(s): 4.034818649291992
