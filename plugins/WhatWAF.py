#!/usr/bin/env python3
# _*_ coding:utf-8 _*_

import pathlib
import re
import sys
from typing import Any, Tuple

try:
    from utils import PLUGIN_TYPE, plugin, urlutil
except:
    sys.path.append(pathlib.Path(__file__).parent.parent.__str__())
    from utils import PLUGIN_TYPE, plugin, urlutil

FINGERPRINT = {
    'ALICLOUD': {
        # 多个条件之间是AND的匹配关系，条件内的子项之间是OR的匹配关系
        # 状态码不存在则直接返回
        'STATUS': [405],
        # 无内容匹配上则直接返回
        'BODYS': [r'block.+errors.aliyun.com'],
        # 无请求头匹配上则直接返回
        'HEADERS': {'Server': [r'Tengine']},
    }
}


class Plugin(plugin.PluginBase):
    def set_info(self):
        return {
            # 字符型，漏洞名称
            'name': 'WhatWAF',
            # 字符型，漏洞编号，比如 CVE/CAN/BUGTRAQ/CNCVE/CNVD/CNNVD
            'catalog': 'PLG-2024-0001',
            # 数字型，漏洞类型，MODULE 为模块检测，POC为原理检测
            'itype': PLUGIN_TYPE.MODULE,
            # 字符型，漏洞相关的协议
            'protocols': ['http', 'https'],
            # 字符型，默认检测端口号
            'port': '80',
        }

    def run(self, url: urlutil.Url, *args, **kwargs) -> Tuple[bool, Any]:
        url.protocol = url.protocol or self.http_or_https(url)
        if not url.protocol:
            return False, 'network protocol does not match.'
        url = url.join('/webshell.php')

        err, response = self.http.rq(url.get_full(), timeout=5)
        if err:
            return False, err
        msg_match = {}
        match_status = True
        match_bodys = True
        match_headers = True
        is_checked = False
        for waf_name in FINGERPRINT:
            if 'STATUS' in FINGERPRINT[waf_name]:
                match_status = False
                is_checked = True
                if response.status_code in FINGERPRINT[waf_name]['STATUS']:
                    match_status = True
                    msg_match['STATUS'] = response.status_code
            if 'BODYS' in FINGERPRINT[waf_name]:
                match_bodys = False
                is_checked = True
                for re_rule in FINGERPRINT[waf_name]['BODYS']:
                    if not re.search(re_rule, response.text):
                        continue
                    match_bodys = True
                    msg_match['BODYS'] = re_rule
                    break
            if 'HEADERS' in FINGERPRINT[waf_name]:
                match_headers = False
                is_checked = True
                for hkey in FINGERPRINT[waf_name]['HEADERS']:
                    if hkey not in response.headers:
                        continue
                    for re_rule in FINGERPRINT[waf_name]['HEADERS'][hkey]:
                        if not re.search(re_rule, response.headers[hkey]):
                            continue
                        match_headers = True
                        msg_match['HEADERS'] = re_rule
                        break
            if match_status and match_bodys and match_headers and is_checked:
                msg_match['WAF_NAME'] = waf_name
                break
            msg_match = {}
            match_status = True
            match_bodys = True
            match_headers = True
            is_checked = False
        return match_status and match_bodys and match_headers and is_checked, msg_match


if __name__ == '__main__':
    import time

    from utils import net_echo

    nc = net_echo.DnslogCn()
    nc.start_service()
    plugin = Plugin(nc)

    s_time = time.time()
    print(plugin.do_testing('scanme.nmap.org'))
    print('total time(s):', time.time() - s_time)

    # HTTP类协议存在3次重试机制，连接失败的情况会重试3次
    s_time = time.time()
    print(plugin.do_testing('scanme.nmap.org:8080'))
    print('total time(s):', time.time() - s_time)

    s_time = time.time()
    print(plugin.do_testing('https://scanme.nmap.org'))
    print('total time(s):', time.time() - s_time)

    s_time = time.time()
    print(plugin.do_testing('https://scanme.nmap.org/admin/login/LoginForm.jsp'))
    print('total time(s):', time.time() - s_time)
