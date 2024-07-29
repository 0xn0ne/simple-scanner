#!/usr/bin/env python3
# _*_ coding:utf-8 _*_

import os
import pathlib
import random
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
        'STATUS': 405,
        # 无内容匹配上则直接返回
        'BODY': r'block.+errors.aliyun.com',
        # 无请求头匹配上则直接返回
        'HEADER': {'Server': r'Tengine'},
    },
    'CRCCLOUD': {
        # 多个条件之间是AND的匹配关系，条件内的子项之间是OR的匹配关系
        # 状态码不存在则直接返回
        'STATUS': 403,
        # 无内容匹配上则直接返回
        'BODY': r'<[\w-]+?>404</[\w-]+?>.+?<[\w\s!-]+?event_id: [0-9a-f]+[\w\s!-]+?>',
    },
}


class Plugin(plugin.PluginBase):
    def set_info(self):
        return plugin.Info(
            name='WhatWAF',
            catalog='PLG-2024-0001',
            itype=PLUGIN_TYPE.POC,
            protocol='http',
            port=80,
            ssl_protocol='https',
            ssl_port=443,
        )

    def run(self, url: urlutil.Url, *args, **kwargs) -> Tuple[bool, Any]:
        if not url.protocol:
            url.protocol, url.port = self.https_or_http(url)
        if not url.protocol:
            return False, 'network protocol does not match.'
        # 防缓存
        url = url.join('/{}/webshell.php'.format(os.urandom(3).hex()))

        http = self.make_http_client()

        while True:
            fake_proxy_ip = [
                random.randint(0, 223),
                random.randint(0, 255),
                random.randint(0, 255),
                random.randint(0, 255),
            ]
            if fake_proxy_ip[0] in [10, 100, 127, 172]:
                continue
            if (
                (fake_proxy_ip[0] == 192 and fake_proxy_ip[1] in [88, 168])
                or (fake_proxy_ip[0] == 169 and fake_proxy_ip[1] == 254)
                or (fake_proxy_ip[0] == 198 and fake_proxy_ip[1] in [18, 19, 51])
                or (fake_proxy_ip[0] == 203 and fake_proxy_ip[1] == 0)
            ):
                continue
            break
        fake_proxy_ip = '.'.join([str(i) for i in fake_proxy_ip])
        http.headers.update(
            {
                'User-Agent': http.get_user_agent_random(),
                'Via': fake_proxy_ip,
                'REMOTE_ADDR': fake_proxy_ip,
                'X-Forwarded-For': fake_proxy_ip,
                'HTTP_CLIENT_IP': fake_proxy_ip,
                'X-Real-IP': fake_proxy_ip,
            }
        )
        err, response = http.rq(url.get_full(), verify=False, timeout=2)
        if err:
            return False, err

        msg_match = {}
        match_status = True
        match_body = True
        match_header = True
        is_checked = False
        for waf_name in FINGERPRINT:
            if 'STATUS' in FINGERPRINT[waf_name]:
                match_status = False
                is_checked = True
                if response.status_code == FINGERPRINT[waf_name]['STATUS']:
                    match_status = True
                    msg_match['STATUS'] = response.status_code
            if 'BODY' in FINGERPRINT[waf_name]:
                match_body = False
                is_checked = True
                if not re.search(FINGERPRINT[waf_name]['BODY'], response.text, re.S):
                    continue
                match_body = True
                msg_match['BODY'] = FINGERPRINT[waf_name]['BODY']
            if 'HEADER' in FINGERPRINT[waf_name]:
                match_header = False
                is_checked = True
                for hkey in FINGERPRINT[waf_name]['HEADER']:
                    if hkey not in response.headers:
                        continue
                    if not re.search(FINGERPRINT[waf_name]['HEADER'][hkey], response.headers[hkey], re.S):
                        continue
                    match_header = True
                    msg_match['HEADER'] = FINGERPRINT[waf_name]['HEADER'][hkey]
            if match_status and match_body and match_header and is_checked:
                msg_match['WAF_NAME'] = waf_name
                break
            msg_match = {}
            match_status = True
            match_body = True
            match_header = True
            is_checked = False
        msg_match['URL'] = url.get_full()
        if match_status and match_body and match_header and is_checked:
            return True, msg_match
        return False, response.text


if __name__ == '__main__':
    import time

    plugin = Plugin()

    s_time = time.time()
    # print(plugin.do_testing('scanme.nmap.org'))
    # print('total time(s):', time.time() - s_time)

    # # HTTP类协议存在3次重试机制，连接失败的情况会重试3次
    # s_time = time.time()
    # print(plugin.do_testing('scanme.nmap.org:8080'))
    # print('total time(s):', time.time() - s_time)

    # s_time = time.time()
    # print(plugin.do_testing('https://scanme.nmap.org'))
    # print('total time(s):', time.time() - s_time)

    # s_time = time.time()
    # print(plugin.do_testing('https://scanme.nmap.org/admin/login/LoginForm.jsp'))
    # print('total time(s):', time.time() - s_time)
