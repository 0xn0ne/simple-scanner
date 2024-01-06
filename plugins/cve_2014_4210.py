#!/usr/bin/env python3
# _*_ coding:utf-8 _*_
# CVE-2014-4210
# updated 2019/10/23, by 0xn0ne
#
# 有漏洞的情况
# 端口不存在
# An error has occurred
# weblogic.uddi.client.structures.exception.XML_SoapException: Tried all: '1' addresses, but could not connect over HTTP to server: 'x.x.x.x', port: '80'
# 端口存在
# An error has occurred
# weblogic.uddi.client.structures.exception.XML_SoapException: Received a response from url: http://x.x.x.x:7001 which did not have a valid SOAP content-type: text/html.

from typing import Dict, Tuple

try:
    from utils import PLUGIN_TYPE, plugin, urlutil
except:
    import pathlib
    import sys

    sys.path.append(pathlib.Path(__file__).parent.parent.__str__())
    from utils import PLUGIN_TYPE, plugin, urlutil


class Plugin(plugin.PluginBase):
    def set_info(self):
        return {
            'name': '',
            'catalog': 'CVE-2014-4210',
            'itype': PLUGIN_TYPE.MODULE,
            'protocols': ['http', 'https'],
            'port': '7001',
        }

    def run(self, url: urlutil.Url) -> Tuple[bool, Dict]:
        url = url.join('/uddiexplorer/SearchPublicRegistries.jsp')

        err, response = self.cli.r_super(url.string(), timeout=5)
        if err:
            return False, err
        if response.status_code == 200:
            return True, response.url
        return False, response


if __name__ == '__main__':
    import time

    plugin = Plugin()

    s_time = time.time()
    print(plugin.do_testing('scanme.nmap.org'))
    print('total time(s):', time.time() - s_time)

    s_time = time.time()
    print(plugin.do_testing('192.168.245.128'))
    print('total time(s):', time.time() - s_time)
