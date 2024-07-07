import pathlib
import sys
from typing import Any, Tuple

try:
    from utils import PLUGIN_TYPE, plugin, urlutil
except:
    sys.path.append(pathlib.Path(__file__).parent.parent.__str__())
    from utils import PLUGIN_TYPE, plugin, urlutil


class Plugin(plugin.PluginBase):
    def set_info(self):
        return {
            'name': 'Weblogic Console Login Page',
            'catalog': None,
            'itype': PLUGIN_TYPE.MODULE,
            'protocols': ['http', 'https'],
            'port': '7001',
        }

    def run(self, url: urlutil.Url, *args, **kwargs) -> Tuple[bool, Any]:
        url.protocol = url.protocol or self.http_or_https(url)
        if not url.protocol:
            return False, 'the network protocol does not match.'
        path = url.path if url.path and url.path != '/' else '/console/login/LoginForm.jsp'

        url = url.join(path)

        err, response = self.http.rq(url.get_full(), timeout=5)
        if err:
            return False, err
        return response.status_code == 200, response.status_code


if __name__ == '__main__':
    import time

    from utils import net_echo

    nc = net_echo.DnslogCn()
    nc.start_service()
    plugin = Plugin(nc)

    s_time = time.time()
    print(plugin.do_testing('scanme.nmap.org'))
    print('total time(s):', time.time() - s_time)

    # 3次重试机制存在，连接失败的情况会重试3次
    s_time = time.time()
    print(plugin.do_testing('https://scanme.nmap.org'))
    print('total time(s):', time.time() - s_time)

    s_time = time.time()
    print(plugin.do_testing('192.168.245.128'))
    print('total time(s):', time.time() - s_time)

    s_time = time.time()
    print(plugin.do_testing('http://192.168.245.128/admin/login/LoginForm.jsp'))
    print('total time(s):', time.time() - s_time)
