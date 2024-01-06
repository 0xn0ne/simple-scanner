from typing import Dict, Tuple

try:
    from utils import PLUGIN_TYPE, plugin, urlutil
except:
    import pathlib
    import sys

    sys.path.append(pathlib.Path(__file__).parent.parent.__str__())
    from utils import PLUGIN_TYPE, plugin, urlutil


class Plugin(plugin.PluginBase):
    info = {'NAME': 'Weblogic Console', 'CVE': None, 'TYPE': PLUGIN_TYPE.MODULE}

    def set_info(self):
        return {
            'name': 'Weblogic Console Login Page',
            'catalog': '',
            'itype': PLUGIN_TYPE.MODULE,
            'protocols': ['http', 'https'],
            'port': '80',
        }

    def run(self, url: urlutil.Url) -> Tuple[bool, Dict]:
        url.protocol = url.protocol or self.http_or_https(url)
        if not url.protocol:
            return False, {'msg': response}
        path = url.path if url.path and url.path != '/' else '/console/login/LoginForm.jsp'

        url = url.join(path)

        err, response = self.cli.r_super(url.string(), timeout=5)
        if err:
            return False, {'msg': err}
        if response.status_code == 200:
            return True, {'data': response.url, 'msg': 'success'}
        return False, {'msg': response}


if __name__ == '__main__':
    import time

    plugin = Plugin()

    s_time = time.time()
    print(plugin.do_testing('scanme.nmap.org'))
    print('total time(s):', time.time() - s_time)

    # 3次重试机制存在，连接失败的情况会重试3次
    s_time = time.time()
    print(plugin.do_testing('scanme.nmap.org:8080'))
    print('total time(s):', time.time() - s_time)

    s_time = time.time()
    print(plugin.do_testing('https://scanme.nmap.org'))
    print('total time(s):', time.time() - s_time)

    s_time = time.time()
    print(plugin.do_testing('https://scanme.nmap.org/admin/login/LoginForm.jsp'))
    print('total time(s):', time.time() - s_time)
