import re

from utils import http_client


class Plugin():
    info = {'NAME': 'Weblogic Console', 'CVE': None}
    type = 'MODULE'

    # type = 'POC'

    def __init__(self):
        self.cli = http_client.new(headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })

    def http_or_https(self, host, port):
        err, response = self.cli.r_super('https://{}:{}/'.format(host, port), 'HEAD', verify=False)
        if not err:
            return 'https'
        err, response = self.cli.r_super('http://{}:{}/'.format(host, port), 'HEAD', verify=False,
                                         allow_redirects=False)
        if not err:
            if 'Location' in response.headers:
                r_link = re.search('https?://[a-zA-Z0-9][-a-zA-Z0-9]{,63}(\.[a-zA-Z0-9][-a-zA-Z0-9]{,63})+(:\d{1,5})?',
                          response.headers['Location'], re.I)
                print(10002, r_link.groups())
            return 'http'
        return None

    def is_exists(self, dip, dport, *args, **kwargs) -> (bool, dict):
        r, data = self.cli('http://{}:{}/console/login/LoginForm.jsp'.format(dip, dport), ssl=force_ssl)
        if r and r.status_code == 200:
            return True, {'url': r.url}
        return False, {}


# def run(data: Dict):
#     obj = Plugin()
#     result = {
#         'IP': data['IP'],
#         'PORT': data['PORT'],
#         'NAME': obj.info['CVE'] if obj.info['CVE'] else obj.info['NAME'],
#         'MSG': '',
#         'STATE': False,
#     }
#     result['STATE'], result['MSG'] = obj.light_and_msg(data['IP'], data['PORT'])
#
#     return result

if __name__ == '__main__':
    plugin = Plugin()
    print(10001, plugin.http_or_https('cn.aliyun.com', 80))
