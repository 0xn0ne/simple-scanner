import random
from typing import Dict, Tuple

from utils import PLUGIN_TYPE, USER_AGENT_LIST, http_client, url


class PluginBase:
    info = {'NAME': '', 'CVE': '', 'TYPE': PLUGIN_TYPE.MODULE}

    def __init__(self):
        self.cli = http_client.new(headers={'User-Agent': USER_AGENT_LIST[random.randint(0, len(USER_AGENT_LIST) - 1)]})

    def http_or_https(self, url: url.Url):
        err, response = self.cli.r_super('https://{}:{}/'.format(url.host, url.port), 'HEAD', verify=False)
        if not err:
            return 'https'
        err, response = self.cli.r_super(
            'http://{}:{}/'.format(url.host, url.port), 'HEAD', verify=False, allow_redirects=False
        )
        if not err:
            if 'Location' in response.headers:
                obj_url = url.Url(response.headers['Location'])
                if obj_url.host == url.host and obj_url.port == url.port:
                    return obj_url.scheme
            return 'http'
        return None

    def testing(self, url: url.Url) -> Tuple[bool, Dict]:
        ret = {
            'scheme': url.scheme,
            'host': url.host,
            'port': url.port,
            'name': self.info['CVE'] if self.info['CVE'] else self.info['NAME'],
        }
        ret['is_exists'], ret['data'] = self.run(url)
        return ret

    def run(self, url: url.Url) -> Tuple[bool, Dict]:
        raise NotImplementedError('')


if __name__ == '__main__':
    plugin = PluginBase()
    plugin.testing(url.Url('httpbin.org'))
