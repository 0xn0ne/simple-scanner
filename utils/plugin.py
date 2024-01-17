import random
from typing import Any, Dict, List, Tuple, Union

try:
    from utils import LANG, PLUGIN_TYPE, USER_AGENT_LIST, http_client, urlutil
except:
    import pathlib
    import sys

    sys.path.append(pathlib.Path(__file__).parent.parent.__str__())
    from utils import LANG, PLUGIN_TYPE, USER_AGENT_LIST, http_client, urlutil


class Info:
    # # 字符型，漏洞名称
    # name = ''
    # # 字符型，漏洞编号，比如 CVE/CAN/BUGTRAQ/CNCVE/CNVD/CNNVD
    # catalog = ''
    # # 数字型，漏洞类型，MODULE 为模块检测，POC为原理检测
    # itype = PLUGIN_TYPE.MODULE
    # # 字符型，漏洞相关的协议
    # protocol = 'http'
    # # 数字型，默认端口号，MODULE 为模块检测，POC为原理检测
    # port = '8080'
    def __init__(
        self,
        name: str = '',
        catalog: str = '',
        itype: int = PLUGIN_TYPE.MODULE,
        protocols: List[str] = None,
        port: str = '80',
    ) -> None:
        self.name = name
        self.catalog = catalog
        self.itype = itype
        self.protocols = protocols
        self.port = port


class PluginBase:
    def __init__(self):
        self.info = Info(**self.set_info())
        if not self.info.name and not self.info.catalog:
            raise ValueError(LANG.t('the "name" and "catalog" of the plugin are empty, one of them must be set.'))
        if len(self.info.protocols) < 1:
            raise ValueError(LANG.t('"protocol" are empty, must set the list of network protocols used by the plugin.'))
        self.cli = http_client.new(
            tries=3, headers={'User-Agent': USER_AGENT_LIST[random.randint(0, len(USER_AGENT_LIST) - 1)]}
        )

    def http_or_https(self, url: urlutil.Url):
        err, response = self.cli.r_super('https://{}:{}/'.format(url.host, url.port), 'HEAD', timeout=5)
        if not err:
            return 'https'
        err, response = self.cli.r_super(
            'http://{}:{}/'.format(url.host, url.port), 'HEAD', allow_redirects=False, timeout=5
        )
        if not err:
            if 'Location' in response.headers:
                obj_url = urlutil.Url(response.headers['Location'])
                if obj_url.host == url.host and obj_url.port == url.port:
                    return obj_url.scheme
            return 'http'
        return 'http'

    def do_testing(self, url: str, data: Dict = None) -> Tuple[bool, Dict]:
        ret = {
            'plugin_name': self.info.catalog or self.info.name,
            'plugin_prtcl': ','.join(self.info.protocols),
            'plugin_type': PLUGIN_TYPE.v2k(self.info.itype),
        }
        data = data or {}

        url_obj = self.make_url(url)
        if not url_obj:
            ret.update(
                {
                    'is_exists': False,
                    'protocol': '',
                    'host': '',
                    'port': '',
                    'data': {'msg': 'incorrect address "{}"'.format(url)},
                }
            )
            return ret
        url_obj.port = url_obj.port or self.info.port
        ret['is_exists'], ret['data'] = self.run(url_obj)
        ret.update({'protocol': url_obj.protocol, 'host': url_obj.host, 'port': url_obj.port, 'url': url_obj.string()})

        return ret

    def make_http_echo():
        pass

    def make_dns_echo():
        pass

    def make_url(self, url: str) -> Union[urlutil.Url, Any]:
        new_url = urlutil.new()
        new_url.from_str(url, False)
        if not new_url.host:
            # 没有host，跳过检测
            # raise ValueError('incorrect address "{}"'.format(url))
            return
        if not new_url.protocol:
            new_url.protocol = self.info.protocols[0]
        if not new_url.protocol in self.info.protocols:
            # 协议不对，跳过检测
            return

        return new_url

    def set_info(self) -> Dict[str, Any]:
        return {
            'name': '',
            'catalog': '',
            'itype': PLUGIN_TYPE.MODULE,
            'protocols': ['http', 'https'],
            'port': '80',
        }

    def run(self, url: urlutil.Url) -> Tuple[bool, Dict]:
        raise NotImplementedError('')
