import random
import time
from typing import Any, Dict, List, Tuple, Union

try:
    from utils import LANG, PLUGIN_TYPE, USER_AGENT_LIST, http_client, net_echo, sockets, urlutil
except:
    import pathlib
    import sys

    sys.path.append(pathlib.Path(__file__).parent.parent.__str__())
    from utils import LANG, PLUGIN_TYPE, USER_AGENT_LIST, http_client, net_echo, sockets, urlutil


class Info:
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
    def __init__(self, echo: net_echo.EchoServiceBase):
        self.info = Info(**self.set_info())
        if not self.info.name and not self.info.catalog:
            raise ValueError(LANG.t('the "name" and "catalog" of the plugin are empty, one of them must be set.'))
        if len(self.info.protocols) < 1:
            raise ValueError(
                LANG.t(
                    'the "protocol" information for plugins with name "{}" and catalog "{}" is empty, you must set the list of network protocols used by the plugin.'.format(
                        self.info.name, self.info.catalog
                    )
                )
            )
        self.http = None
        self.cli_mng = sockets.ClientManager()
        self.tcp = None
        self.echo = echo

    def http_or_https(self, url: urlutil.Url, *args, **kwargs):
        err, response = self.http.rq('https://{}:{}/'.format(url.host, url.port), 'HEAD', timeout=5)
        if not err:
            return 'https'
        err, response = self.http.rq(
            'http://{}:{}/'.format(url.host, url.port), 'HEAD', allow_redirects=False, timeout=5
        )
        if not err:
            if 'Location' in response.headers:
                obj_url = urlutil.Url(response.headers['Location'])
                if obj_url.host == url.host and obj_url.port == url.port:
                    return obj_url.protocol
            return 'http'
        return 'http'

    def do_testing(self, url: str, data: Dict = None) -> Dict:
        ret = {
            'name': self.info.name,
            'catalog': self.info.catalog,
            'protocol': ','.join(self.info.protocols),
            'plugin_type': PLUGIN_TYPE.v2k(self.info.itype),
        }
        data = data or {}

        o_url = self.make_url(url)
        if not o_url:
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
        o_url.port = o_url.port or self.info.port
        self.http = http_client.new(
            tries=3, headers={'User-Agent': USER_AGENT_LIST[random.randint(0, len(USER_AGENT_LIST) - 1)]}
        )
        self.tcp = self.cli_mng.new_tcp(o_url.host, o_url.i_port)
        ret['is_exists'], ret['data'] = self.run(o_url, **data)
        ret.update({'protocol': o_url.protocol, 'host': o_url.host, 'port': o_url.port, 'url': o_url.string()})
        if self.tcp.is_connect():
            self.tcp.close()
        return ret

    def make_tcp_echo(self, pre_id: str = ''):
        """
        如果使用 TCP 的反射功能，不能像 DNS 反射一样直接把 rid 加在返回的域名前后，因为网络无法识别这类地址无法反射，只能放在如 http 的 path、header、body 中
        """
        if self.echo._type.lower() != 'http' and self.echo._type.lower() != 'tcp':
            return None
        return self.echo.get_random_id(pre_id)

    def make_dns_echo(self, pre_id: str = ''):
        if self.echo._type.lower() != 'dns':
            return None
        return self.echo.get_random_id(pre_id)

    def get_results(self, random_id: str):
        return self.echo.get_results(random_id)

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
        raise NotImplementedError('')
        # return {
        #     # 字符型，漏洞名称
        #     'name': '',
        #     # 字符型，漏洞编号，比如 CVE/CAN/BUGTRAQ/CNCVE/CNVD/CNNVD
        #     'catalog': '',
        #     # 数字型，漏洞类型，MODULE 为模块检测，POC为原理检测
        #     'itype': PLUGIN_TYPE.MODULE,
        #     # 字符型，漏洞相关的协议
        #     'protocols': ['http', 'https'],
        #     # 字符型，默认检测端口号
        #     'port': '80',
        # }

    def run(self, url: urlutil.Url, *args, **kwargs) -> Tuple[bool, Any]:
        raise NotImplementedError('')
