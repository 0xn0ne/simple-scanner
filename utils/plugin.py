import random
import time
import traceback
from typing import Any, Dict, List, Tuple, Union

try:
    from utils import (LANG, PLUGIN_TYPE, USER_AGENT_LIST, http_client,
                       net_echo, sockets, urlutil)
except:
    import pathlib
    import sys

    sys.path.append(pathlib.Path(__file__).parent.parent.__str__())
    from utils import (LANG, PLUGIN_TYPE, USER_AGENT_LIST, http_client,
                       net_echo, sockets, urlutil)


class Info:
    def __init__(
        self,
        name: str = '',
        catalog: str = '',
        itype: int = PLUGIN_TYPE.MODULE,
        protocols: List[str] = None,
        port: int = 80,
    ) -> None:
        self.name = name
        self.catalog = catalog
        self.itype = itype
        self.protocols = protocols
        self.port = port


class PluginBase:
    def __init__(self, echo: net_echo.EchoServiceBase = None):
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
        ret = self.http.is_https(url.host, url.port)
        if ret:
            return 'https'
        return 'http'

    def do_testing(self, url: Union[str, urlutil.Url], data: Dict = None) -> Dict:
        ret = {
            'name': self.info.name,
            'catalog': self.info.catalog,
            'protocol': ','.join(self.info.protocols),
            'plugin_type': PLUGIN_TYPE.v2k(self.info.itype),
        }
        data = data or {}
        if isinstance(url, str):
            url = urlutil.Url(url)
        if not self.is_vaild_url(url):
            ret.update(
                {
                    'is_exists': False,
                    'protocol': '',
                    'host': '',
                    'port': 0,
                    'data': {'msg': 'incorrect address "{}"'.format(url)},
                }
            )
            return ret
        url.port = url.port or self.info.port
        self.http = http_client.new(
            tries=3, headers={'User-Agent': USER_AGENT_LIST[random.randint(0, len(USER_AGENT_LIST) - 1)]}
        )
        self.tcp = self.cli_mng.new_tcp(url.host, url.port)
        try:
            ret['is_exists'], ret['data'] = self.run(url, **data)
            if self.tcp.is_connect():
                self.tcp.close()
        except Exception as e:
            ret['is_exists'], ret['data'] = False, traceback.format_exc()
        ret.update({'protocol': url.protocol, 'host': url.host, 'port': url.port, 'url': url.get_full()})
        return ret

    def make_tcp_echo(self, pre_id: str = ''):
        """
        如果使用 TCP 的反射功能，不能像 DNS 反射一样直接把 rid 加在返回的域名前后，因为网络无法识别这类地址无法反射，只能放在如 http 的 path、header、body 中
        """
        if not self.echo or self.echo._type.lower() != 'http' and self.echo._type.lower() != 'tcp':
            raise ModuleNotFoundError('requires http or tcp type reflection.')
        return self.echo.get_random_id(pre_id)

    def make_dns_echo(self, pre_id: str = ''):
        if not self.echo or self.echo._type.lower() != 'dns' and self.echo._type.lower() != 'tcp':
            raise ModuleNotFoundError('requires dns type reflection.')
        return self.echo.get_random_id(pre_id)

    def get_results(self, random_id: str):
        if not self.echo:
            raise ModuleNotFoundError('requires network echo.')
        return self.echo.get_results(random_id)

    def is_vaild_url(self, url: urlutil.Url) -> bool:
        if not url.host:
            # 没有host，跳过检测
            # raise ValueError('incorrect address "{}"'.format(url))
            return False
        if not url.protocol:
            url.protocol = self.info.protocols[0]
        if not url.protocol in self.info.protocols:
            # 协议不对，跳过检测
            return False
        return True

    def set_info(self) -> Dict[str, Any]:
        raise NotImplementedError('the plugin does not use the set_info() function to set information')
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
        """_summary_

        Args:
            url (urlutil.Url): _description_

        Raises:
            NotImplementedError: 未改写直接调用该函数会直接报错

        Returns:
            Tuple[bool, Any]: _description_
        """
        raise NotImplementedError(
            'please rewrite the run function first, plugin name: {}, plugin catalog: {}'.format(
                self.info.name, self.info.catalog
            )
        )
