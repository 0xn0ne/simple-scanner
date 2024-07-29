import random
import socket
import time
import traceback
from typing import Any, Callable, Dict, Tuple

import urllib3

urllib3.disable_warnings()

try:
    from utils import (LANG, PLUGIN_TYPE, http_client, logger, net_echo,
                       pro_async, sockets, urlutil)
except:
    import pathlib
    import sys

    sys.path.append(pathlib.Path(__file__).parent.parent.__str__())
    from utils import (LANG, PLUGIN_TYPE, http_client, logger, net_echo,
                       pro_async, sockets, urlutil)

log = logger.new('simple-scanner', logger.DBG, logger.FORMAT_PRD)


class Info:
    def __init__(
        self,
        name: str,
        catalog: str,
        protocol: str,
        port: int,
        ssl_protocol: str = None,
        ssl_port: int = 0,
        itype: int = PLUGIN_TYPE.MODULE,
    ) -> None:
        # 字符型，漏洞名称
        self.name = name
        # 字符型，漏洞编号，比如 CVE/CAN/BUGTRAQ/CNCVE/CNVD/CNNVD
        self.catalog = catalog
        # 字符型，漏洞相关的协议
        self.protocol = protocol
        # 数字型，默认检测端口号
        self.port = int(port)
        # 字符型，如有，漏洞相关的SSL协议
        self.ssl_protocol = ssl_protocol
        # 数字型，如有，默认检测SSL端口号
        self.ssl_port = int(ssl_port)
        # 数字型，漏洞类型，MODULE 为模块检测，POC为原理检测
        self.itype = itype


class PluginBase:
    def __init__(self, echo: net_echo.EchoServiceBase = None):
        info = self.set_info()
        if isinstance(info, Info):
            self.info = info
        else:
            self.info = Info(**self.set_info())
        # 检测插件名称编号
        if not self.info.name and not self.info.catalog:
            raise ValueError(LANG.t('the "name" and "catalog" of the plugin are empty, one of them must be set.'))
        # 检测插件协议端口
        if not self.info.protocol or not self.info.port:
            raise ValueError(
                LANG.t(
                    'the "protocol" and "port" information for plugins with name "{}" and catalog "{}" is empty, you must set the network protocol used by the plugin.'.format(
                        self.info.name, self.info.catalog
                    )
                )
            )
        # 无法配置协程池子 TypeError: cannot pickle 'gevent._gevent_cevent.Event' object，交给函数自行调用
        # self.async_pool = pro_async.AsyncPool()
        self.cli_mng = sockets.ClientManager()
        self.echo = echo

    def __repr__(self):
        string_attrs = ''
        for key in self.info.__dict__:
            attr = getattr(self.info, key)
            if isinstance(attr, Callable) or key.startswith('_'):
                continue
            string_attrs += f', {key}={getattr(self.info, key)}'
        ret = f'<{self.info.__module__}.{type(self.info).__name__} object at {hex(id(self))}{string_attrs}>'
        return ret

    def https_or_http(self, url: urlutil.Url, *args, **kwargs) -> Tuple[str | None, int | None]:
        """探测当前目标使用的是 http 或 https 协议

        Args:
            url (urlutil.Url): Url 对象

        Returns:
            Tuple[str | None, int | None]: 返回协议类型和可用的端口号
        """
        # 有可能不输入端口，不输入端口使用插件默认的端口
        port = url.port if url.port else self.info.port
        ssl_port = url.port if url.port else self.info.ssl_port
        # 起协程分别探测http或https协议
        ayn_pool = self.make_async_pool()
        hcli = self.make_http_client(tries=2, timeout=1)
        ayn_pool.sp_by_key('https', hcli.rq, 'https://{}:{}'.format(url.host, ssl_port), verify=False)
        ayn_pool.sp_by_key('http', hcli.rq, 'http://{}:{}'.format(url.host, port), verify=False)
        err, _ = ayn_pool.get_by_key('https')
        if not err:
            return 'https', ssl_port
        err, _ = ayn_pool.get_by_key('http')
        if not err:
            return 'http', port
        return None, port

    def do_testing(self, url: str | urlutil.Url, data: Dict = {}) -> Dict[str, bool | str | int | Any]:
        start_time = time.time()
        ret = {
            'NAME': self.info.name,
            'CATALOG': self.info.catalog,
            'PROTOCOL': self.info.protocol,
            'PLUGIN_TYPE': PLUGIN_TYPE.v2k(self.info.itype),
            'IS_EXIST': False,
            'HOST': '',
            'PORT': 0,
        }
        if isinstance(url, str):
            url = urlutil.Url(url)
        if not self.is_vaild_url(url):
            ret['DATA'] = 'incorrect address "{}"'.format(url)
            return ret

        url.port = url.port or self.info.port
        log.dbg('running {}, url: {}, data: {}'.format(self.info.catalog or self.info.name, url, data))
        try:
            ret['IS_EXIST'], ret['DATA'] = self.run(url, **data)
        except Exception as e:
            ret['IS_EXIST'], ret['DATA'] = False, traceback.format_exc()
        ret.update({'PROTOCOL': url.protocol, 'HOST': url.host, 'PORT': url.port, 'URL': url.get_full()})

        running_times = time.time() - start_time
        if running_times > 8:
            log.dbg(
                'finish {}, times: {:.2}s, url: {}, data: {}'.format(
                    self.info.catalog or self.info.name, time.time() - start_time, url, data
                )
            )
        # # 测试专用记录日志，上线清理
        # running_times = time.time() - start_time
        # # 超过8s记录插件信息，用于优化
        # if running_times > 8:
        #     with open(
        #         '.cache/runtimes-{}-{}.txt'.format(int(time.time() - start_time), self.info.catalog),
        #         'a',
        #         encoding='utf-8',
        #     ) as file:
        #         file.write(
        #             'TIME(s): {}\nURL: {}\nDATA: {}\nRETURN: {}\n\n'.format(time.time() - start_time, url, data, ret)
        #         )
        return ret

    def make_async_pool(self, size: int = None, greenlet_class: object = None) -> pro_async.AsyncPool:
        """创建协程池子，需要注意的是，在插件单独调试的情况下，因为没有做 geven 的猴子补丁，协程不会正常运行

        Args:
            size (int, optional): 单个池子同时运行的协程数量。默认：None
            greenlet_class (object, optional): 不建议调整。默认：None

        Returns:
            pro_async.AsyncPool: 协程池子实例对象
        """
        return pro_async.AsyncPool(size, greenlet_class)

    def make_http_client(
        self,
        headers: Dict[str, str] = None,
        tries: int = 2,
        timeout: float = 3,
    ):
        return http_client.HttpClient(headers, tries, timeout)

    def make_tcp_client(
        self,
        host: str,
        port: int,
        family: socket.AddressFamily | int = None,
        _type: socket.SocketKind | int = None,
        proto: int = None,
        file_no: int | None = None,
    ):
        # 不及时close，是不是会造成大量的内存浪费？
        return self.cli_mng.new_tcp(host, port, family, _type, proto, file_no)

    # 先不用，不成熟
    def make_echo_tcp(self, pre_id: str = ''):
        """
        如果使用 TCP 的反射功能，不能像 DNS 反射一样直接把 rid 加在返回的域名前后，因为网络无法识别这类地址无法反射，只能放在如 http 的 path、header、body 中
        """
        if not self.echo or self.echo._type.lower() != 'http' and self.echo._type.lower() != 'tcp':
            raise ModuleNotFoundError('requires http or tcp type reflection.')
        return self.echo.get_random_id(pre_id)

    # 先不用，不成熟
    def make_echo_dns(self, pre_id: str = ''):
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
        # 留给脚本自己处理默认协议的工作
        # if not url.port:
        #     url.port = self.info.port
        # if not url.protocol:
        #     url.protocol = self.info.protocol
        # if not url.protocol in self.info.protocol:
        #     # 协议不对，跳过检测
        #     return False
        return True

    def set_info(self) -> Dict[str, Any]:
        raise NotImplementedError('the plugin does not use the set_info() function to set information')
        # return Info(
        #     # 字符型，漏洞名称
        #     name='',
        #     # 字符型，漏洞编号，比如 CVE/CAN/BUGTRAQ/CNCVE/CNVD/CNNVD
        #     catalog='',
        #     # 数字型，漏洞类型，MODULE 为模块检测，POC为原理检测
        #     itype=PLUGIN_TYPE.MODULE,
        #     # 字符型，漏洞相关的协议
        #     protocol='http',
        #     # 数字型，默认检测端口号
        #     port=80,
        #     # 字符型，如有，漏洞相关的SSL协议
        #     ssl_protocol='https',
        #     # 数字型，如有，默认检测SSL端口号
        #     ssl_port=443,
        # )

    def run(self, url: urlutil.Url, *args, **kwargs) -> Tuple[bool, Any]:
        """插件自定义的函数

        Args:
            url (urlutil.Url): 将输入进行解析后得到的URL对象

        Raises:
            NotImplementedError: 未改写直接调用该函数会直接报错

        Returns:
            Tuple[bool, Any]: 第一返回的信息用于是表示插件是否检测到，第二个信息为需要存入结果的数据
        """
        raise NotImplementedError(
            'please rewrite the run function first, plugin name: {}, plugin catalog: {}'.format(
                self.info.name, self.info.catalog
            )
        )
