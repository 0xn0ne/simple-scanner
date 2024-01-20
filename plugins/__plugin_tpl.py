#!/usr/bin/env python3
# _*_ coding:utf-8 _*_
# 插件模板，名字头部带 2 个下划线的 py 文件不会加入检测列表
# 更新时间：2024/1/18

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
            # 字符型，漏洞名称
            'name': 'Oracle Weblogic Console Login Page',
            # 字符型，漏洞编号，比如 CVE/CAN/BUGTRAQ/CNCVE/CNVD/CNNVD
            'catalog': '',
            # 数字型，漏洞类型，MODULE 为模块检测，POC为原理检测
            'itype': PLUGIN_TYPE.MODULE,
            # 字符型，漏洞相关的协议
            'protocols': ['http', 'https'],
            # 字符型，默认检测端口号
            'port': '80',
        }

    def run(self, url: urlutil.Url, *args, **kwargs) -> Tuple[bool, Any]:
        """
        需要重写的函数，程序会自动调用 Plugin.run(url) 函数运行，接收的参数一定要带 *args, **kwargs，因为配置文件的数据会导入到插件中
        """
        url.protocol = url.protocol or self.http_or_https(url)  # 检测 protocol 如果不存在自动检测目标是 http 或 https 协议
        if not url.protocol:  # 检测和自动检测都找不到可用协议
            return False, 'the network protocol does not match.'
        path = (
            url.path if url.path and url.path != '/' else '/console/login/LoginForm.jsp'
        )  # 如果输入包含路径的 URL 则使用输入的路径，没有则使用常见的路径

        url = url.join(path)  # URL拼接

        err, response = self.http.rq(url.string(), timeout=5)  # 发出 HTTP 请求
        if err:  # 判断 HTTP 请求有没有发生错误
            return False, err
        return response.status_code == 200, response.status_code  # 返回是否存在漏洞，漏洞相关信息


if __name__ == '__main__':
    import time

    from utils import net_echo

    nc = net_echo.DnslogCn()
    nc.start_service()
    plugin = Plugin(nc)

    s_time = time.time()
    print(plugin.do_testing('scanme.nmap.org'))
    print('total time(s):', time.time() - s_time)

    # HTTP类协议存在3次重试机制，连接失败的情况会重试3次
    s_time = time.time()
    print(plugin.do_testing('scanme.nmap.org:8080'))
    print('total time(s):', time.time() - s_time)

    s_time = time.time()
    print(plugin.do_testing('https://scanme.nmap.org'))
    print('total time(s):', time.time() - s_time)

    s_time = time.time()
    print(plugin.do_testing('https://scanme.nmap.org/admin/login/LoginForm.jsp'))
    print('total time(s):', time.time() - s_time)
