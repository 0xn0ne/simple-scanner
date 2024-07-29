#!/usr/bin/env python3
# _*_ coding:utf-8 _*_
# 插件模板，名字头部带 2 个下划线的 py 文件不会加入检测列表
# 更新时间：2024/07/28

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
        return plugin.Info(
            # 字符型，漏洞名称
            name='Oracle Weblogic Console Login Page',
            # 字符型，漏洞编号，比如 CVE/CAN/BUGTRAQ/CNCVE/CNVD/CNNVD/None
            catalog=None,
            # 数字型，漏洞类型，MODULE 为模块检测，POC为原理检测
            itype=PLUGIN_TYPE.MODULE,
            # 字符型，漏洞相关的协议
            protocol='http',
            port=7001,
            # 字符型，漏洞相关的加密协议
            ssl_protocol='https',
            # 字符型，默认检测加密端口号
            ssl_port=7001,
        )

    def run(self, url: urlutil.Url, *args, **kwargs) -> Tuple[bool, Any]:
        """
        需要重写的函数，程序会自动调用 Plugin.run(url) 函数运行，接收的参数一定要带 *args, **kwargs，因为配置文件的数据会导入到插件中
        """
        # 检测 protocol 如果不存在自动检测目标是 http 或 https 协议
        if not url.protocol:
            url.protocol, url.port = self.https_or_http(url)
        # 检测和自动检测都找不到可用协议
        if not url.protocol:
            return False, 'the network protocol does not match.'
        # URL拼接
        page_url = url.join('console/login/LoginForm.jsp')

        # 创建 HTTP 客户端
        http = self.make_http_client()
        # 发出 HTTP 请求
        err, response = http.rq(page_url.get_full(), verify=False, timeout=5)
        # 判断 HTTP 请求有没有发生错误
        if err:
            return False, err
        if response.status_code != 200:
            return response.status_code == 200, 'error status code: {}'.format(response.status_code)

        login_url = url.join('console/j_security_check')
        usernames = ['admin', 'root', 'weblogic', 'system']
        passwords = [
            'password',
            'security',
            'weblogic',
            'weblogic123',
            'weblogic@123',
            'Oracle@123',
            'oracle',
            'oracle123',
            'oracle@123',
            'wlcsystem',
            'wlpisystem',
        ]
        # 创建异步池子
        async_pool = self.make_async_pool()
        for usr in usernames:
            for pwd in passwords:
                data = {'j_username': usr, 'j_password': pwd, 'j_character_encoding': 'UTF-8'}
                # 使用异步池子发送爆破请求
                async_pool.sp(http.rq, login_url, 'POST', data=data, allow_redirects=False)

        # ! 事实上这个插件是失败的，因为异步速度太快 Weblogic 会锁账户，这个插件的爆破没有意义，只是为了演示异步池子怎么使用
        # 等待结果返回，并判断
        for err, response in async_pool.get_yeild():
            # 登录成功会跳转 /console 页面，登录失败会跳转 /console/login/LoginForm.jsp
            if 'Location' in response.headers and '/console/login/LoginForm.jsp' not in response.headers['Location']:
                return True, response.request.body

        # 返回是否存在漏洞，漏洞相关信息，返回的第一个参数为是否存在漏洞，第二个参数为漏洞相关信息，可以写任何内容
        return False, 'no available username and password found'


if __name__ == '__main__':
    pass
    # 单插件运行测试时使用 do_testing 函数，但是该函数会阻断错误的输出
    # 也可以手动构造 url 对象直接使用 run 函数运行也行，参考最后一个样例
    import time

    plg = Plugin()

    s_time = time.time()
    print(plg.do_testing('scanme.nmap.org'))
    print('total time(s):', time.time() - s_time)

    # HTTP类协议存在3次重试机制，连接失败的情况会重试3次
    s_time = time.time()
    print(plg.do_testing('scanme.nmap.org:8080'))
    print('total time(s):', time.time() - s_time)

    s_time = time.time()
    print(plg.do_testing('https://scanme.nmap.org'))
    print('total time(s):', time.time() - s_time)

    s_time = time.time()
    url = urlutil.Url('https://scanme.nmap.org/admin/login/LoginForm.jsp')
    print(plg.run(url))
    print('total time(s):', time.time() - s_time)
