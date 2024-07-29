# _*_ coding:utf-8 _*_
# 目前不支持IPV6
import re
import sys

from gevent import monkey

monkey.patch_all(thread=False, httplib=True)
import fnmatch
import importlib
import json
import pathlib
import time
from typing import Dict, List, Set

from utils import (LANG, NET_ECHO, logger, net_echo, network, plugin, process,
                   progress_bar, save_csv, urlutil)

PATH_CACHE = pathlib.Path('.cache')

log = logger.new('simple-scanner', logger.INF, format_string=logger.FORMAT_PRD)
log.set_handle_console()
log.set_handle_file_timed_rotating(PATH_CACHE.joinpath('ss.log'))

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='''
    ███████╗██╗███╗   ███╗██████╗ ██╗     ███████╗    ███████╗
    ██╔════╝██║████╗ ████║██╔══██╗██║     ██╔════╝    ██╔════╝
    ███████╗██║██╔████╔██║██████╔╝██║     █████╗      ███████╗
    ╚════██║██║██║╚██╔╝██║██╔═══╝ ██║     ██╔══╝      ╚════██║
    ███████║██║██║ ╚═╝ ██║██║     ███████╗███████╗    ███████║
    ╚══════╝╚═╝╚═╝     ╚═╝╚═╝     ╚══════╝╚══════╝    ╚══════╝
    v0.2.4
    by 0xn0ne, https://github.com/0xn0ne/simple-scanner
''',
    )
    parser.add_argument(
        '-t',
        '--targets',
        required=True,
        nargs='+',
        help=LANG.t('scanning targets, or scanning target list files (e.g. "127.0.0.1:80").'),
    )
    '扫描目标，或扫描目标列表文件'
    parser.add_argument(
        '-m',
        '--module',
        nargs='+',
        help=LANG.t('vulnerability plugins name used, default scan all modules (e.g. "CVE-2014-*").'),
    )
    parser.add_argument(
        '-p', '--process-number', default=8, type=int, help=LANG.t('number of program processes, default 5 processes.')
    )
    parser.add_argument(
        '-o',
        '--output-format',
        type=str,
        help=LANG.t('output file format, available formats json, csv. default csv format.'),
    )
    parser.add_argument(
        '-i',
        '--interval',
        type=int,
        default=0,
        help=LANG.t('time interval (in seconds) between submitting a task to the process pool.'),
    )
    # parser.add_argument(
    #     '-e',
    #     '--net-echo',
    #     type=str,
    #     help=LANG.t(
    #         'network reflection mode used, available dnslogorg, dnslogcn, localsocket. default dnslogorg. !!!note: there is a difference between tcp reflection and dns reflection detection logic, and you need to pay attention to what type of reflection tool the target POC is using when using it.'
    #     ),
    # )
    parser.add_argument(
        '-is',
        '--is-silent',
        action='store_true',
        help=LANG.t(
            'silent mode: when turned on, no hit data will be output on the console. use a progress bar instead.'
        ),
    )
    parser.add_argument(
        '-dps',
        '--disable-port-scan',
        action='store_true',
        help=LANG.t(
            'disable port scanning. note: if the port not open, the program sending PAYLOAD will cause meaningless waiting time for a response'
        ),
    )

    args = parser.parse_args()
    log.inf(LANG.t('initializing...'))
    s_time = time.time()
    path_output = pathlib.Path(__file__).parent.joinpath(PATH_CACHE).mkdir(exist_ok=True, parents=True)

    NET_ECHO = None
    # 网络反射工具预加载，先禁用
    # if args.net_echo == 'dnslogcn':
    #     NET_ECHO = net_echo.DnslogCn()
    # elif args.net_echo == 'dnslogorg':
    #     NET_ECHO = net_echo.DnslogOrg()
    # elif args.net_echo == 'localsocket':
    #     NET_ECHO = net_echo.LocalSocket()
    # else:
    #     NET_ECHO = None
    # if NET_ECHO:
    #     NET_ECHO.start_service()

    # 插件筛选
    plugin_list: List[plugin.PluginBase] = []
    for filepath in pathlib.Path('plugins').glob('*'):
        if filepath.name.startswith('__') or not filepath.name.endswith('.py') or filepath.is_dir():
            continue

        module_name = filepath.name.split('.')[0]
        module = importlib.import_module('.{}'.format(module_name), 'plugins')
        if 'Plugin' not in module.__dir__():
            continue
        _plugin = module.Plugin(NET_ECHO)
        if not args.module:
            plugin_list.append(_plugin)
            continue
        for match in args.module:
            match = match.lower().replace('-', '_')
            plugin_name = _plugin.info.name.lower().replace('-', '_') if _plugin.info.name else ''
            catalog = _plugin.info.catalog.lower().replace('-', '_') if _plugin.info.catalog else ''
            if fnmatch.fnmatch(plugin_name, match) or fnmatch.fnmatch(catalog, match):
                plugin_list.append(_plugin)
    if not plugin_list:
        log.wrn(LANG.t('plugin list is empty, exit.'))
        exit(0)

    # 收集默认端口
    plugin_port_list = set()
    for _plugin in plugin_list:
        plugin_port_list.add(_plugin.info.port)
        if _plugin.info.ssl_port:
            plugin_port_list.add(_plugin.info.ssl_port)

    # 目标解析
    # 存放host和port数据，用于端口探测，KEY为host，VAL为端口清单
    infos_for_portscan: Dict[str, Set[int]] = {}
    # 存放原始输入数据，包括协议，路径等数据，用于插件扫描，KEY为net_location（用于后续快速匹配存活与不存活端口），VAL为URL清单
    infos_for_plugin: Dict[str, Set[urlutil.Url]] = {}
    for targets in args.targets:
        t_list = []
        t_path = pathlib.Path(targets)
        # 输入的是文件夹，跳过
        if t_path.is_dir():
            continue
        # 输入的是文件读取并解析
        elif t_path.is_file():
            targets = re.split(r'[\s;,；，]', t_path.read_text(encoding='utf-8'))
        # 输入的ip或域名
        else:
            targets = [targets]
        # 将 target 转化为 url 对象，并存放端口记录用于后续主机端口扫描
        for target in targets:
            url = urlutil.Url(target, False)
            # 因为关闭了URL检验，判断是否正确识别host，无法识别直接跳过
            if not url.host:
                continue
            if url.host not in infos_for_portscan:
                infos_for_portscan[url.host] = set()
            # URL写法的几种情况：
            # 有host，此时端口为0，使用默认插件端口
            # 有host和端口，此时端口为指定端口
            # 有host和协议，除非协议无法识别，此时端口为协议默认端口
            if url.port > 0:
                infos_for_portscan[url.host].add(url.port)
                if url.netloc not in infos_for_plugin:
                    infos_for_plugin[url.netloc] = set()
                infos_for_plugin[url.netloc].add(url)
            else:
                infos_for_portscan[url.host].update(plugin_port_list)

    path_hosts_info = '! not port scanning file.'
    port_alive: Set[str] = set()
    if not args.disable_port_scan:
        host_num = len(infos_for_portscan.keys())
        port_num = sum([len(y) for y in infos_for_portscan.values()])
        log.inf(LANG.t('ports scanning, total of {} hosts, {} ports...').format(host_num, port_num))
        # 存活端口探测
        port_scanner = network.Scanner()
        for host in infos_for_portscan:
            port_scanner.scan_run(host, infos_for_portscan[host], is_check_alive=False, is_yield=False)
            # 清空端口清单，后续仅存放存活端口
            infos_for_portscan[host] = set()
        probar = progress_bar.new()
        for itor in probar.iter(port_scanner.get_yield_tcp(), total=host_num * port_num):
            # itor 只会是IP，如果IP在infos_for_portscan则说明原始目标的host就是IP，如果不在说明原始目标是域名
            if itor[0] in infos_for_portscan:
                port_alive.add('{}:{}'.format(itor[0], itor[1]))
            else:
                for host in port_scanner.ip_info[itor[0]]['RECORDS']:
                    port_alive.add('{}:{}'.format(host, itor[1]))

        # 保存主机存活信息
        path_hosts_info = pathlib.Path('hosts-info-{}.csv'.format(time.strftime('%y%m%d.%H%M', time.localtime())))
        save_csv(port_scanner.gen_expand_ipinfo(), path_hosts_info)
        log.inf(LANG.t('host info saved:', path_hosts_info.absolute().__str__()))
    else:
        port_alive = set(infos_for_plugin.keys())

    # 交叉匹配取差集核对可用目标
    targets = set(infos_for_plugin.keys())
    # 清除不存活目标
    for unable in targets.difference(port_alive):
        del infos_for_plugin[unable]
    # 添加使用插件自带端口探测的目标
    for netloc in port_alive.difference(targets):
        if netloc not in infos_for_plugin:
            infos_for_plugin[netloc] = set()
        infos_for_plugin[netloc].add(urlutil.Url(netloc))

    # todo: 实时写入数据；无法实现，特别是写json的时候每次都要重新序列化
    # 启动插件扫描
    log.inf(LANG.t('adding plugins...'))
    pool = process.new(max_workers=args.process_number)
    for netloc in infos_for_plugin:
        for url in infos_for_plugin[netloc]:
            for _plugin in plugin_list:
                # 如果输入的 target 带协议，则匹配协议是否正确，否则全插件扫描
                if url.protocol and url.protocol != _plugin.info.protocol and url.protocol != _plugin.info.ssl_protocol:
                    continue
                # 加入进程池启动扫描，如果 target 使用最简洁写法的情况（如：eg.com），target 只有 host 属性，插件自己做好端口、协议判断
                pool.sm(_plugin.do_testing, url)
                if args.interval > 0:
                    time.sleep(args.interval)

    # 没有匹配任何插件，没有可用目标，退出扫描
    if not pool.jobs:
        log.wrn(LANG.t('scannable target not found. if port scanning is enabled, check file:', path_hosts_info))
        sys.exit(0)

    ret = []
    probar = progress_bar.new()
    probar.print_func = log.inf
    log.inf(LANG.t('wait for plugin scanning...'))
    for result in probar.iter(pool.yield_result(), total=len(pool.jobs)):
        with progress_bar.redirect_stdout():
            if result['IS_EXIST'] and not args.is_silent:
                probar.print(
                    LANG.t(
                        '{}, {}, url: {}, info: {}',
                        result['CATALOG'],
                        result['NAME'],
                        result['URL'],
                        result['DATA'].__str__().strip().split('\n')[0],
                    )
                )
            ret.append(result)

    path_hosts_vuls = pathlib.Path('hosts-plugin-result-{}.csv'.format(time.strftime('%y%m%d.%H%M', time.localtime())))
    if args.output_format == 'json':
        path_hosts_vuls = path_hosts_vuls.with_suffix('.json')
        with open(path_hosts_vuls, 'w', encoding='utf-8') as _f:
            _f.write(json.dumps(ret))
    else:
        save_csv(ret, path_hosts_vuls)

    log.inf(LANG.t('plugin result saved: {}', path_hosts_vuls.absolute().__str__()))
