import re

from gevent import monkey

monkey.patch_all(thread=False)
import csv
import fnmatch
import importlib
import json
import pathlib
import sys
import time
from typing import Dict, List, Union

from utils import (LANG, NET_ECHO, net_echo, network, plugin, process,
                   progress_bar, save_csv, urlutil)

PATH_CACHE = '.cache'

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
    v0.2.3
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
        '-e',
        '--net-echo',
        type=str,
        help=LANG.t(
            'network reflection mode used, available dnslogorg, dnslogcn, localsocket. default dnslogorg. !!!note: there is a difference between tcp reflection and dns reflection detection logic, and you need to pay attention to what type of reflection tool the target POC is using when using it.'
        ),
    )
    parser.add_argument(
        '-s',
        '--is-silent',
        action='store_true',
        help=LANG.t(
            'silent mode: when turned on, no hit data will be output on the console. use a progress bar instead.'
        ),
    )

    args = parser.parse_args()
    print('[*] initializing...')
    s_time = time.time()
    path_output = pathlib.Path(__file__).parent.joinpath(PATH_CACHE).mkdir(exist_ok=True, parents=True)

    # 网络反射工具预加载
    if args.net_echo == 'dnslogcn':
        NET_ECHO = net_echo.DnslogCn()
    elif args.net_echo == 'dnslogorg':
        NET_ECHO = net_echo.DnslogOrg()
    elif args.net_echo == 'localsocket':
        NET_ECHO = net_echo.LocalSocket()
    else:
        NET_ECHO = None

    if NET_ECHO:
        NET_ECHO.start_service()

    # 应用插件解析
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
        print(LANG.t('[!] plugin list is empty, exit.'))
        exit(0)

    # 收集默认端口
    default_port_list = []
    for _plugin in plugin_list:
        default_port_list.append(int(_plugin.info.port))

    # 目标解析
    target_list: List[urlutil.Url] = []
    target_port_map: Dict[urlutil.Url, List[int]] = {}
    for targets in args.targets:
        t_list = []
        t_path = pathlib.Path(targets)
        if t_path.is_dir():
            continue
        elif t_path.is_file():
            targets = re.split(r'[\s;,；，]', t_path.read_text(encoding='utf-8'))
        else:
            targets = [targets]
        for target in targets:
            url = urlutil.Url(target)
            target_list.append(urlutil.Url(target))
            if url.host not in target_port_map:
                target_port_map[url.host] = []
            target_port_map[url.host].append(url.port)

    print('[*] ports scanning...')
    # 存活端口探测
    port_scanner = network.Scanner()
    for host in target_port_map:
        port_list = target_port_map[host] if target_port_map[host] else default_port_list
        target_port_map[host] = [i[1] for i in port_scanner.scan_run(host, target_port_map[host], is_check_alive=False)]

    # 保存主机存活信息
    path_hosts_info = pathlib.Path('hosts-info-{}.csv'.format(time.strftime("%m%d.%H%M", time.localtime())))
    save_csv(list(port_scanner.hosts_info.values()), path_hosts_info)
    print('[!] host info saved:', path_hosts_info.absolute().__str__())

    # 启动插件扫描
    pool = process.new(max_workers=args.process_number)
    for targets in target_list:
        for _plugin in plugin_list:
            # 不存活的端口排除
            if (
                not int(_plugin.info.port) in target_port_map[targets.host]
                and not targets.port in target_port_map[targets.host]
            ):
                continue
            pool.sm(_plugin.do_testing, targets)
    ret = []
    probar = progress_bar.new()
    if pool.jobs:
        print('[*] plugin scanning...')
        for result in probar.iter(pool.yield_result(), total=len(pool.jobs)):
            with progress_bar.redirect_stdout():
                if result['is_exists']:
                    print(
                        LANG.t(
                            '[+] {}, {}, url: {}, info: {}',
                            result['catalog'],
                            result['name'],
                            result['url'],
                            result['data'].__str__().strip().split('\n')[0],
                        )
                    )
                ret.append(result)

        path_hosts_vuls = pathlib.Path(
            'hosts-vulnerabilities-{}.csv'.format(time.strftime("%m%d.%H%M", time.localtime()))
        )
        if args.output_format == 'json':
            path_hosts_vuls = path_hosts_vuls.with_suffix('json')
            with open(path_hosts_vuls, 'w', encoding='utf-8') as _f:
                _f.write(json.dumps(ret))
        else:
            save_csv(ret, path_hosts_vuls)
    else:
        print('[!] scannable target not found, check file:', path_hosts_info)

    print('[!] host vuls saved:', path_hosts_vuls.absolute().__str__())
