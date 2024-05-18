import csv
import fnmatch
import importlib
import json
import pathlib
import time

import pandas

from utils import LANG, NET_ECHO, net_echo, process, progress_bar

PATH_CACHE = 'cache'

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

    # 目标解析
    target_list = []
    for target in args.targets:
        t_list = []
        t_path = pathlib.Path(target)
        if t_path.is_file():
            target_list.extend(t_path.read_text(encoding='utf-8').split('\n'))
            continue
        if t_path.is_dir():
            continue
        target_list.append(target)

    # 应用插件解析
    plugin_list = []
    for filepath in pathlib.Path('plugins').glob('*'):
        if filepath.name.startswith('__') or not filepath.name.endswith('.py') or filepath.is_dir():
            continue

        module_name = filepath.name.split('.')[0]
        module = importlib.import_module('.{}'.format(module_name), 'plugins')
        if 'Plugin' not in module.__dir__():
            continue
        plugin = module.Plugin(NET_ECHO)
        if not args.module:
            plugin_list.append(plugin)
            continue
        for match in args.module:
            match = match.lower().replace('-', '_')
            plugin_name = plugin.info.name.lower().replace('-', '_') if plugin.info.name else ''
            catalog = plugin.info.catalog.lower().replace('-', '_') if plugin.info.catalog else ''
            if fnmatch.fnmatch(plugin_name, match) or fnmatch.fnmatch(catalog, match):
                plugin_list.append(plugin)
    if not plugin_list:
        print(LANG.t('[!] plugin list is empty, exit.'))
        exit(0)

    pool = process.new(max_workers=args.process_number)
    for target in target_list:
        for plugin in plugin_list:
            pool.submit_super(plugin.do_testing, target)

    ret = []
    probar = progress_bar.new()
    print('[*] scanning...')
    for result in probar.iter(pool.result_yield(), total=len(target_list) * len(plugin_list)):
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

    filename = 'results-{}'.format(time.strftime("%m%d.%H%M", time.localtime()))
    if args.output_format == 'json':
        out_path = pathlib.Path(filename + '.json')
        with open(out_path, 'w', encoding='utf-8') as _f:
            _f.write(json.dumps(ret))
    else:
        out_path = pathlib.Path(filename + '.csv')
        dataframe = pandas.DataFrame(ret)
        dataframe.to_csv(out_path, quoting=csv.QUOTE_MINIMAL)
    print('[*] output:', out_path.absolute().__str__())
