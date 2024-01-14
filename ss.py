import csv
import fnmatch
import importlib
import json
import pathlib
import time

import pandas

from utils import LANG, process, progress_bar

PATH_CACHE = 'cache'

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='''
    ███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
    ██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
    ███████╗    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
    ╚════██║    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
    ███████║    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
    ╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
    v0.1.1
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
        required=False,
        type=str,
        help=LANG.t('output file format, available formats json, csv. default csv format.'),
    )
    # parser.add_argument(
    #     '-r',
    #     '--is-redirect',
    #     action='store_true',
    #     help=LANG.t(
    #         'whether to automatically use the redirected link if it encounters a redirect, the default is not to use the redirected link.'
    #     ),
    # )
    parser.add_argument(
        '-s',
        '--is-silent',
        action='store_true',
        help=LANG.t(
            'silent mode: when turned on, no hit data will be output on the console. use a progress bar instead.'
        ),
    )

    args = parser.parse_args()

    s_time = time.time()
    path_output = pathlib.Path(__file__).parent.joinpath(PATH_CACHE).mkdir(exist_ok=True, parents=True)

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
        plugin = module.Plugin()
        if not args.module:
            plugin_list.append(plugin)
            continue
        for match in args.module:
            match = match.lower().replace('-', '_')
            plugin_name = plugin.info.name.lower().replace('-', '_')
            catalog = plugin.info.catalog.lower().replace('-', '_')
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
    for result in probar.iter(pool.result_yield(), total=len(target_list) * len(plugin_list)):
        with progress_bar.redirect_stdout():
            if result['is_exists']:
                print(
                    LANG.t(
                        '[+] {}, url: {}, info: {}',
                        result['plugin_name'],
                        result['url'],
                        result['data'],
                    )
                )
            ret.append(result)

    filename = 'results.csv'
    if args.output_format == 'json':
        filename = 'results.json'
        with open(filename, 'w', encoding='utf-8') as _f:
            _f.write(json.dumps(ret))
    else:
        dataframe = pandas.DataFrame(ret)
        dataframe.to_csv(filename, quoting=csv.QUOTE_MINIMAL)
