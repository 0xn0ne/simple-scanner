import pathlib
import time

from utils import LANG

PATH_CACHE = 'cache/results.csv'

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
        help=LANG.t('vulnerability plugins name used, default scan all modules (e.g. "CVE-*").'),
    )
    parser.add_argument(
        '-p', '--process_number', default=8, type=int, help=LANG.t('number of program processes, default 5 processes.')
    )
    parser.add_argument(
        '-o',
        '--output-format',
        required=False,
        type=str,
        help=LANG.t('output file format, available formats json, csv. default csv format.'),
    )
    parser.add_argument(
        '-r',
        '--is-redirect',
        action='store_true',
        help=LANG.t(
            'whether to automatically use the redirected link if it encounters a redirect, the default is not to use the redirected link.'
        ),
    )

    args = parser.parse_args()

    s_time = time.time()
    args.targets = ''
    args.output = args.output if args.output else pathlib.Path(__file__).joinpath(PATH_CACHE)
    pathlib.Path(args.output).parent.mkdir()
