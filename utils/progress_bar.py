#!/bin/python3
# _*_ coding:utf-8 _*_
#
# progress_bar.py
# 进度条处理工具
# 依赖安装：pip install tqdm
# 参考链接：
#   tqdm 官方文档：https://tqdm.github.io/
#   print 函数处理：https://stackoverflow.com/questions/36986929/redirect-print-command-in-python-script-through-tqdm-write

import contextlib
import sys
from typing import Iterable

import tqdm


class DummyFile:
    def __init__(self, file):
        if file is None:
            file = sys.stderr
        self.file = file

    def write(self, text: str):
        if not len(text.rstrip()) > 0:
            # avoid print() second call (useless '\n')
            return
        tqdm.tqdm.write(text, file=self.file)


@contextlib.contextmanager
def redirect_stdout(file=None):
    """
    重定向输出，在 tqdm 的进度条输出过程中，使用 print 输出内容时正常输出，确保 tqdm 的进度条不会错乱
    """
    if file is None:
        file = sys.stderr
    save_stdout = sys.stdout
    sys.stdout = DummyFile(file)
    yield
    sys.stdout = save_stdout


class ProgressBar:
    def __init__(
        self, format='{n_fmt}/{total_fmt} [{bar}] {elapsed}<{remaining},{rate_fmt}{postfix}', mininterval=1, ncols=80
    ) -> None:
        self.format = format
        self.mininterval = mininterval
        self.ncols = ncols
        self.msg_list = []
        self.print_func = print

    def print(self, msg: str, *args, **kwargs):
        self.msg_list.append(msg)

    def iter(
        self,
        its: Iterable,
        total: int = None,
        position: int = 0,
        format: str = None,
        mininterval: int = 1,
        ncols: int = 80,
        *args,
        **kwargs
    ):
        for it in tqdm.tqdm(
            its,
            total=total,
            bar_format=format or self.format,
            mininterval=mininterval or self.mininterval,
            ncols=ncols or self.ncols,
            position=position,
            *args,
            **kwargs
        ):
            yield it
            while self.msg_list:
                with redirect_stdout():
                    self.print_func(self.msg_list.pop(0))


def new(*args, **kwargs):
    return ProgressBar(*args, **kwargs)


if __name__ == '__main__':
    import time

    probar = ProgressBar()
    number = 100 * 1024 * 1024

    # optimized usage, but with ~16% performance loss
    s_time = time.time()
    for batch in probar.iter(range(number)):
        if batch % (number / 5) != 0:
            continue
        probar.print(batch)

    print('total time(s):', time.time() - s_time)
    print('the out-of-scope print function is not affected.')
    print('all done!')

    # original usage
    s_time = time.time()
    for batch in tqdm.tqdm(range(number)):
        if batch % (number / 5) != 0:
            continue
        with redirect_stdout():
            print(batch)

    print('total time(s):', time.time() - s_time)
