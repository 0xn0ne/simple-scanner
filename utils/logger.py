#!/bin/python3
# _*_ coding:utf-8 _*_
#
# logger.py
# logger 生成工具

import datetime
import io
import logging
import logging.handlers
import pathlib
import sys
import warnings
from typing import Dict, List, Self, Union

DEFAULT_NAME = '__DEFAULT_LOGGER'

# 格式设置参考：https://docs.python.org/3/library/logging.html#logrecord-attributes
# 开发环境Development：方便开发时联调，极不稳定，随时可能挂，可能存在大量 bug 和脏数据，一定要单独数据库，可能会刷数据
FORMAT_DEV = '%(asctime)s [%(levelname)s]%(process)6d|%(thread)6d|no:%(lineno)3d|%(filename)s: %(message)s'
# 测试环境Testing：主要提供给 QA、PM 测试，基本稳定，可能存在少量 bug 和脏数据，单独数据库，可能会 mock 数据
FORMAT_TST = FORMAT_DEV
# 验收环境User acceptance testing：用于用户验收或展示新功能，很稳定，不应该有 bug 和脏数据，单独数据库
FORMAT_UAT = FORMAT_TST
# 预发环境Staging：正式上线前的少量灰度，极其稳定，不允许有 bug 和脏数据，与生产环境使用相同的数据库
FORMAT_STG = '%(asctime)s [%(levelname)s]: %(message)s'
# 生产环境Production：用于真实生产，极其稳定，不允许有 bug 和脏数据
FORMAT_PRD = FORMAT_STG
DEFAULT_LOG_FORMAT = FORMAT_DEV

CRT = 55
ERR = 45
WRN = 35
INF = 25
DBG = 15
NTE = 5
DEFAULT_LOG_LEVEL = DBG

LVL_TO_NAME = {
    CRT: 'CRT',
    ERR: 'ERR',
    WRN: 'WRN',
    INF: 'INF',
    DBG: 'DBG',
    NTE: 'NTE',
}

NAME_TO_LVL = {
    'CRI': CRT,
    'ERR': ERR,
    'WRN': WRN,
    'INF': INF,
    'DBG': DBG,
    'NTE': NTE,
}

for lvl in LVL_TO_NAME:
    logging.addLevelName(lvl, LVL_TO_NAME[lvl])


class Logger(logging.Logger):
    def __init__(
        self, name: str = DEFAULT_NAME, level: int = DEFAULT_LOG_LEVEL, format_string: str = DEFAULT_LOG_FORMAT
    ):
        super().__init__(name, level)
        if format_string:
            self.formatter = logging.Formatter(format_string)
        else:
            self.formatter = logging.Formatter(FORMAT_DEV)

    def nte(self, msg: str, *args, **kwargs):
        self.log(NTE, msg, *args, **kwargs)

    def dbg(self, msg: str, *args, **kwargs):
        self.log(DBG, msg, *args, **kwargs)

    def inf(self, msg: str, *args, **kwargs):
        self.log(INF, msg, *args, **kwargs)

    def wrn(self, msg: str, *args, **kwargs):
        self.log(WRN, msg, *args, **kwargs)

    def err(self, msg: str, *args, **kwargs):
        self.log(ERR, msg, *args, **kwargs)

    def crt(self, msg: str, *args, **kwargs):
        self.log(CRT, msg, *args, **kwargs)

    def set_handle_file(self, filename: Union[pathlib.Path, str] = None, mode='a', encoding='utf-8', *args, **kwargs):
        # 文件日志
        if not filename:
            filename = self.name + '.log'
        if isinstance(filename, str):
            filename = pathlib.Path(filename)
            filename.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(filename.absolute().__str__(), mode, encoding=encoding, *args, **kwargs)
        handler.setFormatter(self.formatter)
        self.addHandler(handler)

    def set_handle_file_timed_rotating(
        self,
        filename: Union[pathlib.Path, str] = None,
        when='D',
        interval=7,
        backupCount=53,
        encoding='utf-8',
        delay=False,
        utc=False,
        atTime=datetime.time(0, 0, 0, 0),
        errors=None,
    ) -> Self:
        """_summary_

        Args:
            filename (str): 输出日志文件名的前缀
            when (str, optional): 间隔类型，支持S/M/H/D/W0-W6/MIDNIGHT. Defaults to 'D'.
            interval (int, optional): 等待多少个单位when的时间后，Logger会自动重建文件. Defaults to 7.
            backupCount (int, optional): 保留日志个数。默认的0是不会自动删除掉日志. Defaults to 0.
            encoding (str, optional): 日志文件编码. Defaults to 0.

        Returns:
            _type_: _description_
        """
        # 文件日志
        if not filename:
            filename = self.name + '.log'
        if isinstance(filename, str):
            filename = pathlib.Path(filename)
            filename.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.handlers.TimedRotatingFileHandler(
            filename.absolute().__str__(), when, interval, backupCount, encoding, delay, utc, atTime, errors
        )
        handler.setFormatter(self.formatter)
        self.addHandler(handler)
        return self

    def set_handle_io(self, io_base: io.IOBase = io.StringIO()) -> Self:
        # 字符串日志
        handler = logging.StreamHandler(io_base)
        handler.setFormatter(self.formatter)
        self.addHandler(handler)
        return self

    def set_handle_console(self) -> Self:
        # 控制台日志
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.formatter = self.formatter
        self.addHandler(console_handler)
        return self

    def set_lvl(self, level: int) -> Self:
        self.setLevel(level)
        return self


__G_LOG: Dict[str, Logger] = {}


def new(name: str = DEFAULT_NAME, level: int = DEFAULT_LOG_LEVEL, format_string: str = DEFAULT_LOG_FORMAT) -> Logger:
    # 必须使用 new 函数创建，否则多个文件使用同一名字获取的 Logger 都是新的实例
    if name not in __G_LOG:
        __G_LOG[name] = Logger(name, level, format_string)
        return __G_LOG[name]
    if level:
        __G_LOG[name].set_lvl(level)
    if format_string:
        __G_LOG[name].formatter = logging.Formatter(format_string)
    return __G_LOG[name]


warnings.filterwarnings('ignore')
# fix: the following warning message
# urllib3\connectionpool.py:1004: InsecureRequestWarning: Unverified HTTPS request is being made to host 'localhost'.
#   Adding certificate verification is strongly advised. See:
#   https://urllib3.readthedocs.io/en/latest/advanced-usage.html#ssl-warnings InsecureRequestWarning,

if __name__ == '__main__':
    logger = new(level=DEFAULT_LOG_LEVEL)
    logger.set_handle_console()
    logger.set_handle_file('{}_{}.log'.format(DEFAULT_NAME, datetime.datetime.now().strftime('%y%m')))
    logger.debug('DEBUG MSG.')
    logger.info('INFO MSG.')
    logger.warning('WARNING MSG.')
    logger.error('ERROR MSG.')
    logger.critical('CRITICAL MSG.')

    logger.nte('NOTICE MSG.')
    logger.dbg('DEBUG MSG.')
    logger.inf('INFO MSG.')
    logger.wrn('WARNING MSG.')
    logger.err('ERROR MSG.')
    logger.crt('CRITICAL MSG.')
