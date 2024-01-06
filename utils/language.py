#!/bin/python3
# _*_ coding:utf-8 _*_
#
# language.py
# 轻量化的多语言支持，默认的 gettext 方法操作比较复杂，自开发的程序一般没这么复杂用不到
import json
import locale
import pathlib
from typing import Any, Dict, Tuple

import toml
import yaml


class Language:
    def __init__(self, path: str = 'language.yml', lang: str = None):
        self.path = pathlib.Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lang = lang or self.get_locale()
        self.raw = self.load()

    def t(self, text: str, *args_format: Tuple[Any], lang: str = None) -> str:
        if text not in self.raw:
            self.raw[text] = {}
            self.dump()
        lang = lang or self.lang

        if lang not in self.raw[text]:
            ret = text
        else:
            ret = self.raw[text][lang]
        if args_format:
            return ret.format(*args_format)
        return ret

    def print(self, text: str, *args, **kwargs):
        print(self.t(text, *args, **kwargs))

    def loads(self, content: str, fmt: str = 'yaml') -> Dict[str, Dict[str, str]]:
        if fmt == 'yaml':
            obj_data = yaml.safe_load(content)
        elif fmt == 'toml':
            obj_data = toml.loads(content)
        else:
            obj_data = json.loads(content)
        if not obj_data:
            return {}
        self.raw = obj_data
        return self.raw

    def load(self, fmt: str = 'yaml', encoding: str = 'utf-8', errors: str = None):
        if not self.path.is_file():
            return {}
        return self.loads(self.path.read_text(encoding, errors), fmt)

    def dumps(self, fmt: str = 'yaml') -> str:
        if fmt == 'yaml':
            content = yaml.safe_dump(self.raw)
        elif fmt == 'toml':
            content = toml.dumps(self.raw)
        else:
            content = json.dumps(self.raw)
        return content

    def dump(self, encoding: str = 'utf-8', errors: str = None):
        self.path.write_text(self.dumps(), encoding, errors)

    @staticmethod
    def get_locale() -> str:
        return locale.getdefaultlocale()[0]


if __name__ == '__main__':
    '''language.yml
    hello world!:
    zh_CN: "\u4F60\u597D\u4E16\u754C\uFF01"
    let go!: {}
    '''
    lang = Language('language.yml', 'zh_CN')
    lang.t('hello world!')
    lang.t('let go!')
    lang.print('hello world!')
    lang.print('hello {}, {}!', 'lining', 'hanmeimei')
    lang.print('let go!')
