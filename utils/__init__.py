import csv
import pathlib
from typing import Dict, List, Union

from utils import language, net_echo, state


class PluginType(state.StateBase):
    EXP = 100
    POC = 80
    MODULE = 20


LANG = language.Language()
PLUGIN_TYPE = PluginType()


DEFAULT_USER_AGENT_LNX = [
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux i686; rv:127.0) Gecko/20100101 Firefox/127.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 OPR/112.0.0.0',
]
DEFAULT_USER_AGENT_MAC = [
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.2592.87',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:127.0) Gecko/20100101 Firefox/127.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 OPR/112.0.0.0',
]
DEFAULT_USER_AGENT_WIN = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.3',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 OPR/112.0.0.0',
]
DEFAULT_USER_AGENT_MOB = [
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/126.0.6478.108 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 EdgiOS/126.2592.86 Mobile/15E148 Safari/605.1.15',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/127.0 Mobile/15E148 Safari/605.1.15',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.122 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 10; HD1913) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.122 Mobile Safari/537.36 EdgA/126.0.2592.80',
    'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.122 Mobile Safari/537.36 EdgA/126.0.2592.80',
]
DEFAULT_USER_AGENT = DEFAULT_USER_AGENT_LNX + DEFAULT_USER_AGENT_MAC + DEFAULT_USER_AGENT_WIN

NET_ECHO: net_echo.EchoServiceBase = None


def save_csv(
    values: List[Union[Dict, List]],
    filename: Union[pathlib.Path, str] = 'output.csv',
    buffering: int = -1,
    encoding: str = 'utf_8_sig',
    errors='ignore',
    newline: str = '',
    column_limit: int = 22000,
):
    # CSV单个单元格字符数量限制为32767，考虑到引号会"转义，字符数量限制在 22000 以内，但是还是有可能超单元格字数限制，比如假设极端情况一大半的字符都是"
    with open(filename, 'w', buffering, encoding, errors, newline) as _file:
        if isinstance(values[0], List):
            writer = csv.writer(_file, quoting=csv.QUOTE_STRINGS)
        else:
            writer = csv.DictWriter(_file, fieldnames=values[0].keys(), quoting=csv.QUOTE_STRINGS)
            writer.writeheader()

        for row in values:
            if isinstance(row, List):
                iter = enumerate(row)
            else:
                iter = row.items()
            for key, val in iter:
                if isinstance(val, str):
                    row[key] = val[:column_limit]
            writer.writerow(row)
