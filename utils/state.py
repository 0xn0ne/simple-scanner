from collections import OrderedDict


# noinspection PyUnresolvedReferences
class MetaClassForInit(type):
    def __new__(mcs, *args, **kwargs):
        new_class = super().__new__(mcs, *args, **kwargs)
        if getattr(new_class, 'cls_init', None):
            new_class.cls_init()
        return new_class


class StateBase(metaclass=MetaClassForInit):
    _keys = []
    _values = []
    _value2key = {}
    _items = None

    @classmethod
    def keys(cls):
        return cls._keys

    @classmethod
    def values(cls):
        return cls._values

    @classmethod
    def v2k(cls, value):
        return cls._value2key[value]

    @classmethod
    def items(cls):
        if cls._items is None:
            cls._items = []
            for k, v in zip(cls.keys(), cls.values()):
                cls._items.append(
                    (k, v),
                )
        return cls._items

    @classmethod
    def to_dict(cls):
        return dict(cls.items())

    @classmethod
    def cls_init(cls):
        _v2k, v2k = {}, OrderedDict()

        for k, v in cls.__dict__.items():
            if k.isupper() and type(v) == int:
                _v2k[v] = k

        for i in sorted(_v2k.keys()):
            v2k[i] = _v2k[i]

        cls._keys = list(v2k.values())
        cls._values = list(v2k.keys())
        cls._value2key = v2k


class R(StateBase):
    '''Response Content'''

    SUCCESS = 0
    FAILED = -255
    TIMEOUT = -254
    UNKNOWN = -253
    TOO_FREQUENT = -252
    DEPRECATED = -251

    NOT_FOUND = -249
    ALREADY_EXISTS = -248

    PERMISSION_DENIED = -239
    INVALID_ROLE = -238

    CHECK_FAILURE = -229
    PARAM_REQUIRED = -228
    POSTDATA_REQUIRED = -227

    INVALID_PARAMS = -219
    INVALID_POSTDATA = -218

    CONNET_FAILED = -209

    WS_DONE = 1

    _lang_cn = {
        SUCCESS: '成功',
        FAILED: '失败',
        TIMEOUT: '超时',
        UNKNOWN: '未知错误',
        TOO_FREQUENT: '请求过于频繁',
        DEPRECATED: '此接口已不推荐使用',
        NOT_FOUND: '未找到',
        ALREADY_EXISTS: '已存在',
        PERMISSION_DENIED: '无权访问',
        INVALID_ROLE: '权限申请失败',
        CHECK_FAILURE: '校验失败',
        PARAM_REQUIRED: '缺少参数',
        POSTDATA_REQUIRED: '缺少提交内容',
        INVALID_PARAMS: '非法参数',
        INVALID_POSTDATA: '非法提交内容',
        CONNET_FAILED: '连接失败',
        WS_DONE: 'Websocket 请求完成',
    }

    _lang_en = {
        SUCCESS: 'success',
        FAILED: 'failed',
        TIMEOUT: 'timeout',
        UNKNOWN: 'unknown',
        TOO_FREQUENT: 'request too frequent',
        DEPRECATED: 'interface deprecated',
        NOT_FOUND: 'not found',
        ALREADY_EXISTS: 'already exists',
        PERMISSION_DENIED: 'permission denied',
        INVALID_ROLE: 'acquire role failed',
        CHECK_FAILURE: 'check failure',
        PARAM_REQUIRED: 'parameter(s) required',
        POSTDATA_REQUIRED: 'post data item(s) required',
        INVALID_PARAMS: 'invalid parameter(s)',
        INVALID_POSTDATA: 'invalid post',
        CONNET_FAILED: 'connection failed',
        WS_DONE: 'Websocket request done',
    }


if __name__ == '__main__':
    print(R.to_dict())
    print(R.v2k(R.FAILED))
