from typing import Any, Callable, Dict, Generator, Set

from gevent import Greenlet, pool, sleep

# patch_all(thread=False, httplib=True)


class AsyncPool(pool.Pool):
    def __init__(self, size: int = None, greenlet_class: Greenlet | None = None):
        super().__init__(size, greenlet_class)
        self._glets: Set[Greenlet] = set()
        self._glets_map: Dict[str | int | bytes, Greenlet] = {}

    def sp_by_key(self, key: str | int | bytes, func: Callable, *args, **kwargs):
        """根据key添加协程任务，结合get_by_key函数可以获取key对应的协程返回值"""
        glet = self.spawn(func, *args, **kwargs)
        self._glets.add(glet)
        self._glets_map[key] = glet
        return glet

    def get_by_key(self, key: str | int | bytes, block: bool = True, timeout: float = None) -> Any:
        glet = self._glets_map[key]
        del self._glets_map[key]
        if glet in self._glets:
            self._glets.remove(glet)
        return glet.get(block, timeout)

    def sp(self, func: Callable, *args, **kwargs):
        """会自动启动任务运行"""
        glet = self.spawn(func, *args, **kwargs)
        self._glets.add(glet)
        return glet

    def get_yeild(self, block: bool = True, timeout: float = None) -> Generator[BaseException | Any, None, None]:
        """返回greenlet返回的结果或重新触发协程中出现的异常。

        Args:
            block (bool, optional): 如果block为 `False` 尝试获取返回值，这时如果 greenlet 还在运行则抛出 `gevent.Timeout` 错误。如果block为 `True`，取消当前 greenlet 的调度，直到返回结果或超时，在超时情况下触发超时异常。默认：`True`
            timeout (float, optional): 从获取结果开始计时的超时时间（单位：秒）。默认：`None`

        Yields:
            Generator: 返回结果的迭代器
        """
        while self._glets:
            glet = self._glets.pop()
            glet.join(timeout)
            # 错误处理
            if glet.exception:
                yield glet.exception
            else:
                yield glet.get(block, timeout)


if __name__ == '__main__':
    import time

    def test_func(id=1):
        print('start: {}'.format(id))
        sleep(3)
        print('end: {}'.format(id))
        return id

    ap = AsyncPool(5)
    start_time = time.time()
    for i in range(10):
        ap.sp(test_func, i)
    print('start run for loop')
    for i in ap.get_yeild():
        print(i)
    print('total time(s):', time.time() - start_time)
    for i in range(10):
        ap.sp_by_key(i, test_func, i)
    for i in range(9, -1, -1):
        print(ap.get_by_key(i))
    [print(_) for _ in ap.get_yeild()]
