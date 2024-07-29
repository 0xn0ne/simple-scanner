#!/bin/python3
# _*_ coding:utf-8 _*_
#
# process.py
# 参考链接：https://segmentfault.com/a/1190000007495352
# 多进程写法优化，多进程适用于CPU密集型、网络请求密集型任务。同时多进程模型也适用于多机分布式场景中，易于多机扩展。单任务CPU需求越大，网络请求操作次数越多，多线程越有优势。

# from gevent import monkey

# # 避免进程 PIPE 阻塞：https://xiaorui.cc/archives/4710
# monkey.patch_all(thread=False)
import concurrent.futures
import os
import random
import time
from typing import Any, Generator, List

# todo: 是否加入全局协程封装待研究，目前速度表现还不错
# import gevent
# 这个模块要求所有代码都是异步，否则有和没有差不多，再考虑一下把
# import aiomultiprocess

class ProcessPool(concurrent.futures.ProcessPoolExecutor):
    def __init__(self, max_workers=None, mp_context=None, initializer=None, initargs=()):
        super().__init__(max_workers, mp_context, initializer, initargs)
        self.jobs: List[concurrent.futures.Future] = []

    def sm(self, fn, /, *args, **kwargs) -> concurrent.futures.Future:
        job = self.submit(fn, *args, **kwargs)
        self.jobs.append(job)
        return job

    def yield_result(self, timeout: float = None) -> Generator[Any, None, None]:
        """
        获取任务执行的返回值，并将任务从队列中移除。在调用本函数时，调用点会进入阻塞状态。
        """
        self.jobs.reverse()
        while self.jobs:
            yield self.jobs.pop().result(timeout)

        self.jobs = []


def new(*args, **kwargs):
    return ProcessPool(*args, **kwargs)


import functools


# 打印运行时间
def print_run_times(label=None):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            ret = func(*args, **kwargs)
            msg = '[*] total times(s):'
            if label:
                msg = '[*] [{}] total times(s):'.format(label)
            print(msg, time.time() - start_time)
            return ret

        return wrapper

    return decorator


######## CPU 密集型任务开始 ########
@print_run_times('TEST_PERFORMANCE')
def __test_performance_func(min: int = 500, max: int = 600):
    # print(os.getpid(), '__test_performance_func running...')
    result = 0
    for i in range(random.randint(min, max)):
        for j in range(random.randint(min, max)):
            for k in range(random.randint(min, max)):
                result += i + j + k
    print(os.getpid(), '__test_performance_func result:', str(result))
    # print(os.getpid(), '__test_performance_func ending...')


@print_run_times('TEST_RETURN')
def __test_return_func(min: int = 500, max: int = 600):
    result = 0
    for i in range(random.randint(min, max)):
        for j in range(random.randint(min, max)):
            for k in range(random.randint(min, max)):
                result += i + j + k
    print(os.getpid(), 'test_return_func result:', str(result))
    # 返回数据
    return result


@print_run_times('TEST_RETURN_DICT')
def __test_return_dict_func(min: int = 500, max: int = 600):
    result = {}
    for i in range(random.randint(min, max)):
        for j in range(random.randint(min, max)):
            for k in range(random.randint(min, max)):
                key = str(i // 500)
                if not key in result:
                    result[key] = 0
                result[key] += i + j + k
    print(os.getpid(), '__test_return_dict_func result:', result)
    # 返回数据
    return result


######## CPU 密集型任务结束 ########

######## IO 密集型任务开始 ########
# 不
######## IO 密集型任务结束 ########


if __name__ == '__main__':
    print('__test_return_func 1 times')
    start_time = time.time()
    print('return:', __test_return_func(500, 550))
    print('run one times, total time(s):', time.time() - start_time)

    pph = ProcessPool(3)

    print('__test_performance_func')
    start_time = time.time()
    [pph.sm(__test_performance_func, 500, 550) for i in range(10)]
    print('return:', [i for i in pph.yield_result()])
    print('total time(s):', time.time() - start_time)

    print('__test_return_func')
    start_time = time.time()
    [pph.sm(__test_return_func, 500, 550) for i in range(10)]
    print('return:', [i for i in pph.yield_result()])
    print('total time(s):', time.time() - start_time)

    print('__test_return_dict_func')
    start_time = time.time()
    [pph.sm(__test_return_dict_func, 500, 550) for i in range(10)]
    print('return:', [i for i in pph.yield_result()])
    print('total time(s):', time.time() - start_time)

    # 处理器:           安装了 1 个处理器。
    #                  [01]: AMD64 Family 25 Model 33 Stepping 0 AuthenticAMD ~3701 Mhz
    # return: 2861758025421224
    # run one times, total time(s): 10.262209177017212
    # return: [2582051420060162, 2385134693133712, 2734006770193755, 2658863161379877, 2367450617576565, 2535566799548760, 2647666940791099, 2445589945625423, 2405781958502416, 2812995873098620]
    # total time(s): 36.40744924545288
    # return: [None, None, None, None, None, None, None, None, None, None]
    # total time(s): 35.91919994354248
