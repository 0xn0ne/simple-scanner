#!/bin/python3
# _*_ coding:utf-8 _*_
#
# net.py
# 网络工具箱
# 扫描用法：https://nmap.org/book/man-port-scanning-techniques.html
# 模块使用参考：https://cloud.tencent.com/developer/article/2352111
# 模块使用参考：https://www.cnblogs.com/LyShark/p/17787636.html#_label2
# 端口说明：http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
import socket

import gevent
from gevent import monkey

monkey.patch_all()
import logging
import re
import time
from typing import List, Tuple, Union

from scapy.interfaces import ifaces
# logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.layers.inet import IP, TCP, Packet
from scapy.plist import PacketList
from scapy.sendrecv import send, sr, sr1, srp1


def compress_port_range(values: List[int]):
    values = sorted(set(values))
    ret = ''
    log_last = -1
    is_plus = False
    for port in values:
        if port < 1 or port > 65535:
            continue
        if port == log_last + 1:
            log_last = port
            is_plus = True
            continue
        if not ret:
            ret = str(port)
        elif not is_plus:
            ret += ',{}'.format(port)
        else:
            ret += '-{},{}'.format(log_last, port)
        log_last = port
        is_plus = False
    return ret


def parse_port_range(values: str):
    ret = set()
    for val in re.split(r'[\s,]+', values):
        if '-' in val:
            spl_port = val.split('-')
            spl_port = [s_port for s_port in spl_port if s_port]
            if len(spl_port) < 2:
                raise ValueError('port "{}" is incorrectly'.format(val))
            for s_port in range(int(spl_port[0]), int(spl_port[1])):
                ret.add(int(s_port))
            # ret.update([i for i in range(int(spl_port[0]), int(spl_port[1]))])
        else:
            ret.add(int(val))
    return ret


DEFAULT_SCAN_PORTS = []
for step in range(0, 60000, 10000):
    for port in parse_port_range(
        '0,7,9,10,13,20-23,25-26,37,53,79-89,106,100,110-111,113,119,135-139,143-144,179-189,199-200,222,300,389,400,427,443-445,465,500,513-515,543-544,548,554,587,600,631,636,646,700,789,800-898,900,990,993,995,1000,1025-1029,1080-1089,1110,1211,1433,1443,1521,1720,1723,1755,1900,2000-2001,2049,2121,2181,2222,2443,2717,3000,3128,3306,3389,3443,3986,4000,4096,4156,4242,4443,4899,5000,5009,5051,5060-5063,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,6080-6089,7000-7005,7070,7080-7089,8000-8088,8100-8188,8200-8288,8443,8800-8888,9000,9100,9999'
    ):
        DEFAULT_SCAN_PORTS.append(step + port)


def parse_ipv4s(values: str):
    ret = set()
    for val in re.split(r'[\s,]+', values):
        if '-' in val:
            spl_port = val.split('-')
        elif '/' in val:
            pass
        elif '*' in val:
            pass
        else:
            ret.add(int(val))
    return ret


# WARNING: Mac address to reach destination not found. Using broadcast.
# 研究失败，好像每次发包都会通过嗅探来获取返回的数据包，很奇怪，不是一个正常的TCP接包机制
# def scan_tcp(ip: str, port: int, timeout: float = 0.8, retry: int = 2) -> Union[Tuple[str, int], None]:
#     # 全开扫描，会和目标端口建立完整的三次握手，需要更长的时间和更多的数据包来获取端口的信息，而且有可能被目标机器记录连接
#     packet_s = IP(dst=ip) / TCP(dport=port, flags="S")
#     packet_r = sr1(packet_s, timeout=timeout, verbose=0, retry=retry)
#     if packet_r[TCP].flags != 'SA':
#         return
#     packet_s = IP(dst=ip) / TCP(dport=port, flags="AR")
#     packet_r = send(packet_s, verbose=0)
#     return ip, port


# def scan_syn(ip: str, port: int, timeout: float = 0.8, retry: int = 2) -> Union[Tuple[str, int], None]:
#     # 半开扫描（SYN扫描），只设置SYN标识，服务器响应SYN、ACK表示端口打开（部分系统可能只会返回SYN标志，极其罕见的TCP特性）；而响应RST表示端口未侦听；如果在多次重传后仍未收到响应，则将该端口标记为已过滤
#     packet_s = IP(dst=ip) / TCP(dport=port, flags='S')
#     packet_r: Packet = sr1(
#         packet_s, timeout=timeout, verbose=0, retry=retry, iface='VMware Virtual Ethernet Adapter for VMnet8'
#     )
#     if not packet_r:
#         # 防火墙过滤，不处理，当不开放统计
#         return
#     if packet_r[TCP].flags != 'S' and packet_r[TCP].flags != 'SA':
#         return
#     return ip, port


# def scan_ack(ip: str, port: int, timeout: float = 0.8, retry: int = 2) -> Union[Tuple[str, int], None]:
#     # ACK扫描，用于探测防火墙规则集，只设置了ACK标志，当扫描未过滤的系统时打开和关闭的端口都会返回一个RST包，不响应或发送某些ICMP错误消息（类型3，代码0、1、2、3、9、10或13）的端口会被标记为过滤端口
#     packet_s = IP(dst=ip) / TCP(dport=port, flags='A')
#     packet_r: Packet = sr1(packet_s, timeout=timeout, verbose=0, retry=retry)
#     if not packet_r:
#         return
#     if packet_r[TCP].flags != 'R':
#         return
#     return ip, port


# def scan_maimon(ip: str, port: int, timeout: float = 0.8, retry: int = 2) -> Union[Tuple[str, int], None]:
#     # 麦蒙扫描，以它的发现者Uriel Maimon的名字命名，这种技术与NULL、FIN和Xmas扫描完全相同，设置FIN、ACK标志如果端口打开，许多BSD派生的系统只是丢弃数据包，对Windows无效
#     packet_s = IP(dst=ip) / TCP(dport=port, flags='FA')
#     packet_r: Packet = sr1(packet_s, timeout=timeout, verbose=0, retry=retry)
#     if packet_r:
#         return
#     return ip, port


# def scan_xmas(ip: str, port: int, timeout: float = 0.8, retry: int = 2) -> Union[Tuple[str, int], None]:
#     packet_s = IP(dst=ip) / TCP(dport=port, flags='FPU')
#     packet_r = sr1(packet_s, timeout=timeout, verbose=0, retry=retry)
#     if not packet_r:
#         return
#     if packet_r[TCP].flags != 'R':
#         return
#     return ip, port


# def tcp_scan_ports(
#     l_ip: List[str],
#     ports: str = '7,9,13,21-23,25-26,37,53,79-89,106,110-111,113,119,135,139,143-144,179-189,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,800-898,990,993,995,1025-1029,1080-1089,1110,1433,1443,1720,1723,1755,1900,2000-2001,2049,2121,2181,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7000-7005,7070,8000-8088,8443,8800-8888,9100,9999-10000,11211,32768,49152-49157',
#     mode: str = 'SYN',
#     timeout: float = 0.8,
#     retry: int = 2,
# ):
#     mode = mode.upper()
#     m_funcs = {
#         'SYN': scan_syn,
#         'S': scan_syn,
#         'ACK': scan_ack,
#         'A': scan_ack,
#         'MAIMON': scan_maimon,
#         'M': scan_maimon,
#         'XMAS': scan_xmas,
#         'X': scan_xmas,
#         'TCP': scan_tcp,
#         'T': scan_tcp,
#     }
#     if mode not in m_funcs:
#         raise ValueError('unsupported scan mode "{}", only supported {}'.format(mode, tuple(m_funcs.keys())))
#     l_task = []
#     for ip in l_ip:
#         for port in parse_port_range(ports):
#             if port < 0 or port > 65535:
#                 continue
#             l_task.append(gevent.spawn(m_funcs[mode], ip, port, timeout, retry))
#     gevent.joinall(l_task)
#     gevent.wait()
#     return [i.value for i in l_task if i.value]


def scan_socket(ip: str, port: int, timeout: float = 0.8):
    if port < 1 or port > 65535:
        return
    clinet = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clinet.settimeout(timeout)
    ret = clinet.connect_ex((ip, port))
    try:
        clinet.shutdown(socket.SHUT_RDWR)
    except OSError:
        # OSError: [WinError 10057] 由于套接字没有连接并且(当使用一个 sendto 调用发送数据报套接字时)没有提供地址，发送或接收数据的请求没有被接受。
        pass
    clinet.close()
    if ret != 0:
        return
    return ip, port


def tcp_scan_ports(
    l_ip: List[str],
    ports: Union[List[int], str] = DEFAULT_SCAN_PORTS,
    timeout: float = 0.8,
):
    if isinstance(ports, str):
        ports = parse_port_range(ports)
    l_task = []
    for ip in l_ip:
        for port in ports:
            # if port < 1 or port > 65535:
            #     continue
            l_task.append(gevent.spawn(scan_socket, ip, port, timeout))
    gevent.joinall(l_task)
    gevent.wait()
    return [i.value for i in l_task if i.value]


if __name__ == '__main__':
    pass
    # print(parse_port_range('22,43  ,623,23,24 42,22,22\n21 99 1230,1083 8000-9000 9000 -10000'))
    # print(compress_port_range([10, 11, 12, 13, 14, 20, 21, 30, 40]))
    # print(len(DEFAULT_SCAN_PORTS), DEFAULT_SCAN_PORTS)

    s_time = time.time()
    print(tcp_scan_ports(['192.168.245.130'], '0-65535'))
    print(time.time() - s_time)
    # print(scan_syn('127.0.0.1', 22))
    # print(scan_syn('127.0.0.1', 135))
    # print(scan_syn('127.0.0.1', 445))
    # print(scan_syn('127.0.0.1', 2123))
    # print(time.time() - s_time)
    # s_time = time.time()
    # print(scan_tcp('127.0.0.1', 22))
    # print(scan_tcp('127.0.0.1', 135))
    # print(scan_tcp('127.0.0.1', 445))
    # print(scan_tcp('127.0.0.1', 2123))
    # print(time.time() - s_time)
    # s_time = time.time()
    # print(scan_ack('127.0.0.1', 22))
    # print(scan_ack('127.0.0.1', 135))
    # print(scan_ack('127.0.0.1', 445))
    # print(scan_ack('127.0.0.1', 2123))
    # print(time.time() - s_time)
    # s_time = time.time()
    # print(scan_mai('127.0.0.1', 22))
    # print(scan_mai('127.0.0.1', 135))
    # print(scan_mai('127.0.0.1', 445))
    # print(scan_mai('127.0.0.1', 2123))
    # print(time.time() - s_time)
    # s_time = time.time()
    # print(scan_xmas('127.0.0.1', 22))
    # print(scan_xmas('127.0.0.1', 135))
    # print(scan_xmas('127.0.0.1', 445))
    # print(scan_xmas('127.0.0.1', 2123))
    # print(time.time() - s_time)
