#!/bin/python3
# _*_ coding:utf-8 _*_
#
# net.py
# 网络工具箱，整个文件还很乱，需要拆分TCP、TCMP协议作为单独的类，socket 塞满的情况下有概率丢包，但是包确实发出去了
# 扫描用法：https://nmap.org/book/man-port-scanning-techniques.html
# 模块使用参考：https://cloud.tencent.com/developer/article/2352111
# 模块使用参考：https://www.cnblogs.com/LyShark/p/17787636.html#_label2
# 端口说明：http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
from gevent import monkey

monkey.patch_socket()
import copy
import os
import re
import socket
import struct
import sys
import time
from typing import (Any, Callable, Dict, Generator, Iterable, List, Self, Set,
                    Tuple, Union)

import netaddr

try:
    from utils import pro_async
except:
    import pathlib
    import sys

    sys.path.append(pathlib.Path(__file__).parent.parent.__str__())
    from utils import pro_async

DEFAULT_RE_SPLIT_HOST_AND_PORT_CHAR = r'[;,；，\s]+'
DEFAULT_SOCKET_TIMEOUT = 1
DEFAULT_SCAN_PORTS = set()


def handle_ip_address(ip_string: str):
    # ip-address-style or ip-network-style IP handler
    return netaddr.IPNetwork(ip_string)


def handle_ip_range(ip_string: str):
    # ip-range-style IP handler
    ip_list = ip_string.split('-')
    if len(ip_list) <= 1:
        ip_list = ip_string.split('_')
    return netaddr.iprange_to_cidrs(ip_list[0], ip_list[1])


def handle_ip_glob(ip_string: str):
    # ip-glob-style IP handler
    if isinstance(ip_string, tuple):
        ip_string = ip_string[0]
    return netaddr.glob_to_cidrs(ip_string)


def ipv4_range_parse(ip_string: str, re_split_char: str = DEFAULT_RE_SPLIT_HOST_AND_PORT_CHAR) -> netaddr.IPSet:
    l_re_handle = [
        # 192.168.1.1/255.255.255.0
        (r'(!\s*)?(\d{1,3}(?:\.\d{1,3}){3}/\d{1,3}(?:\.\d{1,3}){3})', handle_ip_address),
        # 192.168.1.1-192.168.1.10
        (r'(!\s*)?(\d{1,3}(?:\.\d{1,3}){3}[-_]\d{1,3}(?:\.\d{1,3}){3})', handle_ip_range),
        # 192.168.1.1-23
        (r'(!\s*)?(\d{1,3}(?:\.\d{1,3}){3}[-_]\d{1,3})', handle_ip_glob),
        # 192.168.1.1/24
        (r'(!\s*)?(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})', handle_ip_address),
        # 192.168.1.1
        (r'(!\s*)?(\d{1,3}(?:\.\d{1,3}){3})', handle_ip_address),
        # 192.168.1.* or 192.168.*
        (r'(!\s*)?([\d\*]{1,3}(?:\.[\d\*]{1,3}){1,3})', handle_ip_glob),
    ]

    ret = netaddr.IPSet()
    for ip in re.split(re_split_char, ip_string):
        is_found = False
        for r_ip, handle in l_re_handle:
            r_ip_ranges = re.findall(r_ip, ip)
            for r_ip_rng in r_ip_ranges:
                is_found = True
                ip_network = handle(r_ip_rng[1])
                # 检查是否有反向标识，清理集合数据
                if r_ip_rng[0]:
                    ret = ret.difference(netaddr.IPSet(ip_network))
                    # tar_list = l_rmv
                else:
                    ret.update(ip_network)
            #         tar_list = l_add
            #     if isinstance(ip_network, list):
            #         tar_list.extend(ip_network)
            #     else:
            #         tar_list.append(ip_network)
            if is_found:
                break
    # [ret.add(row) for row in l_add]
    # [ret.remove(row) for row in l_rmv]
    # ret.difference()
    return ret


def ports_to_range(values: List[int]):
    values = sorted(set(values))
    ret = ''
    log_last = -1
    is_plus = False
    for index, port in enumerate(values):
        if port < 1 or port > 65535:
            continue
        if port == log_last + 1 and index != len(values) - 1:
            log_last = port
            is_plus = True
            continue
        if not ret:
            ret = str(port)
        elif not is_plus:
            ret += ',{}'.format(port)
        elif index == len(values) - 1:
            ret += '-{}'.format(port)
            break
        else:
            ret += '-{},{}'.format(log_last, port)
        log_last = port
        is_plus = False
    return ret


def range_to_ports(values: str):
    ret = set()
    for val in re.split(DEFAULT_RE_SPLIT_HOST_AND_PORT_CHAR, values):
        port_range = [-1, -1]
        if '-' in val:
            spl_port = val.split('-')
            spl_port = [s_port for s_port in spl_port if s_port]
            if len(spl_port) < 2:
                raise ValueError('the format of port {} is incorrectly'.format(val))
            port_range = [int(spl_port[0]), int(spl_port[1])]
        else:
            port_range = [int(val), int(val)]

        if port_range[0] < 0 or port_range[1] > 65535:
            raise ValueError('port "{}" is incorrectly'.format(val))
        for port in range(port_range[0], port_range[1] + 1):
            ret.add(port)
    return ret


for step in range(0, 40000, 10000):
    # shoden 收集的常用TOP1500端口
    for port in range_to_ports(
        '0-3,8,10-13,19-26,30,53,66,70,77,79-90,95-100,110-111,119,121-123,131,134-135,137,139,143,161,175,179-180,195,199,211,221-222,225,243,250,256,303,311,333-334,389,433,440,442-450,456,465,500-503,512,520,522-523,550,554-556,636,646,666-667,771-772,777,789,800-801,805-806,808,843,880-890,909-912,922,943,987,990,992-995,999-1001,1022-1029,1050,1080,1099-1100,1110-1112,1122,1153,1177,1200,1210-1211,1234-1235,1250,1290,1300,1311,1314,1337,1344,1355,1366,1388,1400,1433-1434,1443-1444,1500,1515,1521,1588,1599,1650,1660,1666,1701,1800-1801,1820,1830,1833,1883,1900-1901,1946-1947,1950-1951,1990,2000-2003,2006,2008,2010,2012,2018,2020-2023,2030,2048-2070,2077-2083,2100,2111,2121-2123,2200-2202,2211,2220-2223,2233,2250,2266,2320,2323,2332-2333,2345,2400,2443,2480,2566-2570,2626,2650,2701,2828,3000-3003,3005,3008,3066-3121,3200,3211,3221,3299,3301,3305-3307,3310-3311,3333-3334,3388-3390,3400-3410,3443,3521-3524,3554-3556,3566-3570,3689-3690,3838-3839,3910,3922,4000-4002,4010,4022,4040,4100,4190,4200,4242-4243,4300,4321,4333,4343-4344,4433-4435,4438-4440,4443-4445,4500,4545,4550,4567,4646,4700,4747,4777,4800,4808,4818,4840,4848,4899,4911,4949,4999-5011,5025,5050-5051,5055,5060,5067,5070,5080,5090,5100,5122,5150,5190,5200-5201,5222,5280,5321,5335,5353,5400,5431-5432,5442-5443,5454,5500-5501,5553-5556,5560,5565-5569,5588,5590-5611,5678,5760,5800-5801,5822,5858,5866,5888,5900-5902,6000-6010,6030,6036,6060,6080,6161,6262,6363,6379,6443,6543,6550,6560-6561,6565,6580-6581,6588,6590,6600-6603,6622,6633,6650,6653,6666-6668,6688,6789,6899,6955,6969,6998,7000-7005,7010,7022,7070-7071,7080-7081,7090,7170-7171,7272,7400-7401,7433-7434,7443-7445,7474,7500,7654,7676,7700,7730,7775-7780,7788,7808,7822,7833,7887,7890,7900,7979,7989-7990,7998-8058,8060-8061,8066,8071-8072,8080-8112,8118,8123-8125,8143,8180-8184,8190,8200-8201,8222,8234,8243,8245,8282,8320,8333-8334,8383,8401-8433,8442-8448,8500-8501,8553-8554,8580,8585-8586,8590,8600,8666,8686,8688,8700,8728,8733,8760,8765-8767,8800-8881,8885,8887-8891,8899-8900,8920,8922,8988-8991,8999-9051,9060,9070-9071,9080-9082,9088-9111,9123,9132,9180,9189-9191,9199-9222,9299-9311,9433,9443-9445,9500,9527-9528,9595,9600,9633,9663,9690,9700-9702,9711,9755-9766,9768-9769,9780,9800-9801,9888-9889,9898-9902,9929-9930,9943-9944,9950,9955,9966,9980-9982,9988-9994,9997-9999'
    ):
        DEFAULT_SCAN_PORTS.add(step + port)


class BytesPacketBase:
    def __init__(self) -> None:
        self._rawdata = b''

    def to_hex(self):
        return self._rawdata.hex()

    def show(self, sep=' '):
        is_new_row = True
        ret = ''
        for index, value in enumerate(self._rawdata):
            if index % 16 == 0 and index != 0:
                ret += '\n'
                is_new_row = True
            if is_new_row:
                ret += '{:02X}'.format(value)
            else:
                ret += '{}{:02X}'.format(sep, value)
            is_new_row = False
        print(ret)

    def __str__(self) -> str:
        raw_string = super().__str__()
        str_attr = ''
        for key in self.__dict__:
            if key.startswith('_'):
                continue
            if isinstance(self.__dict__[key], Callable):
                continue
            str_attr += '{}={}, '.format(key, self.__dict__[key])
        return '{} {}>'.format(raw_string[:-1], str_attr[:-2])


class IPPacket(BytesPacketBase):

    def include(self):
        # 加载更高层的数据包
        pass

    def exclude(self):
        # 导出更高层的数据包
        pass


class ICMPPacket(IPPacket):
    def __init__(
        self, type_: int = 8, code: int = 0, identifier: int = 0, sequence: int = 0, payload: bytes = b''
    ) -> None:
        # Type AND Code: https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
        super().__init__()
        self.type_ = type_
        self.code = code
        self.identifier = identifier or os.getpid()
        self.sequence = sequence
        self.payload = payload

    @classmethod
    def get_checksum(cls, raw_packet: bytes = None) -> int:
        raw_packet = raw_packet or cls._rawdata
        if len(raw_packet) % 2:
            raw_packet += b'\00'
        checksum = 0
        for i in range(len(raw_packet) // 2):
            (word,) = struct.unpack('!H', raw_packet[2 * i : 2 * i + 2])
            checksum += word
        while True:
            carry = checksum >> 16
            if carry:
                checksum = (checksum & 0xFFFF) + carry
            else:
                break
        return ~checksum & 0xFFFF

    def incr_sequence(self) -> None:
        self.sequence += 1

    def pack(self) -> bytes:
        packet_info = struct.pack('!BBHH', self.type_, self.code, self.identifier, self.sequence) + self.payload
        checksum = self.get_checksum(packet_info)
        self._rawdata = packet_info[:2] + struct.pack('!H', checksum) + packet_info[2:]
        return self._rawdata

    @classmethod
    def unpack(cls, raw_packet: bytes) -> Self:
        (_type, code, _, identifier, sequence) = struct.unpack('!BBHHH', raw_packet[:8])
        payload = raw_packet[8:]
        return cls(_type, code, identifier, sequence, payload)


class ICMPSocket(socket.socket):
    # 写法参考：https://fasionchan.com/network/icmp/ping-py/
    def __init__(
        self,
        timeout: int = None,
        fileno: int | None = None,
    ) -> None:
        super().__init__(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP, fileno)
        if timeout is not None:
            self.settimeout(timeout)

    def send_one(self, dst_host: str, identifier: int = None, payload: bytes = b'') -> int:
        packet = ICMPPacket(identifier=identifier, payload=payload)
        # send it
        send_length = self.sendto(packet.pack(), 0, (dst_host, 0))
        packet.incr_sequence()
        return packet

    def recv_one(self, identifier: int = None, bufsize: int = 1500) -> Tuple[str, ICMPPacket]:
        recv_bytes, (src_ip, _) = self.recvfrom(bufsize)
        # 去掉 20 个字节的 IP 头部
        packet = ICMPPacket.unpack(recv_bytes[20:])
        if identifier is not None and packet.identifier != identifier:
            return
        return src_ip, packet

    def send_and_get_detail(
        self, dst_host: str, timeout: float = DEFAULT_SOCKET_TIMEOUT, payload: bytes = b'', is_check_alive: bool = True
    ):
        if timeout is not None:
            self.settimeout(timeout)
        self.send_one(dst_host, payload=payload)
        replay_ip = None
        try:
            replay_ip, packet = self.recv_one()
        except TimeoutError:
            # TimeoutError: timed out
            # 无响应导致超时
            pass
        # type、code 定义：https://tonydeng.github.io/sdn-handbook/basic/icmp.html
        if not replay_ip or (is_check_alive and (packet.type_ != 0 or packet.code != 0)):
            return
        # 需要注意在部分情况响应IP和请求IP不一致，如扫描VMWare网卡的网络地址时会响应其它IP
        return dst_host, replay_ip, packet

    def send_and_close(
        self,
        dst_host: str,
        timeout: float = DEFAULT_SOCKET_TIMEOUT,
        payload: bytes = b'',
        is_check_alive: bool = True,
        retry: int = 3,
    ):
        ret = ''
        while retry > 0:
            ret = self.send_and_get_detail(dst_host, timeout, payload, is_check_alive)
            if ret:
                break
            retry -= 1
        self.close()
        if not ret:
            return
        return dst_host


class Scanner:
    def __init__(self, size=300) -> None:
        """初始化扫描对象；协程池子的大小和网速有关，端口扫描分为2种结果，端口开放或端口不开放（过滤之类的不考虑视为不开放）
        端口开放的情况下扫描机器会发送（即上传）几个数据包1.SYN包66Byte、2.ACK包54Byte、3.FIN/ACK包54Byte、4.ACK包54Byte；还会接收（即下载）几个数据包1.SYN/ACK包66Byte、2.ACK包54Byte、3.FIN包54-96Byte（部分应用会夹带私货，取最大96）
        也就是每次发送会占用 66+54+54+54 = 222 Byte 的带宽，接收会占用 66+60+96 = 216 Byte 的带宽，换算一下按10Mbps的上传、下载网速计算：
        上传可设置的size为 10 * 1024 / * 1024 / 8 / 222 = 5904；
        下载可设置的size为 10 * 1024 / * 1024 / 8 / 216 = 6068；
        取最小值为5904，但是要注意这是理想状态下，有些应用在连接后即使迅速切断连接还是会偷跑数据、设备本身也有网络通信请求；其次这个值的最终值还和TCP的窗口等有关，懒得研究了
        经过互联网的扫描并发池子大小最好参考比例设置，否则结果会不准确，抓包显示确实无任何回包，判断是池子过大造成互联网拥堵丢包；内网的并发池子大小可以设置任意值（最好还是65535以内），反正没试出上限值

        Args:
            size (int, optional): 协程的池子的大小，最好参考20Mbps/300按比例设置，默认：500
        """
        self.default_alive_scan_ports = [22, 80, 135, 137, 139, 443, 445]
        self.pool_dns: pro_async.AsyncPool = pro_async.AsyncPool(size // 2)
        self.pool_icmp: pro_async.AsyncPool = pro_async.AsyncPool(size)
        self.pool_tcp: pro_async.AsyncPool = pro_async.AsyncPool(size)
        self.ip_info: Dict[str, Dict[str, Union[str, Set, bool]]] = {}
        self.host_ip_map: Dict[str, str] = {}

    def parse_address(
        self, addrs: str | Iterable, split_char: str = DEFAULT_RE_SPLIT_HOST_AND_PORT_CHAR
    ) -> netaddr.IPSet:
        def gethostbyname(host):
            return socket.gethostbyname(host), host

        ret = netaddr.IPSet()
        domain_list = set()
        if isinstance(addrs, str):
            addrs = re.split(split_char, addrs)
            for addr in addrs:
                r_addr = re.search(r'(!\s)?([\d\*]{1,3}(?:\.[\d\*]{1,3}){1,3})', addr)
                if r_addr:
                    ips = ipv4_range_parse(addr)
                else:
                    domain_list.add(addr)
                    continue

                for ip in ips:
                    ret.add(ip)
                    self.init_ip_info(ip.__str__())
            # 对域名统一进行处理
            self.init_ip_info('no-dns-resolution')
            for domain in domain_list:
                self.pool_dns.sp(gethostbyname, domain)

            # socket.gaierror: [Errno 11001] getaddrinfo failed
            # 地址写法不对，或者是域名没解析
            # raise RuntimeError('"{}" has an incorrect address format or cannot be resolved'.format(addr))
            for itor in self.pool_dns.get_yeild():
                if isinstance(itor, BaseException):
                    continue
                ret.add(itor[0])
                if self.has_ip_info(itor[0]):
                    self.log_ip_info_records(itor[0], itor[1])
                else:
                    self.init_ip_info(itor[0], {'RECORDS': set([itor[1]])})
                self.host_ip_map[itor[1]] = itor[0]

        else:
            ret = netaddr.IPSet(addrs)
            for ip in addrs:
                self.init_ip_info(ip.__str__())
        return ret

    def init_ip_info(self, ip: str, value: Dict = {}) -> Dict[str, Union[str, Set]]:
        if not ip in self.ip_info:
            self.ip_info[ip] = {
                # 目标IP
                'IP': ip,
                # 域名解析或IP映射的值
                'RECORDS': set(),
                # 主机是否存活
                'ALIVE': False,
                # 存活的端口
                'PORTS': set(),
            }
        self.ip_info[ip].update(value)
        return self.ip_info[ip]

    def has_ip_info(self, ip: str) -> Dict[str, Union[str, Set]]:
        if ip in self.ip_info:
            return self.ip_info[ip]
        return

    def log_ip_info_alive(self, ip: str, is_alive: bool) -> Dict[str, Union[str, Set]]:
        self.ip_info[ip]['ALIVE'] = is_alive
        return self.ip_info[ip]

    def log_ip_info_port(self, ip: str, value: int) -> Dict[str, Union[str, Set]]:
        self.ip_info[ip]['PORTS'].add(value)
        return self.ip_info[ip]

    def log_ip_info_records(self, ip: str, value: str) -> Dict[str, Union[str, Set]]:
        self.ip_info[ip]['RECORDS'].add(value)
        return self.ip_info[ip]

    @staticmethod
    def handle_tcp_socket(ip: str, port: int, timeout: float = DEFAULT_SOCKET_TIMEOUT):
        if port < 1 or port > 65535:
            return

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(timeout)
        # client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 655350)
        # client.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 655350)
        # 1. 发送 SYN 请求连接
        # 端口不存活情况：返回 RST、ACK 直接关闭
        # 端口存活情况：
        # 1. connect_ex 处正常三次握手
        # 2. shutdown/close 处正常4次挥手
        # Linux 下会出现 OSError: [Errno 24] Too many open files，因为程序会同时打开大量的连接但是又不会迅速关闭；
        # 解决该问题可以使用 ulimit -n 102400 如果设备性能比较好，可以设置比 102400 更大的值
        # Windows 上可能的返回值：https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2
        # Linux 上可能的返回值：https://gist.github.com/gabrielfalcao/4216897
        ret = client.connect_ex((ip, port))
        # try:
        #     ret = client.connect((ip, port))
        # except socket.error:
        #     return
        # while retry:
        #     ret = client.connect_ex((ip, port))
        #     if ret == 0:
        #         break
        #     time.sleep(0.1)
        #     retry -= 1
        try:
            # Windows 下必须使用 shutdown 来检测，不知道为什么连接建立后 Windows 中错误值还是10035，而不是0
            client.shutdown(socket.SHUT_RDWR)
        except OSError:
            # 说明没有连接成功，直接返回
            # OSError: [WinError 10057] 由于套接字没有连接并且(当使用一个 sendto 调用发送数据报套接字时)没有提供地址，发送或接收数据的请求没有被接受。
            return
        client.close()
        # Linux 下必须检测 ret，Linux 下强制 shutdown 并不会抛出异常
        if ret != 0 and sys.platform not in ['win32', 'cygwin']:
            return
        # if ret != 0:
        #     return
        return ip, port

    def scan_icmp(
        self,
        ip_list: Union[netaddr.IPSet, Generator[Tuple[str], Any, None]],
        timeout: float = DEFAULT_SOCKET_TIMEOUT,
        retry: int = 3,
    ):
        for ip in ip_list:
            if isinstance(ip, netaddr.IPAddress):
                ip = ip.__str__()
            else:
                ip = ip[0]
            icmp_engine = ICMPSocket(timeout=timeout)
            self.pool_icmp.sp(icmp_engine.send_and_close, ip, timeout, retry=retry)
        for ip in self.pool_icmp.get_yeild():
            if ip:
                self.log_ip_info_alive(ip, True)
                yield ip, 0

    def scan_tcp_ports(
        self,
        ip_list: Union[netaddr.IPSet, Generator[Tuple[str], Any, None]],
        ports: Union[List[int], str] = DEFAULT_SCAN_PORTS,
        timeout: float = DEFAULT_SOCKET_TIMEOUT,
        is_yield: bool = True,
    ):
        for ip in ip_list:
            if isinstance(ip, netaddr.IPAddress):
                ip = ip.__str__()
            else:
                ip = ip[0]
            for port in ports:
                self.pool_tcp.sp(self.handle_tcp_socket, ip, port, timeout)
        if not is_yield:
            return
        return self.get_yield_tcp()

    def scan_run(
        self,
        addresses: Union[str, netaddr.IPSet],
        ports: Union[List[int], str] = DEFAULT_SCAN_PORTS,
        timeout: float = DEFAULT_SOCKET_TIMEOUT,
        is_check_alive: bool = True,
        is_yield: bool = True,
    ) -> Generator[Tuple[str, int], None, None]:
        addresses = self.parse_address(addresses)
        if isinstance(ports, str):
            ports = range_to_ports(ports)
        # 存活探测
        if is_check_alive:
            addresses = self.scan_icmp(addresses)
        gen = self.scan_tcp_ports(addresses, ports, timeout, is_yield)
        if not is_yield:
            return
        return gen

    def get_yield_tcp(self) -> Generator[Tuple[str, int], None, None]:
        for ip_and_port in self.pool_tcp.get_yeild():
            if not ip_and_port:
                continue
            self.log_ip_info_alive(ip_and_port[0], True)
            self.log_ip_info_port(ip_and_port[0], ip_and_port[1])
            yield ip_and_port

    def show(self, hosts_info: Dict[str, Dict[str, Union[str, Set]]] = None, is_only_alive: bool = True):
        hosts_info = hosts_info or self.ip_info
        if not hosts_info:
            print('no host found.')

        for ip, infos in hosts_info.items():
            if is_only_alive and not infos['ALIVE']:
                continue

            print(ip)
            for key, info in infos.items():
                if isinstance(info, Iterable) and not isinstance(info, (str, bytes)):
                    info = ', '.join([str(i) for i in sorted(info)])
                print(' |- {:8}: {}'.format(key, info))
            print()

    def gen_expand_ipinfo(self) -> List[Dict[str, str | int | None]]:
        ret = []
        for ip in self.ip_info:
            self.ip_info[ip]['RECORDS'] = list(set(self.ip_info[ip]['RECORDS']))
            info_base = {'IP': ip, 'ALIVE': self.ip_info[ip]['ALIVE']}
            for port in self.ip_info[ip]['PORTS']:
                if self.ip_info[ip]['RECORDS']:
                    for record in self.ip_info[ip]['RECORDS']:
                        info = copy.deepcopy(info_base)
                        info['RECORDS'] = record
                        info['PORT'] = port
                        ret.append(info)
                else:
                    info = copy.deepcopy(info_base)
                    info['RECORDS'] = None
                    info['PORT'] = port
                    ret.append(info)
        return ret


if __name__ == '__main__':
    pass
    # IP_STYLE = [
    #     # '192.168.1.1/255.255.255.192',
    #     # '192.168.1.1-192.168.1.10',
    #     # '192.168.1.1_192.168.1.10',
    #     # '192.168.1.1-23',
    #     # '192.168.1.1/24',
    #     # '192.168.1.1',
    #     # # '192.168.0.2-1.*',  # 不支持
    #     # '!192.168.0.2-19',
    #     # '192.168.0.*',
    #     # '192.168.*.*',
    #     # # '192.168.*',        # 不支持
    #     '''192.168.1.1/255.255.255.192
    #     192.168.8.8/24
    #     !192.168.8.192/26
    #     !192.168.8.64/26
    #     '192.168.8.0/26'
    #     '192.168.8.68'        '''
    # ]
    # for ip in IP_STYLE:
    #     print('rawstr: {}'.format(ip))
    #     print('output: {}'.format(ipv4_range_parse(ip)))
    #     for ip_addr in ipv4_range_parse(ip):
    #         print('ip: {}, int: {}, bin: {}'.format(ip_addr, int(ip_addr), bin(ip_addr)))
    #         break
    # RANGE = '0  ,  21-23 ;22 \n 21 80-88; 65535'
    # print(sorted(range_to_ports(RANGE)))
    # print(len(range_to_ports(RANGE)))
    # # shodan 收集端口处理
    # # sorted(set([int(i) % 10000 for i in t.split()]))
    # print(ports_to_range([0, 1, 2, 3, 7, 8, 10, 11, 13, 15, 17, 19]))

    # icmp = ICMPEngine()
    # print(icmp.send('192.168.245.130'))

    scanner = Scanner()
    # # print(scanner.handle_tcp_socket('192.168.245.130'))
    # # print([i for i in scanner.scan_icmp('www.baidu.com', timeout=3)])
    # # print(len(scanner.default_scan_ports))

    s_time = time.time()
    # 速度比较优秀，但是1s内瞬发任务量在超过5000个端口时，会丢失精准度，找了很多材料没找到问题，猜测是互联网拥堵造成的
    # [
    #     _
    #     for _ in scanner.scan_run(
    #         'nmap.org , sectools.org;seclists.org, insecure.org ,www.vulnweb.com，www.testfire.net；zero.webappsecurity.com\n  scanme.nmap.org,www.vulhub.org.cn,vulhub.org,www.vulnhub.com,vulnstack.qiyuanxuetang.net,www.pentesterlab.com,vulapps.evalbug.com,www.itsecgames.com,www.mozhe.cn,ctf.aabyss.cn'
    #     )
    # ]
    scanner.scan_run('192.168.245.0/24', is_yield=False)
    print([i for i in scanner.get_yield_tcp()])
    # [i for i in scanner.scan_run('192.168.245.130', '22, 222,5432')]
    print(time.time() - s_time)
    # print(scanner.map_ip_address)
    # print(scanner.hosts_info)
    scanner.show(is_only_alive=False)
    print(scanner.gen_expand_ipinfo())
