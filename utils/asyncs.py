from gevent import monkey

monkey.patch_socket()

import socket
import sys
from queue import Queue

import gevent


def make_port_list(ports):
    new_port_list = []

    if "," in ports:
        temp_list = ports.split(",")
        for port in temp_list:
            if "-" in port:
                for p in range(int(port.split("-")[0]), int(port.split("-")[1]) + 1):
                    new_port_list.append(p)
            else:
                new_port_list.append(port)

    elif "-" in ports:
        for p in range(int(ports.split("-")[0]), int(ports.split("-")[1]) + 1):
            new_port_list.append(p)

    else:
        new_port_list.append(ports)

    return new_port_list


def coroutines():
    # 开启多协程
    cos = []
    num = ip_port.qsize()
    print(num)
    for i in range(num):
        # 调用工作函数
        cor = gevent.spawn(star_scan)
        cos.append(cor)
    gevent.joinall(cos)


def star_scan():
    sockets = ip_port.get()
    ip = sockets[0]
    port = int(sockets[1])
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 创建一个基于网络并且使用tcp协议的套接字，用于通信。
        s.settimeout(0.02)  # 设置超时时间
        s.connect((ip, port))
    except Exception as e:
        pass
        # print("[+]{}:{} \tclosed".format(ip, port))
    else:
        res = s.recv(3096).decode('utf-8').encode()
        print(res)
        print("[+]{}:{} \topen".format(ip, port))
    finally:
        s.close()


ip_port = Queue()
ip = "192.168.247.135"
port = "21,22-2400"
port_list = make_port_list(port)
print("total port num:{}".format(len(port_list)))

for port in port_list:
    ip_port.put([ip, port])

coroutines()
