import socket
import threading
import time
from typing import AnyStr, Tuple, Union


class Server:
    def __init__(
        self,
        host: str = '127.0.0.1',
        port: int = 3380,
        is_block: bool = False,
        family: int = -1,
        _type: int = -1,
        proto: int = -1,
    ) -> None:
        self.host = host
        self.port = port
        self.raw = socket.socket(family, _type, proto)
        self.raw.bind((self.host, self.port))
        self.end_message: bytes = b''
        self.raw.setblocking(is_block)

    def set_end_message(self, message: AnyStr, encoding='utf-8'):
        if isinstance(message, str):
            self.end_message = message.encode(encoding)
        else:
            self.end_message = message

    def run(self, queue_size: int = 10):
        self.raw.listen(queue_size)

    # def accept(self) -> tuple[socket.socket, Tuple[str, int]]:
    #     fd, addr = self.raw._accept()
    #     sock = ClientTcp(self.family, self.type, self.proto, fileno=fd)
    #     # Issue #7995: if no default timeout is set and the listening
    #     # socket had a (non-zero) timeout, force the new socket in blocking
    #     # mode to override platform-specific socket flags inheritance.
    #     if getdefaulttimeout() is None and self.gettimeout():
    #         sock.setblocking(True)
    #     return sock, addr
    #     return self.raw.accept()

    def wait_request(
        self, bufsize: int = 4096, timeout_nondate: float = 3, timeout: float = 60
    ) -> Tuple[str, int, bytes]:
        def while_recv():
            nonlocal ret
            nonlocal s_time
            nonlocal is_receiving
            while True:
                try:
                    # Windows 系统不支持 socket.MSG_WAITALL，因此该函数无法处理客户端长周期发送数据的情况，比如每秒客户端发送1个字节到服务端
                    rec_data = client.recv(bufsize)
                    s_time = time.time()
                    ret += rec_data
                    if len(rec_data) % bufsize != 0:
                        break
                except TimeoutError:
                    # 连接时间过长 settimeout 造成的错误
                    break
                except BrokenPipeError:
                    # 当没数据 timeout_nondate 后被强制 shutdown 造成的错误
                    break
            is_receiving = False

        ret = b''
        is_receiving = True

        client, address = self.raw.accept()
        client.settimeout(timeout)

        thr = threading.Thread(target=while_recv)
        thr.start()
        s_time = time.time()
        while time.time() - s_time < timeout_nondate and is_receiving:
            time.sleep(0.5)
        if self.end_message:
            client.send(self.end_message)
        client.shutdown(socket.SHUT_RDWR)
        return address[0], address[1], ret


class ClientTcp(socket.socket):
    def __init__(
        self,
        host: str,
        port: int,
        family: socket.AddressFamily | int = -1,
        type: socket.SocketKind | int = -1,
        proto: int = -1,
        fileno: int | None = None,
    ) -> None:
        super().__init__(family, type, proto, fileno)
        self.host = host
        self.port = port

    def connect(self, __address: Tuple[str, int] = None) -> None:
        if not __address:
            __address = (self.host, self.port)
        return super().connect(__address)

    def is_connect(self) -> bool:
        try:
            host, port = self.getpeername()
            return True
        except OSError:
            return False

    def rq(
        self, data: Union[bytes, str], bufsize: int = 4096, timeout: float = 3, delay: float = 1, retry: int = 3
    ) -> Tuple[Union[Exception, None], Union[bytes, None]]:
        """
        当 timeout 小于 0 时跳过数据接收，发送完成直接退出函数
        """
        if not self.is_connect():
            return ConnectionError('the socket connection was disconnected.'), None
        if isinstance(data, str):
            data = str2byt(data)
        error = None
        while retry:
            retry -= 1
            # 部分服务端数据处理速度很慢，只能强制 delay
            try:
                self.sendall(data)
                if timeout <= 0:
                    continue
                ret = self.rcv(bufsize)
                return None, ret
            except Exception as err:
                error = err
            time.sleep(delay)
        return error, None

    def close(self) -> None:
        if self.is_connect():
            super().shutdown(socket.SHUT_RDWR)
        super().close()

    def rcv(self, bufsize: int = 4096):
        ret = b''

        raw_timeout = self.gettimeout()
        self.settimeout(0.01)
        while True:
            # Windows 系统不支持 socket.MSG_WAITALL，因此该函数无法处理长周期发送数据的情况，比如每秒发送端发送1个字节到接收端
            try:
                data_rcv = self.recv(bufsize)
                ret += data_rcv
                data_len = len(data_rcv)
                if data_len == 0:
                    break
            except TimeoutError as err:
                # 连接时间过长 socket.settimeout 造成的错误
                break
            # if data_len == 0 or len(data_rcv) % bufsize != 0:
            #     break
            # try:
            #     # Windows 系统不支持 socket.MSG_WAITALL，因此该函数无法处理长周期发送数据的情况，比如每秒发送端发送1个字节到接收端
            #     rec_data = self.recv(bufsize)
            #     ret += rec_data
            #     if len(rec_data) % bufsize != 0:
            #         break
            # except TimeoutError as err:
            #     # 连接时间过长 socket.settimeout 造成的错误
            #     error = err
            # except BrokenPipeError:
            #     # 当没数据 timeout 后被强制 shutdown 造成的错误
            #     error = err
            # except BlockingIOError:
            #     # 超时后对端才发回数据，因为等待太久，为了速度这部分数据直接丢弃
            #     error = err
        self.settimeout(raw_timeout)
        return ret


class ClientManager:
    def __init__(
        self,
        is_block: bool = True,
        family: socket.AddressFamily | int = -1,
        _type: socket.SocketKind | int = -1,
        proto: int = -1,
        timeout: float = 8,
    ):
        self.is_block = is_block
        self.family = family
        self._type = _type
        self.proto = proto
        self.timeout = timeout

    def new_tcp(
        self,
        host: str,
        port: int,
        family: socket.AddressFamily | int = None,
        _type: socket.SocketKind | int = None,
        proto: int = None,
        file_no: int | None = None,
    ) -> ClientTcp:
        """
        创建一个 tcp 的 socket 通道，但不会直接启动连接
        """
        skt = ClientTcp(host, port, family or self.family, _type or self._type, proto or self.proto, file_no)
        skt.setblocking(self.is_block)
        if self.timeout > 0:
            skt.settimeout(self.timeout)
        return skt


def str2byt(content: str):
    return content.encode()


def hex2byt(content: str):
    return bytes.fromhex(content)


def new(*args, **kwargs):
    return Server(*args, **kwargs)


if __name__ == '__main__':
    # b''.decode()
    # ss = Server()
    # ss.run()
    # ss.set_end_message('success')
    # result = ss.wait_request()
    # print(result)

    sm = ClientManager()
    sk = sm.new_tcp('192.168.245.128', 7001)
    sk.connect()
    print(10001, sk.rq(b't3 9.2.0.0\nAS:255\nHL:92\nMS:10000000\nPU:t3://127.0.0.1:7001\n\n'))
