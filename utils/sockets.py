import socket
import threading
import time
from typing import AnyStr, Tuple


class Server:
    def __init__(
        self,
        host: str = '127.0.0.1',
        port: int = 3380,
        family: int = -1,
        _type: int = -1,
        proto: int = -1,
    ) -> None:
        self.host = host
        self.port = port
        self.service = socket.socket(family, _type, proto)
        self.service.bind((self.host, self.port))
        self.end_message: bytes = None

    def set_end_message(self, message: AnyStr, encoding='utf-8'):
        if isinstance(message, str):
            self.end_message = message.encode(encoding)
        else:
            self.end_message = message

    def run(self, queue_size: int = 10):
        self.service.listen(queue_size)

    def wait_request(
        self, block_size: int = 4096, timeout_nondate: float = 3, timeout: float = 60
    ) -> Tuple[str, int, bytes]:
        def while_recv():
            nonlocal ret
            nonlocal s_time
            nonlocal is_receiving
            while True:
                try:
                    # Windows 系统不支持 socket.MSG_WAITALL，因此该函数无法处理客户端长周期发送数据的情况，比如每秒客户端发送1个字节到服务端
                    rec_data = client.recv(block_size)
                    s_time = time.time()
                    ret += rec_data
                    if len(rec_data) % block_size != 0:
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

        client, address = self.service.accept()
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


def new(*args, **kwargs):
    return Server(*args, **kwargs)


if __name__ == '__main__':
    ss = Server()
    ss.run()
    ss.set_end_message('success')
    result = ss.wait_request()
    print(result)
