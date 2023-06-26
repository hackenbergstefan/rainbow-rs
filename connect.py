import socket

from chipwhisperer.capture.targets import SimpleSerial2


class SimpleSocket2(SimpleSerial2):
    def __init__(self):
        super().__init__()
        self.sock = socket.socket()

    def con(self, address: str, port: int):
        self.sock.connect((address, port))

    def write(self, data):
        if type(data) is list:
            data = bytearray(data)
        self.sock.send(data)

    def read(self, num_char=0, timeout=250):
        self.sock.settimeout(timeout)
        return self.sock.recv(num_char)


if __name__ == "__main__":
    import logging
    import time
    import timeit

    logging.basicConfig(level=logging.DEBUG)

    sock = SimpleSocket2()
    sock.con("localhost", 1234)
    t = time.time()
    for _ in range(1):
        sock.simpleserial_write(0x01, 16 * b"\x01")
        sock.sock.recv(2)
    print(time.time() - t)
