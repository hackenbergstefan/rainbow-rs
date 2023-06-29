# SPDX-FileCopyrightText: 2023 Stefan Hackenberg <mail@stefan-hackenberg.de>
#
# SPDX-License-Identifier: MIT

import struct
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


number_of_samples = 4
number_of_traces = 3

if __name__ == "__main__":
    import logging
    import time
    import timeit

    logging.basicConfig(level=logging.DEBUG)

    sock = SimpleSocket2()
    sock.con("localhost", 1234)
    sock.sock.settimeout(1)
    t = time.time()
    for i in range(number_of_traces):
        sock.simpleserial_write(0x01, bytes([i, i + 1]))
        trace = struct.unpack(
            f">{number_of_samples}f",
            (sock.sock.recv(4 * number_of_samples)),
        )
        print(trace)
    print(time.time() - t)
