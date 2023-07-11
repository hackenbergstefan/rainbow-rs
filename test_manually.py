# SPDX-FileCopyrightText: 2023 Stefan Hackenberg <mail@stefan-hackenberg.de>
#
# SPDX-License-Identifier: MIT

import json
import socket

from chipwhisperer.capture.targets import SimpleSerial2


class SimpleSocket2(SimpleSerial2):
    def __init__(self):
        super().__init__()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(1)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def con(self, address: str, port: int):
        self.sock.connect((address, port))

    def write(self, data):
        self.sock.send(json.dumps({"VictimData": list(data)}).encode() + b"\n")

    def read(self, num_char=0, timeout=250):
        self.sock.settimeout(timeout)
        return self.sock.recv(num_char)


number_of_samples = 4
number_of_traces = 10_000

if __name__ == "__main__":
    import logging
    import time

    logging.basicConfig(level=logging.DEBUG)

    sock = SimpleSocket2()
    sock.con("localhost", 6666)
    t = time.time()
    for i in range(number_of_traces):
        sock.simpleserial_write(0x01, bytes([i % 256, (i + 1) % 256]))
        sock.sock.send(json.dumps({"GetTrace": number_of_samples}).encode() + b"\n")
        sock.sock.recv(4096)
    print(time.time() - t)
