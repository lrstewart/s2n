##
# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
#

"""
Common functions to run s2n integration tests.
"""

import os
import pytest
import subprocess
import time
from collections import defaultdict
from enum import Enum as BaseEnum


class Enum(BaseEnum):

    def __str__(self):
        return self.name

    @classmethod
    def all(cls):
        return cls


class Libcrypto(Enum):
    openssl_111      = "openssl-1.1.1"
    openssl_102      = "openssl-1.0.2"
    openssl_102_fips = "openssl-1.0.2-fips"
    libressl         = "libressl"

    @classmethod
    def supported(cls):
        return Libcrypto(str(os.getenv("S2N_LIBCRYPTO")).strip('"'))


class Version(int, Enum):
    SSLv3 = 30
    TLS10 = 31
    TLS11 = 32
    TLS12 = 33
    TLS13 = 34


class Mode(Enum):
    client = 0
    server = 1

    def inverse(self):
        return Mode.server if self is Mode.client else Mode.client


class Command(list):

    def __init__(self, mode, cmd, success_signals):
        self.mode = mode
        self._success_signals = success_signals
        super().__init__(cmd)

    def connect(self, success_signal=None, **kwargs):
        if not success_signal:
            success_signal = self._success_signals[self.mode]

        self.process = get_process(self)
        
        if not self.wait_for_output(success_signal, **kwargs):
            self.close()
            assert False, str(self.mode) + ": " + self.get_error()
        
        return self.process

    def get_error(self, *args, **kwargs):
        assert self.process
        return get_error(self.process, *args, **kwargs)

    def wait_for_output(self, *args, **kwargs):
        assert self.process
        return wait_for_output(self.process, *args, **kwargs)

    def negotiate(self, other_cmd):
        assert other_cmd.mode is self.mode.inverse()

        # Start the server, then the client.
        if self.mode is Mode.client:
            other_cmd.process = other_cmd.connect()
            self.process = self.connect()
            return (other_cmd.process, self.process)
        else:
            self.process = self.connect()
            other_cmd.process = other_cmd.connect()
            return (self.process, other_cmd.process)

    def close(self):
        cleanup_processes(self.process)

    def __str__(self):
        return " ".join(self)


def get_error(process, line_limit=10):
    error_msg = ""
    for count in range(line_limit):
        line = process.stderr.readline().decode("utf-8")
        if line:
            error_msg += "\n" + line
        else:
            return error_msg

    return error_msg


def wait_for_output(process, marker, line_limit=25):
    for count in range(line_limit):
        line = process.stdout.readline().decode("utf-8")
        if marker in line:
            return True
        if not line:
            return False
    return False


def cleanup_processes(*processes):
    for p in filter(None, processes):
        p.kill()
        p.wait()


def get_process(cmd):
    return subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class RetryBackoff:
    def __init__(self, step_size=0.01):
        self._step_size = step_size
        self._test_records = defaultdict(int)

    def __call__(self, err, name, test, plugin):
        time.sleep(self._test_records[name])
        self._test_records[name] += self._step_size
        return True


_port_counter = iter(range(8888, 65535))
_ports_available = set()

@pytest.fixture()
def random_port():
    try:
        port = _ports_available.pop()
    except KeyError:
        port = next(_port_counter)
    yield port
    _ports_available.add(port)

