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
Most s2n integration tests are run against a variety of arguments.
A "scenario" represents a specific set of inputs, such as address,
cipher, version, etc.
"""

import multiprocessing
from enum import Enum as BaseEnum
from multiprocessing.pool import ThreadPool


class Enum(BaseEnum):
    @classmethod
    def all(cls):
        return [v.value for v in cls]


class Cipher():
    def __init__(self, name, min_version):
        self.name = name
        self.min_version = min_version

    def __str__(self):
        return self.name

    @classmethod
    def all(cls):
        return ALL_CIPHERS


class Version(Enum):
    SSLv3 = 30
    TLS10 = 31
    TLS11 = 32
    TLS12 = 33
    TLS13 = 34


class Mode(Enum):
    client = 0
    server = 1

    def __str__(self):
        return "Client" if self.is_client() else "Server"

    def is_client(self):
        return self is Mode.client

    def is_server(self):
        return self is Mode.server

    def other(self):
        return Mode.server if self.is_client() else Mode.client


ALL_CIPHERS = [
    Cipher("TLS_AES_256_GCM_SHA384", Version.TLS13),
    Cipher("TLS_CHACHA20_POLY1305_SHA256", Version.TLS13),
    Cipher("TLS_AES_128_GCM_SHA256", Version.TLS13)
]


class Scenario:

    """
    Describes the configuration for a specific TLS connection.

    """

    def __init__(self, s2n_mode, host, port, version=None, cipher=None, s2n_flags=[], peer_flags=[]):
        """
        Args:
            s2n_mode: whether s2n should act as a client or server.
            host: host to connect or listen to.
            port: port to connect or listen to.
            version: which TLS protocol version to use. If None, the implementation will
                use its default.
            cipher: which cipher to use. If None, the implementation will use its default.
            s2n_flags: any extra flags that should be passed to s2n.
            peer_flags: any extra flags that should be passed to the TLS implementation
                that s2n connects to.

        """
        self.s2n_mode = s2n_mode
        self.host = host
        self.port = port
        self.version = version
        self.cipher = cipher
        self.s2n_flags = s2n_flags
        self.peer_flags = peer_flags

    def __str__(self):
        cipher = self.cipher if self.cipher else "ANY"
        return "Mode:%s Endpoint:%s:%s Cipher:%s" % (self.s2n_mode, self.host, self.port, str(cipher).ljust(30))


def __create_thread_pool():
    threadpool_size = multiprocessing.cpu_count() * 2  # Multiply by 2 since performance improves slightly if CPU has hyperthreading
    threadpool = ThreadPool(processes=threadpool_size)
    return threadpool


def run_scenarios(test_func, scenarios):
    failed = 0
    threadpool = __create_thread_pool()
    results = {}

    print("\tRunning scenarios: " + str(len(scenarios)))

    for scenario in scenarios:
        async_result = threadpool.apply_async(test_func, (scenario,))
        results.update({scenario: async_result})

    threadpool.close()
    threadpool.join()

    for scenario, async_result in results.items():
        result = async_result.get()
        print("%s %s" % (str(scenario), str(result).rstrip()))
        if not result.is_success:
            failed += 1

    return failed


def get_scenarios(host, start_port, s2n_modes=Mode.all(), versions=[None], ciphers=[None], s2n_flags=[], peer_flags=[]):
    port = start_port
    scenarios = []

    for version in versions:
        for cipher in ciphers:
            if cipher.min_version.value > version.value:
                continue

            for s2n_mode in s2n_modes:
                scenarios.append(Scenario(s2n_mode, host, port, version, cipher, s2n_flags, peer_flags))
                port += 1
        
    return scenarios

