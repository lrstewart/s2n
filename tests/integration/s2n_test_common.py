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

import sys
import subprocess
import multiprocessing
import select
from enum import Enum
from multiprocessing.pool import ThreadPool
from s2n_test_constants import *
from time import sleep

CERT = TEST_ECDSA_CERT
KEY = TEST_ECDSA_KEY

ALL_VERSIONS = [S2N_SSLv3, S2N_TLS10, S2N_TLS11, S2N_TLS12, S2N_TLS13]

class Cipher():
    def __init__(self, name, min_version):
        self.name = name
        self.min_version = min_version

    def __str__(self):
        return self.name

ALL_CIPHERS = [
    Cipher("TLS_AES_256_GCM_SHA384", S2N_TLS13),
    Cipher("TLS_CHACHA20_POLY1305_SHA256", S2N_TLS13),
    Cipher("TLS_AES_128_GCM_SHA256", S2N_TLS13)
]

class Mode(Enum):
    client = 0
    server = 1

    def __str__(self):
        return "Client" if self is Mode.client else "Server"

    def other(self):
        return Mode.server if self is Mode.client else Mode.client

ALL_MODES = [e.value for e in Mode]

class Status:
    def __init__(self, name, color):
        self.name = name
        self.color = color

    def __str__(self):
        return with_color(self.name, self.color)

PASSED = Status("PASSED", 32 )
FAILED = Status("FAILED", 31 )

class Result:
    def __init__(self, error=None):
        self.error = error
        self.status = PASSED if error == None else FAILED

    def __str__(self):
        result = str(self.status)
        if self.error:
            result += "\n\t\t%s %s" % (with_color("Error:", FAILED.color), self.error)
        return result

class Scenario:
    def __init__(self, s2n_mode, host, port, version=None, cipher=None, s2n_flags=[], peer_flags=[]):
        self.s2n_mode = s2n_mode
        self.host = host
        self.port = port
        self.version = version
        self.cipher = cipher
        self.s2n_flags = s2n_flags
        self.peer_flags = peer_flags

    def __str__(self):
        cipher = self.cipher if self.cipher else "ANY"
        return "\tMode:%s Endpoint:%s:%s Cipher:%s" % (self.s2n_mode, self.host, self.port, str(cipher).ljust(30))

def with_color(msg, color):
    if sys.stdout.isatty():
        return "\033[%d;1m%s\033[0m" % (color, msg)
    else:
        return msg

def cleanup_processes(*processes):
    for p in filter(None, processes):
        p.kill()
        p.wait()

def create_thread_pool():
    threadpool_size = multiprocessing.cpu_count() * 2  # Multiply by 2 since performance improves slightly if CPU has hyperthreading
    print("\tCreating ThreadPool of size: " + str(threadpool_size))
    threadpool = ThreadPool(processes=threadpool_size)
    return threadpool

def get_error(process):
    return process.stderr.readline().decode("utf-8")

def wait_for_output(process, marker, line_limit=10):
    for count in range(line_limit):
        line = process.stdout.readline().decode("utf-8")
        if marker in line:
            return True
    return False

def get_process(cmd):
    return subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def get_test(get_peer, test_func=None):
    def test(scenario):
        client = None
        server = None
        try:
            server, client = connect(get_peer, scenario)
            if test_func:
                return test_func(server, client)
            else:
                return Result()
        except AssertionError as error:
            return Result(error)
        finally:
            cleanup_processes(server, client)
    return test

def run_scenarios(test_func, scenarios):
    failed = 0
    threadpool = create_thread_pool()
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
        if result != PASSED:
            failed += 1

    return failed


def get_scenarios(host, start_port, s2n_modes=[Mode.client, Mode.server], versions=[None], ciphers=[None], s2n_flags=[], peer_flags=[]):
    port = start_port
    scenarios = []

    for version in versions:
        for cipher in ciphers:
            if cipher.min_version > version:
                continue

            for s2n_mode in s2n_modes:
                scenarios.append(Scenario(s2n_mode, host, port, version, cipher, s2n_flags, peer_flags))
                port += 1
        
    return scenarios

def connect(get_peer, scenario):
    server = get_s2n(scenario) if scenario.s2n_mode is Mode.server else get_peer(scenario)
    client = get_peer(scenario) if scenario.s2n_mode is Mode.server else get_s2n(scenario)

    return (server, client)

def get_s2n_cmd(scenario):
    mode_char = 'c' if scenario.s2n_mode is Mode.client else 'd'

    s2n_cmd = [ "../../bin/s2n%c" % mode_char,
                "-c", "test_all",
                "--insecure"]

    if scenario.s2n_mode is Mode.server:
        s2n_cmd.extend(["--key", KEY])
        s2n_cmd.extend(["--cert", CERT])

    if scenario.version is S2N_TLS13:
        s2n_cmd.append("--tls13")

    s2n_cmd.extend(scenario.s2n_flags)
    s2n_cmd.extend([str(scenario.host), str(scenario.port)])

    return s2n_cmd

S2N_SIGNALS = {
    Mode.client: "Connected to",
    Mode.server: "Listening on"
}

def get_s2n(scenario):
    s2n_cmd = get_s2n_cmd(scenario)
    s2n = get_process(s2n_cmd)

    if not wait_for_output(s2n, S2N_SIGNALS[scenario.s2n_mode]):
        raise AssertionError("s2n %s: %s" % (scenario.s2n_mode, get_error(s2n)))

    sleep(0.1)
    return s2n
