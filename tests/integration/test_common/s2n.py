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

from .common import Mode, Version, Command
from .constants import TEST_ECDSA_CERT, TEST_ECDSA_KEY


S2N_SIGNALS = {
    Mode.client: "Connected to",
    Mode.server: "Listening on"
}


class S2NCommand(Command):
    def __init__(self, mode, *args, **kwargs):
        super().__init__(mode, s2n_cmd(mode, *args, **kwargs), S2N_SIGNALS)


def s2n_cmd(mode, endpoint, port=None, version=None, cipher_preferences=None, corked_io=False):
    mode_char = 'c' if mode is Mode.client else 'd'
    if not cipher_preferences: cipher_preferences = "test_all" 

    cmd = [ "../../bin/s2n%c" % mode_char,
            "-c", cipher_preferences ]

    if version is Version.TLS13:
        cmd += [ "--tls13" ]

    if corked_io:
        cmd += [ "-C" ]

    if mode is Mode.server:
        cmd += [ "--key", TEST_ECDSA_KEY ]
        cmd += [ "--cert", TEST_ECDSA_CERT ]

    cmd += [ endpoint ]
    if port:
        cmd += [ str(port) ]

    return cmd

