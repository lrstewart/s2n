#
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
Common functions used to create test openssl servers and clients.
"""

from .common import Mode, Version, Command
from .constants import TEST_ECDSA_CERT, TEST_ECDSA_KEY
from time import sleep


OPENSSL_SIGNALS = {
    Mode.client: "CONNECTED",
    Mode.server: "ACCEPT",
}


VERSION_ARGS = {
    Version.TLS10: "-tls1",
    Version.TLS11: "-tls1_1",
    Version.TLS12: "-tls1_2",
    Version.TLS13: "-tls1_3",
}


class OpensslCommand(Command):
    def __init__(self, mode, *args, **kwargs):
        super().__init__(mode, openssl_cmd(mode, *args, **kwargs), OPENSSL_SIGNALS)

    def connect(self, success_signal=None, **kwargs):
        connection = super().connect(success_signal, **kwargs)

        # Openssl outputs the success signal BEFORE binding the socket, so wait a little
        sleep(0.1)
        return connection


def openssl_cmd(mode, endpoint, port=None,
                  version=None, cipher=None, curve=None):
    openssl_cmd = [ "openssl"]

    if mode is Mode.client:
        openssl_cmd += [ "s_client", "-connect", str(endpoint) + ":" + str(port) ]
    else:
        openssl_cmd += [ "s_server", "-accept", str(port) ]

    openssl_cmd += [ "-cert", TEST_ECDSA_CERT,
                     "-key", TEST_ECDSA_KEY,
                     "-tlsextdebug" ]

    if version:
        openssl_cmd += [ VERSION_ARGS[version] ]

    if cipher:
        if cipher.min_version < Version.TLS13:
            openssl_cmd += [ "-cipher", str(cipher) ]
        else:
            openssl_cmd += [ "-ciphersuites", str(cipher) ]

    if curve:
        openssl_cmd += [ "-curves", curve ]

    return openssl_cmd

