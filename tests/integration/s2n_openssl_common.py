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

from s2n_test_common import *

OPENSSL_SIGNALS = {
    Mode.client: "CONNECTED",
    Mode.server: "ACCEPT",
}

VERSION_ARGS = {
    S2N_TLS10: "-tls1",
    S2N_TLS11: "-tls1_1",
    S2N_TLS12: "-tls1_2",
    S2N_TLS13: "-tls1_3",
}

def get_openssl_cmd(scenario):
    openssl_cmd = [ "openssl"]

    if scenario.s2n_mode is Mode.client:
        openssl_cmd.extend(["s_server", "-accept", str(scenario.port)])
    else:
        openssl_cmd.extend(["s_client", "-connect", str(scenario.host) + ":" + str(scenario.port)])

    openssl_cmd.extend(["-cert", CERT,
                        "-key", KEY,
                        "-tlsextdebug"])

    if scenario.version:
        openssl_cmd.append(VERSION_ARGS[scenario.version])

    if scenario.cipher:
        openssl_cmd.extend(["-ciphersuites", str(scenario.cipher)])

    openssl_cmd.extend(scenario.peer_flags)

    return openssl_cmd

def get_openssl(scenario):
    openssl_cmd = get_openssl_cmd(scenario)
    openssl = get_process(openssl_cmd)
    
    if not wait_for_output(openssl, OPENSSL_SIGNALS[scenario.s2n_mode.other()]):
        raise AssertionError("openssl %s: %s" % (scenario.s2n_mode.other(), get_error(openssl)))

    sleep(2)
    return openssl

def openssl_test(test_func=None):
    return get_test(get_openssl, test_func)

