#
# Copyright 2017-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
import pytest

from ..test_common.common import Version, Command, random_port
from ..test_common.constants import DEFAULT_ENDPOINT
from ..test_common.params import ALL_MODES, ALL_CORKED_IO, ALL_CURVES, cipher_params
from ..test_common.s2n import S2NCommand
from ..test_common.openssl import OpensslCommand


@pytest.mark.parametrize("mode",            ALL_MODES)
@pytest.mark.parametrize("version, cipher", cipher_params([Version.TLS13]))
@pytest.mark.parametrize("use_corked_io",   ALL_CORKED_IO)
@pytest.mark.parametrize("curve",           ALL_CURVES)
def test_handshake(random_port, mode, version, cipher, curve, use_corked_io):
    port = random_port

    s2n = S2NCommand(mode, DEFAULT_ENDPOINT, port=port, version=version, corked_io=use_corked_io)
    s2n += [ "--insecure"] # Do not validate certificates

    openssl = OpensslCommand(mode.inverse(), DEFAULT_ENDPOINT, port=port, version=version, cipher=cipher, curve=curve)

    (client, server) = s2n.negotiate(openssl)

    openssl.close()
    s2n.close()
