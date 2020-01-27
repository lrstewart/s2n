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
import collections

from ..test_common.common import Mode, RetryBackoff
from ..test_common.constants import CERT_BUNDLE
from ..test_common.params import ALL_CORKED_IO
from ..test_common.s2n import S2NCommand


class Endpoint():

    def __init__(self, endpoint, cipher_preferences=None, expected_cipher=None, allowed_to_fail=False):
        self.endpoint = endpoint
        self.cipher_preferences = cipher_preferences
        self.expected_cipher = expected_cipher
        self.allowed_to_fail = allowed_to_fail

    def __str__(self):
        name = self.endpoint
        if self.cipher_preferences: name += "::" + self.cipher_preferences
        if self.expected_cipher: name += "::" + self.expected_cipher
        return name

    def to_param(self):
        marks = []
        if self.allowed_to_fail: marks.append(pytest.mark.xfail)
        return pytest.param(self, id=str(self), marks=marks)


TEST_ENDPOINTS = [
    Endpoint("amazon.com"),
    Endpoint("facebook.com"),
    Endpoint("google.com"),
    Endpoint("netflix.com"),
    Endpoint("s3.amazonaws.com"),
    Endpoint("twitter.com"),
    Endpoint("wikipedia.org", allowed_to_fail=True),
    Endpoint("yahoo.com"),
    Endpoint("kms.us-east-1.amazonaws.com",
             cipher_preferences="KMS-PQ-TLS-1-0-2019-06",
             expected_cipher="ECDHE-BIKE-RSA-AES256-GCM-SHA384" ),
    Endpoint("kms.us-east-1.amazonaws.com",
             cipher_preferences="PQ-SIKE-TEST-TLS-1-0-2019-11",
             expected_cipher="ECDHE-SIKE-RSA-AES256-GCM-SHA384" ),
]

ALL_TEST_ENDPOINTS = map(Endpoint.to_param, TEST_ENDPOINTS)


@pytest.mark.flaky(max_runs=5, rerun_filter=RetryBackoff())
@pytest.mark.parametrize("endpoint_config", ALL_TEST_ENDPOINTS)
@pytest.mark.parametrize("use_corked_io",   ALL_CORKED_IO)
def test_endpoints(use_corked_io, endpoint_config):
    success_signal = "Cipher negotiated: " + endpoint_config.expected_cipher if endpoint_config.expected_cipher else None

    s2n = S2NCommand(Mode.client, endpoint_config.endpoint,
                     cipher_preferences=endpoint_config.cipher_preferences, corked_io=use_corked_io)
    s2n += [ "--ca-file", CERT_BUNDLE ] # Use a valid certificate chain
    s2n += [ "--alpn", "http/1.1"]

    conn = s2n.connect(success_signal)
    s2n.close()
