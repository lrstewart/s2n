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
Common cipher lists and utility functions.
"""

import os


RUN_DIR = os.path.abspath(os.path.dirname(__file__))
INTEG_TEST_ROOT = os.path.abspath(os.path.join(RUN_DIR, os.path.pardir))
TEST_ROOT = os.path.abspath(os.path.join(INTEG_TEST_ROOT, os.path.pardir))
PROJECT_ROOT = os.path.abspath(os.path.join(TEST_ROOT, os.path.pardir))


S2NC = os.path.join(PROJECT_ROOT, "bin", "s2nc")
S2ND = os.path.join(PROJECT_ROOT, "bin", "s2nd")


DEFAULT_ENDPOINT = "127.0.0.1"
DEFAULT_PORT = "8888"


CERT_BUNDLE = os.path.join(INTEG_TEST_ROOT, "trust-store", "ca-bundle.crt")


TEST_CERT_DIRECTORY = os.path.join(TEST_ROOT, "pems")
TEST_ECDSA_CERT = os.path.join(TEST_CERT_DIRECTORY, "ecdsa_p384_pkcs1_cert.pem")
TEST_ECDSA_KEY = os.path.join(TEST_CERT_DIRECTORY, "ecdsa_p384_pkcs1_key.pem")