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

from .common import Version, Libcrypto


class Cipher():
    def __init__(self, name, min_version, fips_compatible):
        self.name = name
        self.min_version = min_version
        self.fips_compatible = fips_compatible

    def valid_for(self, version):
        # Connections can't user ciphers that require a higher version
        if version < self.min_version:
            return False

        # TLS1.3 connections can't use pre-TLS1.3 ciphers
        if version >= Version.TLS13:
            return self.min_version >= Version.TLS13

        return True

    def __repr__(self):
        return "<Cipher: %s>" % self.name

    def __str__(self):
        return self.name


class Ciphers(list):

    @classmethod
    def all(cls):
        return Ciphers(ALL_TEST_CIPHERS)

    @classmethod
    def all_supported(cls, libcrypto=Libcrypto.supported()):
        return S2N_LIBCRYPTO_TO_TEST_CIPHERS[libcrypto]

    def filter(self, filter_func):
        return list(filter(filter_func, self))

    def select(self, name, exact=True):
        if exact:
            return self.filter(lambda x: x.name == name)
        else:
            return self.filter(lambda x: name in x.name)

    def reject(self, name, exact=True):
        if exact:
            return self.filter(lambda x: x.name != name)
        else:
            return self.filter(lambda x: name not in x.name)

    def fips_compatible(self):
        return self.filter(lambda x: x.fips_compatible == True)
        

ALL_TEST_CIPHERS = [
    Cipher("RC4-MD5", Version.SSLv3, False),
    Cipher("RC4-SHA", Version.SSLv3, False),
    Cipher("DES-CBC3-SHA", Version.SSLv3, True),
    Cipher("DHE-RSA-DES-CBC3-SHA", Version.SSLv3, False),
    Cipher("AES128-SHA", Version.SSLv3, True),
    Cipher("DHE-RSA-AES128-SHA", Version.SSLv3, False),
    Cipher("AES256-SHA", Version.SSLv3, True),
    Cipher("DHE-RSA-AES256-SHA", Version.SSLv3, False),
    Cipher("AES128-SHA256", Version.TLS12, True),
    Cipher("AES256-SHA256", Version.TLS12, True),
    Cipher("DHE-RSA-AES128-SHA256", Version.TLS12, True),
    Cipher("DHE-RSA-AES256-SHA256", Version.TLS12, True),
    Cipher("AES128-GCM-SHA256", Version.TLS12, True),
    Cipher("AES256-GCM-SHA384", Version.TLS12, True),
    Cipher("DHE-RSA-AES128-GCM-SHA256", Version.TLS12, True),
    Cipher("DHE-RSA-AES256-GCM-SHA384", Version.TLS12, True),
    Cipher("ECDHE-ECDSA-AES128-SHA", Version.SSLv3, False),
    Cipher("ECDHE-ECDSA-AES256-SHA", Version.SSLv3, False),
    Cipher("ECDHE-ECDSA-AES128-SHA256", Version.TLS12, True),
    Cipher("ECDHE-ECDSA-AES256-SHA384", Version.TLS12, True),
    Cipher("ECDHE-ECDSA-AES128-GCM-SHA256", Version.TLS12, True),
    Cipher("ECDHE-ECDSA-AES256-GCM-SHA384", Version.TLS12, True),
    Cipher("ECDHE-RSA-DES-CBC3-SHA", Version.SSLv3, False),
    Cipher("ECDHE-RSA-AES128-SHA", Version.SSLv3, False),
    Cipher("ECDHE-RSA-AES256-SHA", Version.SSLv3, False),
    Cipher("ECDHE-RSA-RC4-SHA", Version.SSLv3, False),
    Cipher("ECDHE-RSA-AES128-SHA256", Version.TLS12, True),
    Cipher("ECDHE-RSA-AES256-SHA384", Version.TLS12, True),
    Cipher("ECDHE-RSA-AES128-GCM-SHA256", Version.TLS12, True),
    Cipher("ECDHE-RSA-AES256-GCM-SHA384", Version.TLS12, True),
    Cipher("ECDHE-RSA-CHACHA20-POLY1305", Version.TLS12, False),
    Cipher("ECDHE-ECDSA-CHACHA20-POLY1305", Version.TLS12, False),
    Cipher("DHE-RSA-CHACHA20-POLY1305", Version.TLS12, False),
    Cipher("TLS_AES_256_GCM_SHA384", Version.TLS13, False),
    Cipher("TLS_CHACHA20_POLY1305_SHA256", Version.TLS13, False),
    Cipher("TLS_AES_128_GCM_SHA256", Version.TLS13, False)
]


S2N_LIBCRYPTO_TO_TEST_CIPHERS = {
    Libcrypto.openssl_111         : Ciphers.all(),
    Libcrypto.openssl_102         : Ciphers.all().reject("CHACHA20", exact=False),
    Libcrypto.openssl_102_fips    : Ciphers.all().fips_compatible(),
    Libcrypto.libressl            : Ciphers.all().reject("CHACHA20", exact=False),
}

