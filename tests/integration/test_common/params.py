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
import itertools
from pytest import param
from .common import Mode, Version
from .ciphers import Ciphers


ALL_CORKED_IO = (param(True, id="corked_io"), param(False, id="no corked_io"))

ALL_MODES = ( Mode.client, Mode.server )

ALL_VERSIONS = tuple(Version.all())

ALL_CURVES = ( "P-256", "P-384" )

SUPPORTED_CIPHERS = tuple(Ciphers.all_supported())


def __combine_params(params1, params2, include_check=None, id_separator=" "):
    params_result = [ ]
    for (param1, param2) in itertools.product(params1, params2):
        (v1, m1, i1) = __read_param(param1)
        (v2, m2, i2) = __read_param(param2)

        if include_check and not include_check(v1, v2):
            continue
        params_result.append(param(v1, v2, marks=m1+m2, id=i1+id_separator+i2))

    return tuple(params_result)

def __read_param(param):
    try:
        return (param.values, param.marks, param.id)
    except AttributeError:
        return (param, (), str(param))


def cipher_params(versions):
    return __combine_params(versions, SUPPORTED_CIPHERS, include_check=lambda v,c: c.valid_for(v))

VALID_VERSIONS_AND_CIPHERS = cipher_params(ALL_VERSIONS)


