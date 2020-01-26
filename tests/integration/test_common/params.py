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

from pytest import param
from .common import Mode
from .ciphers import Ciphers

CORKED_IO_PARAM = (param(True, id="corked_io"), param(False, id="no corked_io"))

MODES_PARAM = ( Mode.client, Mode.server )

CIPHERS_PARAM = tuple(Ciphers.all_supported())