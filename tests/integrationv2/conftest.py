# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from global_flags import set_flag, S2N_PROVIDER_VERSION, S2N_FIPS_MODE


def pytest_addoption(parser):
    parser.addoption("--provider-version", action="store", dest="provider-version",
                     default=None, type=str, help="Set the version of the TLS provider")
    parser.addoption("--fips-mode", action="store", dest="fips-mode",
                     default=False, type=int, help="S2N is running in FIPS mode")


def pytest_configure(config):
    """
    pytest hook that adds the function to deselect tests if the parameters
    don't makes sense.
    """
    config.addinivalue_line(
        "markers", "uncollect_if(*, func): function to unselect tests from parametrization"
    )

    fips_mode = config.getoption('fips-mode', 0)
    if fips_mode == 1:
        set_flag(S2N_FIPS_MODE, True)

    set_flag(S2N_PROVIDER_VERSION, config.getoption('provider-version', None))


def pytest_collection_modifyitems(config, items):
    """
    pytest hook to modify the test arguments to call the uncollect function.
    """
    removed = []
    kept = []
    for item in items:
        m = item.get_closest_marker('uncollect_if')
        if m:
            func = m.kwargs['func']
            if func(**item.callspec.params):
                removed.append(item)
                continue
        kept.append(item)
    if removed:
        config.hook.pytest_deselected(items=removed)
        items[:] = kept
