import copy
import os
import pytest
import time

from configuration import available_ports, TLS13_CIPHERS, ALL_TEST_CURVES, ALL_TEST_CERTS, ALL_TEST_CIPHERS, PROTOCOLS
from common import ProviderOptions, Protocols, data_bytes
from fixtures import managed_process
from providers import Provider, S2N, OpenSSL
from utils import invalid_test_parameters, get_parameter_name, get_expected_s2n_version, get_expected_openssl_version


@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
def test_session_resumption_s2n_server(managed_process, cipher, curve, protocol, provider, certificate):
    host = "localhost"
    port = next(available_ports)
    
    ticket_filename = 'session_ticket_' + str(port)

    client_options = ProviderOptions(
        mode=Provider.ClientMode,
        host="localhost",
        port=port,
        cipher=cipher,
        curve=curve,
        insecure=True,
        reconnect=False,
        extra_flags = ['-sess_out', ticket_filename],
        protocol=protocol)
    
    server_options = copy.copy(client_options)
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert
    server_options.use_session_ticket = True
    server_options.extra_flags = None

    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(provider, client_options, timeout=5)

    # Client inputs stored session ticket to resume a session
    client_options.extra_flags = ['-sess_in', ticket_filename]
    client_options.data_to_send = random_bytes

    port = next(available_ports)
    client_options.port = port
    server_options.port = port

    server = managed_process(S2N, server_options, timeout=5)
    client = managed_process(provider, client_options, timeout=5)

    openssl_version = get_expected_openssl_version(protocol)
    s2n_version = get_expected_s2n_version(protocol, OpenSSL)

    # The client should have received a session ticket
    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert b'Post-Handshake New Session Ticket arrived:' in results.stdout
        assert bytes("Protocol  : {}".format(openssl_version).encode('utf-8')) in results.stdout

    # The server should indicate a session has been resumed
    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert b'Resumed session' in results.stdout
        assert bytes("Actual protocol version: {}".format(s2n_version).encode('utf-8')) in results.stdout
