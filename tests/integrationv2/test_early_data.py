import copy
import os
import pytest
import time
from enum import Enum
from collections import namedtuple

from configuration import available_ports, ALL_TEST_CIPHERS, ALL_TEST_CURVES, ALL_TEST_CERTS, PROTOCOLS, TLS13_CIPHERS
from common import ProviderOptions, Protocols, Curves, data_bytes
from fixtures import managed_process
from providers import Provider, S2N as S2NBase, OpenSSL as OpenSSLBase
from utils import invalid_test_parameters, get_parameter_name, to_bytes


TICKET_FILE = 'ticket'
EARLY_DATA_FILE = 'early_data'

MAX_EARLY_DATA = 20 # Arbitrary large number

NUM_RESUMES = 5 # Hardcoded for s2nc --reconnect
NUM_CONNECTIONS = NUM_RESUMES + 1 # resumes + initial

S2N_DEFAULT_CURVE = Curves.X25519
S2N_UNSUPPORTED_CURVE = 'X448' # We have no plans to support this curve any time soon
S2N_HRR_CURVES = list(curve for curve in ALL_TEST_CURVES if curve != S2N_DEFAULT_CURVE)

S2N_CURVE_MARKER = "Curve: {curve}"
S2N_EARLY_DATA_RECV_MARKER = "Early Data received: "
S2N_EARLY_DATA_STATUS_MARKER = "Early Data status: {status}"
S2N_EARLY_DATA_ACCEPTED_MARKER = S2N_EARLY_DATA_STATUS_MARKER.format(status="ACCEPTED")
S2N_EARLY_DATA_REJECTED_MARKER = S2N_EARLY_DATA_STATUS_MARKER.format(status="REJECTED")


class S2N(S2NBase):
    def __init__(self, options: ProviderOptions):
        S2NBase.__init__(self, options)

    def setup_client(self):
        cmd_line = S2NBase.setup_client(self)
        early_data_file = self.options.early_data_file
        if early_data_file and os.path.exists(early_data_file):
            cmd_line.extend(['--early-data', early_data_file])
        return cmd_line

    def setup_server(self):
        cmd_line = S2NBase.setup_server(self)
        cmd_line.extend(['--max-early-data', self.options.max_early_data])
        return cmd_line


class OpenSSL(OpenSSLBase):
    def __init__(self, options: ProviderOptions):
        OpenSSLBase.__init__(self, options)

    def setup_client(self):
        cmd_line = OpenSSLBase.setup_client(self)
        early_data_file = self.options.early_data_file
        if early_data_file and os.path.exists(early_data_file):
            cmd_line.extend(['-early_data', early_data_file])
        ticket_file = self.options.ticket_file
        if ticket_file:
            if os.path.exists(ticket_file):
                cmd_line.extend(['-sess_in', ticket_file])
            else:
                cmd_line.extend(['-sess_out', self.options.ticket_file])
        return cmd_line

    def setup_server(self):
        cmd_line = OpenSSLBase.setup_server(self)
        cmd_line.extend(['-early_data'])
        return cmd_line


def get_early_data_bytes(file_path, early_data_size):
    early_data = data_bytes(early_data_size)
    with open(file_path, 'wb') as fout:
        fout.write(early_data)
    return early_data


def get_ticket_from_s2n_server(options, managed_process, provider, certificate):
    port = next(available_ports)
    print(str(port))

    """
    Some clients start checking for stdin EoF to exit as soon as they finish the handshake.
    To make sure the client reliably receives the post-handshake NST,
    do NOT indicate stdin EoF until after some data has been received from the server.
    """
    close_marker_bytes = data_bytes(10)

    client_options = copy.copy(options)
    client_options.mode = Provider.ClientMode
    client_options.port = port

    server_options = copy.copy(options)
    server_options.mode = Provider.ServerMode
    server_options.port = port
    server_options.key = certificate.key
    server_options.cert = certificate.cert
    server_options.data_to_send = close_marker_bytes

    assert not os.path.exists(options.ticket_file)

    s2n_server = managed_process(S2N, server_options)
    client = managed_process(provider, client_options, close_marker=str(close_marker_bytes))

    for results in s2n_server.get_results():
        assert results.exception is None
        assert results.exit_code == 0

    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0

    assert os.path.exists(options.ticket_file)


"""
Basic S2N server happy case.

We make one full connection to get a session ticket with early data enabled,
then another resumption connection with early data.
"""
@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
@pytest.mark.parametrize("early_data_size", [int(MAX_EARLY_DATA/2), int(MAX_EARLY_DATA-1), MAX_EARLY_DATA, 1])
def test_s2n_server_with_early_data(managed_process, tmp_path, cipher, curve, protocol, provider, certificate, early_data_size):
    ticket_file = str(tmp_path / TICKET_FILE)
    early_data_file = str(tmp_path / EARLY_DATA_FILE)
    early_data = get_early_data_bytes(early_data_file, early_data_size)

    options = ProviderOptions(
        port=next(available_ports),
        cipher=cipher,
        curve=curve,
        protocol=protocol,
        insecure=True,
        use_session_ticket=True,
    )
    options.ticket_file = ticket_file
    options.early_data_file = early_data_file
    options.max_early_data = MAX_EARLY_DATA

    get_ticket_from_s2n_server(options, managed_process, provider, certificate)

    client_options = copy.copy(options)
    client_options.mode = Provider.ClientMode

    server_options = copy.copy(options)
    server_options.mode = Provider.ServerMode

    s2n_server = managed_process(S2N, server_options)
    client = managed_process(provider, client_options)

    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0

    for results in s2n_server.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert (to_bytes(S2N_EARLY_DATA_RECV_MARKER) + early_data) in results.stdout
        assert to_bytes(S2N_EARLY_DATA_ACCEPTED_MARKER) in results.stdout


"""
Basic S2N client happy case.

The S2N client tests session resumption by repeatedly reconnecting.
That means we don't need to manually perform the initial full connection, and there is no external ticket file.

This test can't be parameterized by curve. The S2N client only sends one key share, so if the server refuses
to accept that key share then we perform a hello retry, which automatically rejects early data.
"""
@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL, S2N], ids=get_parameter_name)
@pytest.mark.parametrize("early_data_size", [int(MAX_EARLY_DATA/2), int(MAX_EARLY_DATA-1), MAX_EARLY_DATA, 1])
def test_s2n_client_with_early_data(managed_process, tmp_path, cipher, protocol, provider, certificate, early_data_size):
    early_data_file = str(tmp_path / EARLY_DATA_FILE)
    early_data = get_early_data_bytes(early_data_file, early_data_size)

    options = ProviderOptions(
        port=next(available_ports),
        cipher=cipher,
        protocol=protocol,
        insecure=True,
        use_session_ticket=True,
        reconnect=True,
    )
    options.ticket_file = None
    options.early_data_file = early_data_file
    options.max_early_data = MAX_EARLY_DATA

    client_options = copy.copy(options)
    client_options.mode = Provider.ClientMode

    server_options = copy.copy(options)
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert
    server_options.reconnects_before_exit = NUM_CONNECTIONS

    server = managed_process(provider, server_options)
    s2n_client = managed_process(S2N, client_options)

    for results in s2n_client.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert results.stdout.count(to_bytes(S2N_EARLY_DATA_ACCEPTED_MARKER)) == NUM_RESUMES

    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert results.stdout.count(early_data) == NUM_RESUMES


"""
Test the S2N server rejecting early data.

We do this by disabling early data on the server after the ticket is issued.
When the client attempts to use the ticket to send early data, the server rejects the attempt.

We can't perform an S2N client version of this test because the S2N client performs its hardcoded
reconnects automatically, without any mechanism to modify the connection in between.
"""
@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
@pytest.mark.parametrize("early_data_size", [int(MAX_EARLY_DATA/2), int(MAX_EARLY_DATA-1), MAX_EARLY_DATA, 1])
def test_s2n_server_with_early_data_rejected(managed_process, tmp_path, cipher, curve, protocol, provider, certificate, early_data_size):
    ticket_file = str(tmp_path / TICKET_FILE)
    early_data_file = str(tmp_path / EARLY_DATA_FILE)
    early_data = get_early_data_bytes(early_data_file, early_data_size)

    options = ProviderOptions(
        port=next(available_ports),
        cipher=cipher,
        curve=curve,
        protocol=protocol,
        insecure=True,
        use_session_ticket=True,
    )
    options.ticket_file = ticket_file
    options.early_data_file = early_data_file
    options.max_early_data = MAX_EARLY_DATA

    get_ticket_from_s2n_server(options, managed_process, provider, certificate)
    options.max_early_data = 0

    client_options = copy.copy(options)
    client_options.mode = Provider.ClientMode

    server_options = copy.copy(options)
    server_options.mode = Provider.ServerMode

    s2n_server = managed_process(S2N, server_options)
    client = managed_process(provider, client_options)

    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0

    for results in s2n_server.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert to_bytes(S2N_EARLY_DATA_RECV_MARKER) not in results.stdout
        assert to_bytes(S2N_EARLY_DATA_REJECTED_MARKER) in results.stdout


"""
Test the S2N client attempting to send early data, but the server triggering a hello retry.

We trigger the HRR by configuring the server to only accept curves that the S2N client
does not send key shares for.
"""
@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", S2N_HRR_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
@pytest.mark.parametrize("early_data_size", [int(MAX_EARLY_DATA/2), int(MAX_EARLY_DATA-1), MAX_EARLY_DATA, 1])
def test_s2n_client_with_early_data_rejected_via_hrr(managed_process, tmp_path, cipher, curve, protocol, provider, certificate, early_data_size):
    early_data_file = str(tmp_path / EARLY_DATA_FILE)
    early_data = get_early_data_bytes(early_data_file, early_data_size)

    options = ProviderOptions(
        port=next(available_ports),
        cipher=cipher,
        curve=curve,
        protocol=protocol,
        insecure=True,
        use_session_ticket=True,
        reconnect=True,
    )
    options.ticket_file = None
    options.early_data_file = early_data_file
    options.max_early_data = MAX_EARLY_DATA

    client_options = copy.copy(options)
    client_options.mode = Provider.ClientMode

    server_options = copy.copy(options)
    server_options.mode = Provider.ServerMode
    server_options.key = certificate.key
    server_options.cert = certificate.cert
    server_options.reconnects_before_exit = NUM_CONNECTIONS

    server = managed_process(provider, server_options)
    s2n_client = managed_process(S2N, client_options)

    for results in s2n_client.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert results.stdout.count(to_bytes(S2N_EARLY_DATA_REJECTED_MARKER)) == NUM_RESUMES

    for results in server.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert early_data not in results.stdout


"""
Test the S2N server rejecting early data because of a hello retry request.

In order to trigger a successful retry, we need to force the peer to offer us a key share that
S2N doesn't support while still supporting at least one curve S2N does support.
"""
@pytest.mark.uncollect_if(func=invalid_test_parameters)
@pytest.mark.parametrize("cipher", TLS13_CIPHERS, ids=get_parameter_name)
@pytest.mark.parametrize("curve", ALL_TEST_CURVES, ids=get_parameter_name)
@pytest.mark.parametrize("certificate", ALL_TEST_CERTS, ids=get_parameter_name)
@pytest.mark.parametrize("protocol", [Protocols.TLS13], ids=get_parameter_name)
@pytest.mark.parametrize("provider", [OpenSSL], ids=get_parameter_name)
@pytest.mark.parametrize("early_data_size", [int(MAX_EARLY_DATA/2), int(MAX_EARLY_DATA-1), MAX_EARLY_DATA, 1])
def test_s2n_server_with_early_data_rejected_via_hrr(managed_process, tmp_path, cipher, curve, protocol, provider, certificate, early_data_size):
    ticket_file = str(tmp_path / TICKET_FILE)
    early_data_file = str(tmp_path / EARLY_DATA_FILE)
    early_data = get_early_data_bytes(early_data_file, early_data_size)

    options = ProviderOptions(
        port=next(available_ports),
        cipher=cipher,
        curve=(S2N_UNSUPPORTED_CURVE + ":" + str(curve)),
        protocol=protocol,
        insecure=True,
        use_session_ticket=True,
    )
    options.ticket_file = ticket_file
    options.early_data_file = early_data_file
    options.max_early_data = MAX_EARLY_DATA

    get_ticket_from_s2n_server(options, managed_process, provider, certificate)

    client_options = copy.copy(options)
    client_options.mode = Provider.ClientMode

    server_options = copy.copy(options)
    server_options.mode = Provider.ServerMode

    s2n_server = managed_process(S2N, server_options)
    client = managed_process(provider, client_options)

    for results in client.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert early_data not in results.stdout

    for results in s2n_server.get_results():
        assert results.exception is None
        assert results.exit_code == 0
        assert to_bytes(S2N_EARLY_DATA_RECV_MARKER) not in results.stdout
        assert to_bytes(S2N_EARLY_DATA_REJECTED_MARKER) in results.stdout
