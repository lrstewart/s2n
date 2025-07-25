// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
mod io;
pub use io::{LocalDataBuffer, TestPairIO, ViewIO};

use std::{error::Error, fmt::Debug, fs::read_to_string};
use strum::EnumIter;

#[derive(Clone, Copy, EnumIter)]
pub enum PemType {
    ServerKey,
    ServerCertChain,
    ClientKey,
    ClientCertChain,
    CACert,
}

impl PemType {
    fn get_filename(&self) -> &str {
        match self {
            PemType::ServerKey => "server-key.pem",
            PemType::ServerCertChain => "server-chain.pem",
            PemType::ClientKey => "client-key.pem",
            PemType::ClientCertChain => "client-cert.pem",
            PemType::CACert => "ca-cert.pem",
        }
    }
}

#[derive(Clone, Copy, Default, EnumIter)]
pub enum SigType {
    #[default]
    Rsa2048,
    Rsa3072,
    Rsa4096,
    Ecdsa384,
    Ecdsa256,
}

impl SigType {
    pub fn get_dir_name(&self) -> &str {
        match self {
            SigType::Rsa2048 => "rsa2048",
            SigType::Rsa3072 => "rsa3072",
            SigType::Rsa4096 => "rsa4096",
            SigType::Ecdsa384 => "ecdsa384",
            SigType::Ecdsa256 => "ecdsa256",
        }
    }
}

impl Debug for SigType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.get_dir_name())
    }
}

pub fn get_cert_path(pem_type: PemType, sig_type: SigType) -> String {
    format!(
        "certs/{}/{}",
        sig_type.get_dir_name(),
        pem_type.get_filename()
    )
}

pub fn read_to_bytes(pem_type: PemType, sig_type: SigType) -> Vec<u8> {
    read_to_string(get_cert_path(pem_type, sig_type))
        .unwrap()
        .into_bytes()
}

#[derive(Clone, Copy)]
pub enum Mode {
    Client,
    Server,
}

/// While ServerAuth and Resumption are not mutually exclusive, they are treated
/// as such for the purpose of benchmarking.
#[derive(Clone, Copy, Default, EnumIter, Eq, PartialEq)]
pub enum HandshakeType {
    #[default]
    ServerAuth,
    MutualAuth,
    Resumption,
}

impl Debug for HandshakeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeType::ServerAuth => write!(f, "server-auth"),
            HandshakeType::MutualAuth => write!(f, "mTLS"),
            HandshakeType::Resumption => write!(f, "resumption"),
        }
    }
}

// these parameters were the only ones readily usable for all three libaries:
// s2n-tls, rustls, and openssl
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Default, EnumIter, Eq, PartialEq)]
pub enum CipherSuite {
    #[default]
    AES_128_GCM_SHA256,
    AES_256_GCM_SHA384,
}

#[derive(Clone, Copy, Default, EnumIter)]
pub enum KXGroup {
    Secp256R1,
    #[default]
    X25519,
}

impl Debug for KXGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Secp256R1 => write!(f, "secp256r1"),
            Self::X25519 => write!(f, "x25519"),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CryptoConfig {
    pub cipher_suite: CipherSuite,
    pub kx_group: KXGroup,
    pub sig_type: SigType,
}

impl CryptoConfig {
    pub fn new(cipher_suite: CipherSuite, kx_group: KXGroup, sig_type: SigType) -> Self {
        Self {
            cipher_suite,
            kx_group,
            sig_type,
        }
    }
}

/// The TlsBenchConfig trait allows us to map benchmarking parameters to
/// a configuration object
pub trait TlsBenchConfig: Sized {
    fn make_config(
        mode: Mode,
        crypto_config: CryptoConfig,
        handshake_type: HandshakeType,
    ) -> Result<Self, Box<dyn Error>>;
}

/// The TlsConnection object can be created from a corresponding config type.
pub trait TlsConnection: Sized {
    /// Library-specific config struct
    type Config;

    /// Make connection from existing config and buffer
    fn new_from_config(
        mode: Mode,
        config: &Self::Config,
        io: &TestPairIO,
    ) -> Result<Self, Box<dyn Error>>;

    /// Run one handshake step: receive msgs from other connection, process, and send new msgs
    fn handshake(&mut self) -> Result<(), Box<dyn Error>>;

    fn handshake_completed(&self) -> bool;

    /// Send `data` to the peer.
    ///
    /// Send is infailable because it communicates over local memory.
    fn send(&mut self, data: &[u8]);

    /// Read application data from the peer into `data`.
    fn recv(&mut self, data: &mut [u8]) -> std::io::Result<()>;

    /// Send a `CloseNotify` to the peer.
    ///
    /// This does not read the `CloseNotify` from the peer.
    ///
    /// Must be followed by a call to [`TlsConnection::shutdown_finish`] to ensure
    /// that any `CloseNotify` alerts from the peer are read.
    fn shutdown_send(&mut self);

    /// Attempt to read the `CloseNotify` from the peer.
    ///
    /// Returns `true` if the connection was successfully shutdown, `false` otherwise.
    ///
    /// The `CloseNotify` might already have been read by `shutdown_send`, depending
    /// on the order of client/server [`TlsConnection::shutdown_send`] calls.
    fn shutdown_finish(&mut self) -> bool;
}

pub trait TlsInfo: Sized {
    fn name() -> String;
    fn get_negotiated_cipher_suite(&self) -> CipherSuite;

    fn negotiated_tls13(&self) -> bool;

    /// Describes whether a connection was resumed.
    fn resumed_connection(&self) -> bool;

    /// For the rustls & openssl implementations, this only works for servers.
    fn mutual_auth(&self) -> bool;
}

/// A TlsConnPair owns the client and server tls connections along with the IO buffers.
pub struct TlsConnPair<C, S> {
    pub client: C,
    pub server: S,
    pub io: TestPairIO,
}

impl<C, S> Default for TlsConnPair<C, S>
where
    C: TlsConnection,
    S: TlsConnection,
    C::Config: TlsBenchConfig,
    S::Config: TlsBenchConfig,
{
    fn default() -> Self {
        Self::new_bench_pair(CryptoConfig::default(), HandshakeType::default()).unwrap()
    }
}

impl<C, S> TlsConnPair<C, S>
where
    C: TlsConnection,
    S: TlsConnection,
    C::Config: TlsBenchConfig,
    S::Config: TlsBenchConfig,
{
    /// Initialize buffers, configs, and connections (pre-handshake)
    pub fn new_bench_pair(
        crypto_config: CryptoConfig,
        handshake_type: HandshakeType,
    ) -> Result<Self, Box<dyn Error>> {
        // do an initial handshake to generate the session ticket
        if handshake_type == HandshakeType::Resumption {
            let server_config =
                S::Config::make_config(Mode::Server, crypto_config, handshake_type)?;
            let client_config =
                C::Config::make_config(Mode::Client, crypto_config, handshake_type)?;

            // handshake the client and server connections. This will result in
            // session ticket getting stored in client_config
            let mut pair = TlsConnPair::<C, S>::from_configs(&client_config, &server_config);
            pair.handshake()?;
            // NewSessionTicket messages are part of the application data and sent
            // after the handshake is complete, so we must trigger an additional
            // "read" on the client connection to ensure that the session ticket
            // gets received and stored in the config
            pair.round_trip_transfer(&mut [0]).unwrap();

            // new_from_config is called interally by the TlsConnPair::new
            // method and will check if a session ticket is available and set it
            // on the connection. This results in the session ticket in
            // client_config (from the previous handshake) getting set on the
            // client connection.
            return Ok(TlsConnPair::<C, S>::from_configs(
                &client_config,
                &server_config,
            ));
        }

        Ok(TlsConnPair::<C, S>::from_configs(
            &C::Config::make_config(Mode::Client, crypto_config, handshake_type).unwrap(),
            &S::Config::make_config(Mode::Server, crypto_config, handshake_type).unwrap(),
        ))
    }
}

impl<C, S> TlsConnPair<C, S>
where
    C: TlsConnection,
    S: TlsConnection,
{
    pub fn from_configs(client_config: &C::Config, server_config: &S::Config) -> Self {
        let io = TestPairIO {
            server_tx_stream: Default::default(),
            client_tx_stream: Default::default(),
        };
        let client = C::new_from_config(Mode::Client, client_config, &io).unwrap();
        let server = S::new_from_config(Mode::Server, server_config, &io).unwrap();
        Self { client, server, io }
    }

    pub fn client(&self) -> &C {
        &self.client
    }

    pub fn client_mut(&mut self) -> &mut C {
        &mut self.client
    }

    pub fn server(&self) -> &S {
        &self.server
    }

    pub fn server_mut(&mut self) -> &mut S {
        &mut self.server
    }

    /// Run handshake on connections
    /// Two round trips are needed for the server to receive the Finished message
    /// from the client and be ready to send data
    pub fn handshake(&mut self) -> Result<(), Box<dyn Error>> {
        for _ in 0..2 {
            self.client.handshake()?;
            self.server.handshake()?;
        }
        assert!(self.handshake_completed());
        Ok(())
    }

    /// Checks if handshake is finished for both client and server
    pub fn handshake_completed(&self) -> bool {
        self.client.handshake_completed() && self.server.handshake_completed()
    }

    /// Send data from client to server, and then from server to client
    pub fn round_trip_transfer(&mut self, data: &mut [u8]) -> Result<(), Box<dyn Error>> {
        // send data from client to server
        self.client.send(data);
        self.server.recv(data)?;

        // send data from server to client
        self.server.send(data);
        self.client.recv(data)?;

        Ok(())
    }

    pub fn shutdown(&mut self) -> Result<(), Box<dyn Error>> {
        // These assertions do not _have_ to be true, but you are likely making
        // a mistake if you are hitting it. Generally all data should have been
        // read before attempting to shutdown
        assert_eq!(self.io.client_tx_stream.borrow().len(), 0);
        assert_eq!(self.io.server_tx_stream.borrow().len(), 0);

        self.client.shutdown_send();
        self.server.shutdown_send();

        let client_shutdown = self.client.shutdown_finish();
        let server_shutdown = self.server.shutdown_finish();
        if client_shutdown && server_shutdown {
            Ok(())
        } else {
            Err(
                format!("Shutdown Failed: client - {client_shutdown} server - {server_shutdown}")
                    .into(),
            )
        }
    }
}

impl<C, S> TlsConnPair<C, S>
where
    C: TlsInfo,
    S: TlsInfo,
{
    pub fn get_negotiated_cipher_suite(&self) -> CipherSuite {
        assert!(
            self.client.get_negotiated_cipher_suite() == self.server.get_negotiated_cipher_suite()
        );
        self.client.get_negotiated_cipher_suite()
    }

    pub fn negotiated_tls13(&self) -> bool {
        self.client.negotiated_tls13() && self.server.negotiated_tls13()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OpenSslConnection, RustlsConnection, S2NConnection, TlsConnPair};
    use std::{io::ErrorKind, path::Path};
    use strum::IntoEnumIterator;

    #[test]
    fn test_cert_paths_valid() {
        for pem_type in PemType::iter() {
            for sig_type in SigType::iter() {
                assert!(
                    Path::new(&get_cert_path(pem_type, sig_type)).exists(),
                    "cert not found"
                );
            }
        }
    }

    fn session_resumption<C, S>()
    where
        S: TlsConnection + TlsInfo,
        C: TlsConnection + TlsInfo,
        C::Config: TlsBenchConfig,
        S::Config: TlsBenchConfig,
    {
        println!("testing with client:{} server:{}", C::name(), S::name());
        let mut conn_pair =
            TlsConnPair::<C, S>::new_bench_pair(CryptoConfig::default(), HandshakeType::Resumption)
                .unwrap();
        conn_pair.handshake().unwrap();
        // read the session tickets which were sent
        let err = conn_pair.client_mut().recv(&mut [0]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WouldBlock);

        assert!(conn_pair.server().resumed_connection());
        conn_pair.shutdown().unwrap();
    }

    #[test]
    fn session_resumption_interop() {
        env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .is_test(true)
            .try_init()
            .unwrap();
        session_resumption::<S2NConnection, S2NConnection>();
        session_resumption::<S2NConnection, RustlsConnection>();
        session_resumption::<S2NConnection, OpenSslConnection>();

        session_resumption::<RustlsConnection, RustlsConnection>();
        session_resumption::<RustlsConnection, S2NConnection>();
        session_resumption::<RustlsConnection, OpenSslConnection>();

        session_resumption::<OpenSslConnection, OpenSslConnection>();
        session_resumption::<OpenSslConnection, S2NConnection>();
        session_resumption::<OpenSslConnection, RustlsConnection>();
    }
}
