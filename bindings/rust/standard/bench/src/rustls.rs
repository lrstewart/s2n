// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    harness::{
        self, read_to_bytes, CipherSuite, CryptoConfig, HandshakeType, KXGroup, Mode,
        TlsBenchConfig, TlsConnection, TlsInfo, ViewIO,
    },
    PemType::{self, *},
    SigType,
};
use rustls::{
    crypto::{
        aws_lc_rs::{
            self,
            cipher_suite::{TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384},
            kx_group::{SECP256R1, X25519},
        },
        CryptoProvider,
    },
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    server::{ProducesTickets, WebPkiClientVerifier},
    version::TLS13,
    ClientConfig, ClientConnection, CommonState, Connection, HandshakeKind,
    ProtocolVersion::TLSv1_3,
    RootCertStore, ServerConfig, ServerConnection,
};
use std::{
    error::Error,
    io::{BufReader, Read, Write},
    sync::Arc,
};

pub struct RustlsConnection {
    // the rustls connection has to own the io view, because it is passed as an
    // argument to read/write rather than being part of the connection configuration
    io: ViewIO,
    connection: Connection,
}

impl RustlsConnection {
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Treat `WouldBlock` as an `Ok` value for when blocking is expected
    ///
    /// Blocking is expected during the initial negotiation. Calls to "read_tls"
    /// will eventually block, because the peer hasn't actually responded to the
    /// written messages.
    ///
    /// Blocking is expected during the reading of application data, because rustls
    /// will return a WouldBlock error when the record is too large to fit into
    /// its internal buffer. Following this error Rustls will increase the size
    /// of the buffer, so that the read call eventually succeeds.
    /// https://github.com/rustls/rustls/blob/87f37dd44e32b2771fa471a5d8111749ca9e7aa7/rustls/src/msgs/deframer/buffers.rs#L220
    fn ignore_block<T: Default>(res: Result<T, std::io::Error>) -> Result<T, std::io::Error> {
        match res {
            Ok(t) => Ok(t),
            Err(err) => match err.kind() {
                std::io::ErrorKind::WouldBlock => Ok(T::default()),
                _ => Err(err),
            },
        }
    }

    fn connection_common(&self) -> &CommonState {
        match &self.connection {
            Connection::Client(client_connection) => client_connection,
            Connection::Server(server_connection) => server_connection,
        }
    }
}

#[derive(Debug)]
struct NoOpTicketer {}

impl ProducesTickets for NoOpTicketer {
    fn enabled(&self) -> bool {
        false
    }

    fn lifetime(&self) -> u32 {
        panic!("session resumption is disabled");
    }

    fn encrypt(&self, _plain: &[u8]) -> Option<Vec<u8>> {
        panic!("session resumption is disabled");
    }

    fn decrypt(&self, _cipher: &[u8]) -> Option<Vec<u8>> {
        panic!("session resumption is disabled");
    }
}

impl RustlsConfig {
    fn get_root_cert_store(sig_type: SigType) -> RootCertStore {
        let mut root_store = RootCertStore::empty();
        root_store.add_parsable_certificates(
            rustls_pemfile::certs(&mut BufReader::new(&*read_to_bytes(CACert, sig_type)))
                .map(|r| r.unwrap()),
        );
        root_store
    }

    fn get_cert_chain(pem_type: PemType, sig_type: SigType) -> Vec<CertificateDer<'static>> {
        rustls_pemfile::certs(&mut BufReader::new(&*read_to_bytes(pem_type, sig_type)))
            .map(|result| result.unwrap())
            .collect()
    }

    fn get_key(pem_type: PemType, sig_type: SigType) -> PrivateKeyDer<'static> {
        let key =
            rustls_pemfile::read_one(&mut BufReader::new(&*read_to_bytes(pem_type, sig_type)))
                .unwrap();
        if let Some(rustls_pemfile::Item::Pkcs8Key(pkcs_8_key)) = key {
            pkcs_8_key.into()
        } else {
            // https://docs.rs/rustls-pemfile/latest/rustls_pemfile/enum.Item.html
            panic!("unexpected key type: {key:?}");
        }
    }
}

/// Clients and servers have different config types in Rustls, so wrap them in an enum
pub enum RustlsConfig {
    Client(Arc<ClientConfig>),
    Server(Arc<ServerConfig>),
}

impl From<ClientConfig> for RustlsConfig {
    fn from(value: ClientConfig) -> Self {
        RustlsConfig::Client(value.into())
    }
}

impl From<ServerConfig> for RustlsConfig {
    fn from(value: ServerConfig) -> Self {
        RustlsConfig::Server(value.into())
    }
}

impl TlsBenchConfig for RustlsConfig {
    fn make_config(
        mode: Mode,
        crypto_config: CryptoConfig,
        handshake_type: HandshakeType,
    ) -> Result<Self, Box<dyn Error>> {
        let cipher_suite = match crypto_config.cipher_suite {
            CipherSuite::AES_128_GCM_SHA256 => TLS13_AES_128_GCM_SHA256,
            CipherSuite::AES_256_GCM_SHA384 => TLS13_AES_256_GCM_SHA384,
        };

        let kx_group = match crypto_config.kx_group {
            KXGroup::Secp256R1 => &SECP256R1,
            KXGroup::X25519 => &X25519,
        };

        let crypto_provider = Arc::new(CryptoProvider {
            cipher_suites: vec![cipher_suite],
            kx_groups: vec![*kx_group],
            ..aws_lc_rs::default_provider()
        });

        match mode {
            Mode::Client => {
                let builder = ClientConfig::builder_with_provider(crypto_provider)
                    .with_protocol_versions(&[&TLS13])?
                    .with_root_certificates(Self::get_root_cert_store(crypto_config.sig_type));

                let config = match handshake_type {
                    HandshakeType::ServerAuth | HandshakeType::Resumption => {
                        builder.with_no_client_auth()
                    }
                    HandshakeType::MutualAuth => builder.with_client_auth_cert(
                        Self::get_cert_chain(ClientCertChain, crypto_config.sig_type),
                        Self::get_key(ClientKey, crypto_config.sig_type),
                    )?,
                };

                if handshake_type != HandshakeType::Resumption {
                    rustls::client::Resumption::disabled();
                }

                Ok(RustlsConfig::Client(Arc::new(config)))
            }
            Mode::Server => {
                let builder = ServerConfig::builder_with_provider(crypto_provider)
                    .with_protocol_versions(&[&TLS13])?;

                let builder = match handshake_type {
                    HandshakeType::ServerAuth | HandshakeType::Resumption => {
                        builder.with_no_client_auth()
                    }
                    HandshakeType::MutualAuth => {
                        let client_cert_verifier = WebPkiClientVerifier::builder(
                            Self::get_root_cert_store(crypto_config.sig_type).into(),
                        )
                        .build()
                        .unwrap();
                        builder.with_client_cert_verifier(client_cert_verifier)
                    }
                };

                let mut config = builder.with_single_cert(
                    Self::get_cert_chain(ServerCertChain, crypto_config.sig_type),
                    Self::get_key(ServerKey, crypto_config.sig_type),
                )?;

                if handshake_type != HandshakeType::Resumption {
                    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
                    config.ticketer = Arc::new(NoOpTicketer {});
                }

                Ok(RustlsConfig::Server(Arc::new(config)))
            }
        }
    }
}

impl TlsConnection for RustlsConnection {
    type Config = RustlsConfig;

    fn new_from_config(
        mode: harness::Mode,
        config: &Self::Config,
        io: &harness::TestPairIO,
    ) -> Result<Self, Box<dyn Error>> {
        let connection = match config {
            RustlsConfig::Client(config) => Connection::Client(ClientConnection::new(
                config.clone(),
                ServerName::try_from("localhost")?,
            )?),
            RustlsConfig::Server(config) => {
                Connection::Server(ServerConnection::new(config.clone())?)
            }
        };

        let io = match mode {
            Mode::Client => io.client_view(),
            Mode::Server => io.server_view(),
        };

        Ok(Self { io, connection })
    }

    fn handshake(&mut self) -> Result<(), Box<dyn Error>> {
        Self::ignore_block(self.connection.complete_io(&mut self.io))?;
        Ok(())
    }

    fn handshake_completed(&self) -> bool {
        !self.connection.is_handshaking()
    }

    fn send(&mut self, data: &[u8]) {
        let mut write_offset = 0;
        while write_offset < data.len() {
            write_offset += self
                .connection
                .writer()
                .write(&data[write_offset..data.len()])
                .unwrap();
            self.connection.writer().flush().unwrap();
            self.connection.complete_io(&mut self.io).unwrap();
        }
    }

    fn recv(&mut self, data: &mut [u8]) -> std::io::Result<()> {
        let data_len = data.len();
        let mut read_offset = 0;
        while read_offset < data.len() {
            self.connection.complete_io(&mut self.io)?;
            read_offset += Self::ignore_block(
                self.connection
                    .reader()
                    .read(&mut data[read_offset..data_len]),
            )?;
        }
        Ok(())
    }

    fn shutdown_send(&mut self) {
        match &mut self.connection {
            Connection::Client(client_connection) => client_connection.send_close_notify(),
            Connection::Server(server_connection) => server_connection.send_close_notify(),
        }
        self.connection.write_tls(&mut self.io).unwrap();
    }

    fn shutdown_finish(&mut self) -> bool {
        self.connection.read_tls(&mut self.io).unwrap();
        self.connection.process_new_packets().unwrap();

        let res = self.connection.reader().read(&mut [0]);
        matches!(res, Ok(0))
    }
}

impl TlsInfo for RustlsConnection {
    fn name() -> String {
        "rustls".to_string()
    }
    fn get_negotiated_cipher_suite(&self) -> CipherSuite {
        match self.connection.negotiated_cipher_suite().unwrap().suite() {
            rustls::CipherSuite::TLS13_AES_128_GCM_SHA256 => CipherSuite::AES_128_GCM_SHA256,
            rustls::CipherSuite::TLS13_AES_256_GCM_SHA384 => CipherSuite::AES_256_GCM_SHA384,
            _ => panic!("Unknown cipher suite"),
        }
    }

    fn negotiated_tls13(&self) -> bool {
        self.connection
            .protocol_version()
            .expect("Handshake not completed")
            == TLSv1_3
    }

    fn resumed_connection(&self) -> bool {
        self.connection_common().handshake_kind().unwrap() == HandshakeKind::Resumed
    }

    fn mutual_auth(&self) -> bool {
        assert!(matches!(self.connection, Connection::Server(_)));
        //> For servers, this is the certificate chain or the raw public key of
        //> the client, if client authentication was completed.
        //> https://docs.rs/rustls/latest/rustls/struct.CommonState.html#method.peer_certificates
        self.connection_common().peer_certificates().is_some()
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utilities;

    use super::*;

    #[test]
    fn sanity_check() {
        test_utilities::basic_handshake::<RustlsConnection>();
    }

    #[test]
    fn all_handshakes() {
        test_utilities::all_handshakes::<RustlsConnection>();
    }

    #[test]
    fn transfer() {
        test_utilities::transfer::<RustlsConnection>();
    }
}
