// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use foreign_types::ForeignTypeRef;
use openssl::ssl::{Ssl, SslContext, SslFiletype, SslMethod, SslVersion};
use s2n_tls::{config, renegotiate::RenegotiateResponse, security::DEFAULT_TLS13};
use s2n_tls_tokio::TlsConnector;
use std::{
    future::Future,
    pin::Pin,
    task::{
        Context,
        Poll::{self, Ready},
    },
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
};
use tokio_openssl::SslStream;

// Currently renegotiation is not available from the openssl-sys bindings
extern "C" {
    fn SSL_renegotiate(s: *mut openssl_sys::SSL) -> libc::size_t;
}

pub async fn get_streams() -> Result<(TcpStream, TcpStream), tokio::io::Error> {
    let localhost = "127.0.0.1".to_owned();
    let listener = TcpListener::bind(format!("{}:0", localhost)).await?;
    let addr = listener.local_addr()?;
    let client_stream = TcpStream::connect(&addr).await?;
    let (server_stream, _) = listener.accept().await?;
    Ok((server_stream, client_stream))
}

pub fn client_config() -> Result<config::Builder, s2n_tls::error::Error> {
    let mut builder = config::Config::builder();
    builder.set_renegotiate_callback(RenegotiateResponse::Accept)?;
    builder.set_security_policy(&DEFAULT_TLS13)?;
    builder.trust_pem(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/certs/cert.pem"
    )))?;
    Ok(builder)
}

fn build_openssl() -> Result<Ssl, Box<dyn std::error::Error>> {
    let mut ctx_builder = SslContext::builder(SslMethod::tls_server())?;
    ctx_builder.set_max_proto_version(Some(SslVersion::TLS1_2))?;
    ctx_builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    ctx_builder.set_certificate_chain_file(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/certs/cert.pem"
    ))?;
    ctx_builder.set_private_key_file(
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/certs/key.pem"),
        SslFiletype::PEM,
    )?;
    let openssl_ctx = ctx_builder.build();
    Ok(Ssl::new(&openssl_ctx)?)
}

// A future that tracks progress towards receiving a ClientHello.
//
// The openssl tokio bindings do not implement renegotiation.
// The biggest issue is that there is no mechanism to read until
// a new ClientHello is sent, rather than read until ApplicationData is sent.
//
// We work around this limitiation by polling read until the client_random
// value changes, which indicates a new ClientHello was received.
struct AwaitClientHello<'a> {
    stream: &'a mut SslStream<TcpStream>,
    client_random: [u8; 32],
}

impl<'a> AwaitClientHello<'a> {
    fn new(stream: &'a mut SslStream<TcpStream>) -> Self {
        let mut result = Self {
            stream,
            client_random: [0; 32],
        };
        result.stream.ssl().client_random(&mut result.client_random);
        result
    }
}

impl Future for AwaitClientHello<'_> {
    type Output = std::io::Result<()>;
    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut_self = self.get_mut();

        // If the random value changes, that indicates that a new ClientHello
        // with a new random value was read.
        let mut client_random = [0; 32];
        mut_self.stream.ssl().client_random(&mut client_random);
        if mut_self.client_random != client_random {
            return Ready(Ok(()));
        }

        let mut buf = ReadBuf::new(&mut [0; 0]);
        match Pin::new(&mut mut_self.stream).poll_read(ctx, &mut buf) {
            Ready(Ok(_)) => panic!("no successful reads expected"),
            result => result,
        }
    }
}

async fn assert_write<T: AsyncWrite + std::marker::Unpin>(
    writer: &mut T,
    data: &[u8],
    message: &str,
) {
    Pin::new(writer).write_all(data).await.expect(message);
}

async fn assert_read<T: AsyncRead + std::marker::Unpin>(
    reader: &mut T,
    data: &[u8],
    message: &str,
) {
    let mut buffer = [0; 100];
    let read = Pin::new(reader).read(&mut buffer).await.expect(message);
    assert_eq!(read, data.len());
    assert_eq!(&buffer[..read], data);
}

async fn assert_renegotiate(openssl: &mut SslStream<TcpStream>) {
    unsafe { SSL_renegotiate(openssl.ssl().as_ptr()) };
    assert_eq!(
        openssl
            .write(&[0; 0])
            .await
            .expect("Writing the HelloRequest"),
        0
    );
    AwaitClientHello::new(openssl)
        .await
        .expect("Waiting for the ClientHello");
    Pin::new(openssl)
        .do_handshake()
        .await
        .expect("Renegotiate handshake");
}

#[tokio::test]
async fn renegotiate_basic() -> Result<(), Box<dyn std::error::Error>> {
    let (server_stream, client_stream) = get_streams().await?;

    let client = TlsConnector::new(client_config()?.build()?);
    let server = build_openssl()?;

    let mut tasks = tokio::task::JoinSet::new();

    let request_data = "request_data".as_bytes();
    let response_data = "response_data".as_bytes();

    tasks.spawn(async move {
        let mut client = client
            .connect("localhost", client_stream)
            .await
            .expect("Connect");
        assert_write(
            &mut client,
            request_data,
            "Client sends request before renegotiate",
        )
        .await;
        assert_read(
            &mut client,
            response_data,
            "Client reads response after renegotiate",
        )
        .await;
    });

    tasks.spawn(async move {
        let mut server = SslStream::new(server, server_stream).expect("New openssl stream");
        Pin::new(&mut server).accept().await.expect("Accept");

        assert_read(&mut server, request_data, "Server reads request").await;
        assert_renegotiate(&mut server).await;
        assert_write(&mut server, response_data, "Server sends response").await;
    });

    // Both the client and server should succeed
    while let Some(res) = tasks.join_next().await {
        res.unwrap();
    }
    Ok(())
}

#[tokio::test]
async fn renegotiate_repeatedly() -> Result<(), Box<dyn std::error::Error>> {
    let (server_stream, client_stream) = get_streams().await?;

    let client = TlsConnector::new(client_config()?.build()?);
    let server = build_openssl()?;

    let mut tasks = tokio::task::JoinSet::new();

    let request_data = "request_data".as_bytes();
    let response_data = "response_data".as_bytes();
    let count = 10;

    tasks.spawn(async move {
        let mut client = client
            .connect("localhost", client_stream)
            .await
            .expect("Connect");

        for _ in 0..count {
            assert_write(
                &mut client,
                request_data,
                "Client sends request before renegotiate",
            )
            .await;
            assert_read(
                &mut client,
                response_data,
                "Client reads response after renegotiate",
            )
            .await;
        }
    });

    tasks.spawn(async move {
        let mut server = SslStream::new(server, server_stream).expect("New openssl stream");
        Pin::new(&mut server).accept().await.expect("Accept");

        for _ in 0..count {
            assert_read(&mut server, request_data, "Server reads request").await;
            assert_renegotiate(&mut server).await;
            assert_write(&mut server, response_data, "Server sends response").await;
        }
    });

    // Both the client and server should succeed
    while let Some(res) = tasks.join_next().await {
        res.unwrap();
    }
    Ok(())
}

#[tokio::test]
async fn renegotiate_with_app_data() -> Result<(), Box<dyn std::error::Error>> {
    let (server_stream, client_stream) = get_streams().await?;

    let client = TlsConnector::new(client_config()?.build()?);
    let server = build_openssl()?;

    let mut tasks = tokio::task::JoinSet::new();

    let count = 9;
    assert!(count % 3 == 0);

    tasks.spawn(async move {
        let mut client = client
            .connect("localhost", client_stream)
            .await
            .expect("Connect");
        for i in 0..count {
            let data = format!("message {}", i % 3).into_bytes();
            assert_read(&mut client, &data, &format!("Client reads message {}", i)).await;
        }
    });

    tasks.spawn(async move {
        let mut server = SslStream::new(server, server_stream).expect("New openssl stream");
        Pin::new(&mut server).accept().await.expect("Accept");

        for i in 0..(count / 3) {
            let data = format!("message {}", i).into_bytes();
            assert_write(
                &mut server,
                &data,
                &format!("Server writes message {} before HelloRequest", i),
            )
            .await;
        }
        unsafe { SSL_renegotiate(server.ssl().as_ptr()) };
        for i in 0..(count / 3) {
            let data = format!("message {}", i).into_bytes();
            assert_write(
                &mut server,
                &data,
                &format!("Server writes message {} after HelloRequest", i),
            )
            .await;
        }
        // This also sends a second HelloRequest message, but that should never
        // be an issue. The client is supposed to ignore duplicate requests.
        assert_renegotiate(&mut server).await;
        for i in 0..(count / 3) {
            let data = format!("message {}", i).into_bytes();
            assert_write(
                &mut server,
                &data,
                &format!("Server writes message {} after renegotiate", i),
            )
            .await;
        }
    });

    // Both the client and server should succeed
    while let Some(res) = tasks.join_next().await {
        res.unwrap();
    }
    Ok(())
}
