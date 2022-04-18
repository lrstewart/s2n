// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use s2n_tls::raw::{config::Config, security::DEFAULT_TLS13};
use s2n_tls_tokio::{TlsAcceptor, TlsConnector};
use tokio::net::{TcpListener, TcpStream};

const default_cert = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/certs/cert.pem");

#[derive(Parser, Debug)]
struct Args {
    trust: Option<String>,
    addr: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let args = Args::parse();
    let cert_pem = include_bytes!(
        args.trust.unwrap_or(default_cert)
    );
    let addr = args.addr.unwrap_or("127.0.0.1:4433");

    let mut config = Config::builder();
    config.set_security_policy(&DEFAULT_TLS13)?;
    config.trust_pem(&cert_pem)?;
    let client = TlsConnector::new(config.build()?);

    let stream = TcpStream::connect(&addr).await?
    client.connect("localhost", stream).await?;

    // TODO: echo

    Ok(())
}
