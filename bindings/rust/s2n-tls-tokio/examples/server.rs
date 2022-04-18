// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use s2n_tls::raw::{config::Config, error::Error, security::DEFAULT_TLS13};
use s2n_tls_tokio::TlsAcceptor;
use std::fs;
use tokio::net::TcpListener;

const DEFAULT_CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/certs/cert.pem");
const DEFAULT_KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/certs/key.pem");

#[derive(Parser, Debug)]
struct Args {
    #[clap(requires = "key", default_value_t = String::from(DEFAULT_CERT))]
    cert: String,
    #[clap(requires = "cert", default_value_t = String::from(DEFAULT_KEY))]
    key: String,
    #[clap(default_value_t = String::from("127.0.0.1:0"))]
    addr: String,
}

async fn run_server(cert_pem: &[u8], key_pem: &[u8], addr: &String) -> Result<(), Error> {
    let mut config = Config::builder();
    config.set_security_policy(&DEFAULT_TLS13)?;
    config.load_pem(&cert_pem, &key_pem)?;
    let server = TlsAcceptor::new(config.build()?);

    let listener = TcpListener::bind(&addr).await.expect("Failed to bind listener");
    println!("Listening on {:?}", listener.local_addr().unwrap_or("UNKNOWN"));
    loop {
        let (stream, peer_addr) = listener.accept().await.expect("Failed to accept connection");
        println!("Connection from {:?}", peer_addr);
        server.accept(stream).await?;
        // TODO: echo
    }
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let args = Args::parse();
    let cert_pem = fs::read(args.cert).expect("Failed to load cert");
    let key_pem = fs::read(args.key).expect("Failed to load key");
    run_server(&cert_pem, &key_pem, &args.addr).await.map_err(|e| e.to_string())?;
    Ok(())
}
