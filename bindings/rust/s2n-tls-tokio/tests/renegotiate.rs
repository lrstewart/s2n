// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

#[test]
fn renegotiate_all() -> Result<(), Box<dyn std::error::Error>> {
    let success = Command::new("cargo")
        .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/renegotiate"))
        .arg("test")
        .status()?
        .success();
    assert!(success, "Cargo test status");
    Ok(())
}
