// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::error::Error;
use crate::config;
use crate::error::Fallible;

#[cfg(feature = "quic")]
impl config::Builder {
    pub fn enable_quic(&mut self) -> Result<&mut Self, Error> {
        unsafe { s2n_tls_sys::s2n_config_enable_quic(self.as_mut_ptr()).into_result() }?;
        Ok(self)
    }
}