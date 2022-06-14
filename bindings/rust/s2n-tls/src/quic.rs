// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::connection::Connection;
use crate::config;
use crate::error::Error;
use crate::ffi::*;
use libc::c_void;
use crate::error::Fallible;
use std::convert::TryInto;

#[cfg(feature = "quic")]
impl Connection {
    pub fn enable_quic(&mut self) -> Result<&mut Self, Error> {
        unsafe { s2n_connection_enable_quic(self.as_ptr()).into_result() }?;
        Ok(self)
    }

    pub fn set_quic_transport_parameters(&mut self, buffer: &[u8]) -> Result<&mut Self, Error> {
        unsafe {
            s2n_connection_set_quic_transport_parameters(
                self.as_ptr(),
                buffer.as_ptr(),
                buffer.len().try_into().map_err(|_| Error::InvalidInput)?,
            )
            .into_result()
        }?;
        Ok(self)
    }

    pub fn quic_transport_parameters(&mut self) -> Result<&[u8], Error> {
        let mut ptr = core::ptr::null();
        let mut len = 0;
        unsafe {
            s2n_connection_get_quic_transport_parameters(
                self.as_ptr(),
                &mut ptr,
                &mut len,
            )
            .into_result()
        }?;
        let buffer = unsafe { core::slice::from_raw_parts(ptr, len as _) };
        Ok(buffer)
    }

    /// # Safety
    ///
    /// The `context` pointer must live at least as long as the connection
    pub unsafe fn set_secret_callback(
        &mut self,
        callback: s2n_secret_cb,
        context: *mut c_void,
    ) -> Result<&mut Self, Error> {
        s2n_connection_set_secret_callback(self.as_ptr(), callback, context)
            .into_result()?;
        Ok(self)
    }
}

#[cfg(feature = "quic")]
impl config::Builder {
    pub fn enable_quic(&mut self) -> Result<&mut Self, Error> {
        unsafe { s2n_tls_sys::s2n_config_enable_quic(self.as_mut_ptr()).into_result() }?;
        Ok(self)
    }
}