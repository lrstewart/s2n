// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Utilities to handle passing Rust code to s2n-tls's C callbacks.
//!
//! s2n-tls uses callbacks to temporarily return control to the application
//! and allow the application to execute custom code.
//!
//! To use a callback in your application, just implement the trait for the
//! target callback type and pass your implementation to the appropriate
//! connection or config method. For example, you can implement
//! [`ClientHelloCallback`] and pass that implementation to
//! [config::Builder::set_client_hello_callback()](`crate::config::Builder::set_client_hello_callback()`)
//! in order to execute custom logic after an s2n-tls server receives a client hello.
//!
//! s2n-tls callbacks come in two flavors:
//! * "sync" callbacks return an immediate result and will block the task
//!   performing the handshake until they return success or failure. See
//!   [`VerifyHostNameCallback`] as an example.
//! * "async" callbacks return a [`Poll`] and should not block the task performing the handshake.
//!   They will be polled until they return [`Poll::Ready`].
//!   [Connection::waker()](`crate::connection::Connection::waker()`)
//!   can be used to register the task for wakeup. See [`ClientHelloCallback`] as an example.

use crate::{connection::Connection, enums::CallbackResult, error::Error};
use core::task::Poll;
use pin_project_lite::pin_project;
use std::pin::Pin;

/// The Future associated with the async connection callback.
///
/// The calling application can provide an instance of [`ConnectionFuture`]
/// when implementing an async callback, eg. [`ClientHelloCallback`], if it wants
/// to run an asynchronous operation (disk read, network call). The application
/// can return an error ([`Err(error::Error::application())`]), to indicate
/// connection failure.
///
/// [`ConfigResolver`] should be used if the application wants to set a new
/// [`Config`] on the connection.
pub trait ConnectionFuture {
    fn poll(
        self: Pin<&mut Self>,
        connection: &mut Connection,
        ctx: &mut core::task::Context,
    ) -> Poll<Result<(), Error>>;
}

pub(crate) type ConnectionFutureResult = Result<Option<Pin<Box<dyn ConnectionFuture>>>, Error>;

// Useful for propagating [`error::Error`] from a C callback back to the Rust application.
pub(crate) struct ErrorFuture {
    error: Option<Error>,
}

impl ConnectionFuture for ErrorFuture {
    fn poll(
        mut self: Pin<&mut Self>,
        _connection: &mut Connection,
        _ctx: &mut core::task::Context,
    ) -> Poll<Result<(), Error>> {
        let err = self.error.take().expect(
            "ErrorFuture should be initialized with Some(error) and a Future should never
            be polled after it returns Poll::Ready",
        );
        Poll::Ready(Err(err))
    }
}

pin_project! {
    struct OptionalFuture{
        #[pin]
        option: Option<Pin<Box<dyn ConnectionFuture>>>,
    }
}

impl OptionalFuture {
    fn new(input: ConnectionFutureResult) -> Self {
        match input {
            Ok(option) => OptionalFuture { option },
            Err(error) => {
                let error = Some(error);
                OptionalFuture {
                    option: Some(Box::pin(ErrorFuture { error })),
                }
            }
        }
    }
}

impl ConnectionFuture for OptionalFuture {
    fn poll(
        mut self: Pin<&mut Self>,
        conn: &mut Connection,
        ctx: &mut core::task::Context,
    ) -> Poll<Result<(), Error>> {
        match self.option.as_mut() {
            Some(future) => future.as_mut().poll(conn, ctx),
            None => Poll::Ready(Ok(())),
        }
    }
}

pub(crate) trait MarkDone {
    fn mark_done(&mut self, conn: &mut Connection) -> Result<(), Error>;
}

pin_project! {
    pub(crate) struct AsyncCallback {
        #[pin]
        future: OptionalFuture,
        #[pin]
        cleanup: Option<Box<dyn MarkDone>>,
    }
}

impl AsyncCallback {
    pub(crate) fn poll(
        self: Pin<&mut Self>,
        conn: &mut Connection,
        ctx: &mut core::task::Context,
    ) -> Poll<Result<(), Error>> {
        let mut this = self.project();
        let poll = this.future.poll(conn, ctx);
        if let Poll::Ready(Ok(())) = poll {
            if let Some(cleanup) = &mut *this.cleanup {
                cleanup.mark_done(conn)?;
            }
        }
        poll
    }

    pub(crate) fn trigger(
        future: ConnectionFutureResult,
        cleanup: Box<dyn MarkDone>,
        conn: &mut Connection,
    ) -> CallbackResult {
        let future = OptionalFuture::new(future);
        let cleanup = Some(cleanup);
        let callback = AsyncCallback { future, cleanup };
        conn.set_async_callback(callback);
        CallbackResult::Success
    }
}
