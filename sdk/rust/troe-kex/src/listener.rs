//! Typed access to one bounded inbound TCP endpoint.
use crate::{Error, Handle, call, tcp_listen};

/// Manifest-granted authority over one listener and its accepted streams.
/// Connection identifiers are scoped to this handle and never reused.
pub struct TcpListen {
    pub(crate) handle: Handle,
}

impl TcpListen {
    /// Claim a local port; zero selects an ephemeral port. Backlog is 1 through 4.
    ///
    /// # Errors
    /// Reports invalid arguments, an occupied port, missing network configuration,
    /// exhausted resources, or service failure.
    pub fn listen(&mut self, port: u16, backlog: u8) -> Result<u16, Error> {
        let request =
            tcp_listen::encode_listen_request(port, backlog).map_err(|_| Error::InvalidCall)?;
        let mut reply = [0; tcp_listen::LISTEN_REPLY_BYTES];
        let count = call(self.handle, tcp_listen::LISTEN, &request, &mut reply)?;
        tcp_listen::decode_listen_reply(&reply[..count]).map_err(|_| Error::InvalidCall)
    }

    /// Wait up to four seconds for a completed inbound handshake.
    ///
    /// # Errors
    /// Reports an unbound listener, exhaustion, cancellation, timeout, or failure.
    pub fn accept(&mut self) -> Result<tcp_listen::AcceptReply, Error> {
        let mut reply = [0; tcp_listen::ACCEPT_REPLY_BYTES];
        let count = call(self.handle, tcp_listen::ACCEPT, &[], &mut reply)?;
        tcp_listen::decode_accept_reply(&reply[..count]).map_err(|_| Error::InvalidCall)
    }

    /// Write and acknowledge one nonempty chunk of at most 1,460 bytes.
    ///
    /// # Errors
    /// Reports invalid input, unknown connection, cancellation, timeout, or failure.
    pub fn write(&mut self, connection: u16, bytes: &[u8]) -> Result<(), Error> {
        let mut request = [0; tcp_listen::MAX_WRITE_REQUEST_BYTES];
        let count = tcp_listen::encode_write_request(connection, bytes, &mut request)
            .map_err(|_| Error::InvalidCall)?;
        empty_reply(self.handle, tcp_listen::WRITE, &request[..count])
    }

    /// Read a bounded chunk; zero bytes denotes orderly end of stream.
    ///
    /// # Errors
    /// Reports an empty destination, unknown connection, cancellation, timeout,
    /// reset, or service failure.
    pub fn read(&mut self, connection: u16, destination: &mut [u8]) -> Result<usize, Error> {
        let requested = destination.len().min(tcp_listen::MAX_READ_BYTES);
        let request = tcp_listen::encode_read_request(connection, requested)
            .map_err(|_| Error::InvalidCall)?;
        call(
            self.handle,
            tcp_listen::READ,
            &request,
            &mut destination[..requested],
        )
    }

    /// Gracefully close a stream and retire its identifier, including on failure.
    ///
    /// # Errors
    /// Reports an unknown connection, cancellation, timeout, reset, or failure.
    pub fn close(&mut self, connection: u16) -> Result<(), Error> {
        let request =
            tcp_listen::encode_close_request(connection).map_err(|_| Error::InvalidCall)?;
        empty_reply(self.handle, tcp_listen::CLOSE, &request)
    }
}

fn empty_reply(handle: Handle, opcode: u16, request: &[u8]) -> Result<(), Error> {
    let count = call(handle, opcode, request, &mut [])?;
    if count == 0 {
        Ok(())
    } else {
        Err(Error::InvalidCall)
    }
}
