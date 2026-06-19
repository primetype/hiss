//! Zero-allocation handshake message buffers.
//!
//! Two cursor types for the send and receive paths of the Noise
//! handshake. Both borrow external memory — the caller provides the
//! buffer, the handshake fills or reads it. No heap allocation.
//!
//! # Send path
//!
//! [`SendBuffer`] wraps a `&mut [u8]` with a write cursor. Token
//! methods append data via [`write`](SendBuffer::write) or obtain a
//! mutable slice for in-place encryption via
//! [`reserve`](SendBuffer::reserve). When all tokens have been
//! processed, `written` returns the filled
//! portion as `&[u8]`.
//!
//! # Receive path
//!
//! [`RecvBuffer`] wraps a `&[u8]` with a read cursor. Token methods
//! consume bytes via [`read`](RecvBuffer::read). No copy — the
//! incoming message is read directly.

use super::error::HandshakeError;

/// A write cursor over a borrowed buffer for building outgoing
/// handshake messages.
///
/// The buffer is provided by the caller — typically a stack-allocated
/// `[u8; N]` where `N` comes from [`noise_message_size!`](crate::noise_message_size). No heap
/// allocation occurs.
pub(crate) struct SendBuffer<'a> {
    data: &'a mut [u8],
    cursor: usize,
}

impl<'a> SendBuffer<'a> {
    /// Wrap a mutable byte slice as a send buffer.
    ///
    /// The caller is responsible for providing a buffer of the correct
    /// size (see [`noise_message_size!`](crate::noise_message_size)).
    pub(crate) fn new(data: &'a mut [u8]) -> Self {
        Self { data, cursor: 0 }
    }

    /// Append `bytes` to the buffer, advancing the write cursor.
    ///
    /// # Panics
    ///
    /// Panics if the buffer has insufficient remaining capacity. This
    /// indicates a bug in the size computation — all token sizes are
    /// known at compile time.
    pub(crate) fn write(&mut self, bytes: &[u8]) {
        let end = self.cursor + bytes.len();
        assert!(
            end <= self.data.len(),
            "SendBuffer overflow: need {} bytes at offset {}, buffer is {} bytes",
            bytes.len(),
            self.cursor,
            self.data.len(),
        );
        self.data[self.cursor..end].copy_from_slice(bytes);
        self.cursor = end;
    }

    /// Reserve `len` bytes at the current cursor position and return
    /// a mutable slice to them.
    ///
    /// Used for in-place encryption — `encrypt_and_hash` writes
    /// ciphertext + tag directly into the reserved region.
    ///
    /// # Panics
    ///
    /// Panics if the buffer has insufficient remaining capacity.
    pub(crate) fn reserve(&mut self, len: usize) -> &mut [u8] {
        let end = self.cursor + len;
        assert!(
            end <= self.data.len(),
            "SendBuffer overflow: need {} bytes at offset {}, buffer is {} bytes",
            len,
            self.cursor,
            self.data.len(),
        );
        let slice = &mut self.data[self.cursor..end];
        self.cursor = end;
        slice
    }

    /// Returns the number of bytes written so far.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.cursor
    }

    /// Returns the filled portion of the buffer.
    #[cfg(test)]
    pub(crate) fn written(&self) -> &[u8] {
        &self.data[..self.cursor]
    }

    /// Consume the buffer and return the filled portion as `&'a [u8]`.
    ///
    /// Releases the mutable borrow, allowing the caller to use the
    /// written bytes as an immutable slice with the original lifetime.
    pub(crate) fn finish(self) -> &'a [u8] {
        let len = self.cursor;
        &self.data[..len]
    }
}

/// A read cursor over a borrowed buffer for parsing incoming
/// handshake messages.
///
/// No copy — the incoming message bytes are read directly from the
/// caller's slice.
pub(crate) struct RecvBuffer<'a> {
    data: &'a [u8],
    cursor: usize,
}

impl<'a> RecvBuffer<'a> {
    /// Wrap a byte slice as a receive buffer.
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, cursor: 0 }
    }

    /// Read exactly `len` bytes from the current position, advancing
    /// the cursor.
    ///
    /// Returns [`HandshakeError::MessageTooShort`] if insufficient
    /// data remains.
    pub(crate) fn read(&mut self, len: usize) -> Result<&'a [u8], HandshakeError> {
        let end = self.cursor + len;
        if end > self.data.len() {
            return Err(HandshakeError::MessageTooShort);
        }
        let slice = &self.data[self.cursor..end];
        self.cursor = end;
        Ok(slice)
    }

    /// Return the remaining unread bytes.
    pub(crate) fn remaining(&self) -> &'a [u8] {
        &self.data[self.cursor..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_write_fills_buffer() {
        let mut buf = [0u8; 10];
        let mut sb = SendBuffer::new(&mut buf);
        sb.write(b"hello");
        sb.write(b"world");
        assert_eq!(sb.len(), 10);
        assert_eq!(sb.written(), b"helloworld");
    }

    #[test]
    fn send_reserve_returns_mutable_slice() {
        let mut buf = [0u8; 6];
        let mut sb = SendBuffer::new(&mut buf);
        sb.write(b"AB");
        let slot = sb.reserve(4);
        slot.copy_from_slice(b"CDEF");
        assert_eq!(sb.written(), b"ABCDEF");
    }

    #[test]
    #[should_panic(expected = "SendBuffer overflow")]
    fn send_write_overflow_panics() {
        let mut buf = [0u8; 3];
        let mut sb = SendBuffer::new(&mut buf);
        sb.write(b"toolong");
    }

    #[test]
    #[should_panic(expected = "SendBuffer overflow")]
    fn send_reserve_overflow_panics() {
        let mut buf = [0u8; 3];
        let mut sb = SendBuffer::new(&mut buf);
        sb.reserve(4);
    }

    #[test]
    fn recv_read_advances_cursor() {
        let data = b"helloworld";
        let mut rb = RecvBuffer::new(data);
        let first = rb.read(5).unwrap();
        assert_eq!(first, b"hello");
        let second = rb.read(5).unwrap();
        assert_eq!(second, b"world");
        assert!(rb.remaining().is_empty());
    }

    #[test]
    fn recv_read_too_much_returns_error() {
        let data = b"short";
        let mut rb = RecvBuffer::new(data);
        let err = rb.read(10).unwrap_err();
        assert!(matches!(err, HandshakeError::MessageTooShort));
    }

    #[test]
    fn recv_remaining_returns_tail() {
        let data = b"abcdef";
        let mut rb = RecvBuffer::new(data);
        let _ = rb.read(2).unwrap();
        assert_eq!(rb.remaining(), b"cdef");
    }

    #[test]
    fn send_zero_size_buffer() {
        let mut buf = [0u8; 0];
        let sb = SendBuffer::new(&mut buf);
        assert_eq!(sb.len(), 0);
        assert_eq!(sb.written(), b"");
    }

    #[test]
    fn recv_empty_buffer() {
        let data = b"";
        let rb = RecvBuffer::new(data);
        assert!(rb.remaining().is_empty());
    }
}
