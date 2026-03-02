use core::cell::RefCell;

use bytemuck::bytes_of_mut;
use cortex_m::interrupt::{self, Mutex};
use mspm0l222x_hal::{
    HalError,
    uart::{InterruptCause, RxInterruptThreshold, uart0, uart1},
};
use thiserror::Error;

use crate::protocol;

#[derive(Debug, Error)]
pub enum MessageError {
    #[error("Unknown error")]
    Unknown,
    #[error("Unexpected opcode: {0:x}")]
    UnexpectedOpcode(u8),
    #[error("Incorrect magic: {0:x}")]
    IncorrectMagic(u8),
    #[error("Body too long")]
    BodyLengthError,
    #[error("No ACK received")]
    AckError,
    #[error("Unexpected ACK opcode: {0:?}")]
    UnexpectedAckOpcode(Opcode),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opcode {
    List,        // L
    Read,        // R
    Write,       // W
    Receive,     // C
    Interrogate, // I
    Listen,      // N
    Ack,         // A
    Error,       // E
    Debug,       // D
}

#[derive(Debug, Clone, Copy)]
pub enum MessagePort {
    UART0,
    UART1,
}

#[derive(Debug)]
pub struct MessageUart {
    port: MessagePort,
}

// Ideally uart0 and uart1 share some trait so both can be used in the same
// struct, but this is a workaround
impl MessageUart {
    pub fn new(port: MessagePort) -> Self {
        Self { port }
    }

    pub fn write_bytes(&self, bytes: &[u8]) {
        match self.port {
            MessagePort::UART0 => uart0().write_bytes(bytes),
            MessagePort::UART1 => uart1().write_bytes(bytes),
        }
    }

    pub fn read_bytes(&self, bytes: &mut [u8]) -> Result<(), HalError> {
        match self.port {
            MessagePort::UART0 => uart0().read_bytes(bytes),
            MessagePort::UART1 => uart1().read_bytes(bytes),
        }
    }
}

impl TryFrom<u8> for Opcode {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, ()> {
        match value {
            b'L' => Ok(Self::List),
            b'R' => Ok(Self::Read),
            b'W' => Ok(Self::Write),
            b'C' => Ok(Self::Receive),
            b'I' => Ok(Self::Interrogate),
            b'N' => Ok(Self::Listen),
            b'A' => Ok(Self::Ack),
            b'E' => Ok(Self::Error),
            b'D' => Ok(Self::Debug),
            _ => Err(()),
        }
    }
}

impl From<Opcode> for u8 {
    fn from(opcode: Opcode) -> u8 {
        match opcode {
            Opcode::List => b'L',
            Opcode::Read => b'R',
            Opcode::Write => b'W',
            Opcode::Receive => b'C',
            Opcode::Interrogate => b'I',
            Opcode::Listen => b'N',
            Opcode::Ack => b'A',
            Opcode::Error => b'E',
            Opcode::Debug => b'D',
        }
    }
}

/// Value required at the start of every message
pub const MAGIC: u8 = b'%';

pub const HEADER_SIZE: usize = 4;
// TODO: how to chunk files for sending? 8kb is like 1/4 of RAM
/// Maximum body size for a message: 4.5 KiB
pub const MAX_BODY_SIZE: usize = 1024; // TODO: this seems far too large
/// Messages get sent in 256-byte chunks, with an ack for each chunk
pub const CHUNK_SIZE: usize = 256;

/// Opcodes that don't require an ack response.
const NACKS: [Opcode; 2] = [Opcode::Debug, Opcode::Ack];

#[derive(Debug)]
pub struct Message {
    pub opcode: Opcode,
    pub length: u16,
    pub port: MessagePort,
}

impl Message {
    /// Creates a new message from the given opcode, length, and body.
    pub fn new(opcode: Opcode, length: u16, port: MessagePort) -> Self {
        Self {
            opcode,
            length,
            port,
        }
    }

    /// Reads a message header from UART without reading the body.
    #[inline]
    pub fn read_header(port: MessagePort) -> Result<Self, MessageError> {
        let reader = MessageUart::new(port);

        let mut magic = 0u8;
        reader.read_bytes(bytes_of_mut(&mut magic)).unwrap();
        if magic != MAGIC {
            return Err(MessageError::IncorrectMagic(magic));
        }

        let mut opcode_byte = 0u8;
        reader.read_bytes(bytes_of_mut(&mut opcode_byte)).unwrap();
        let Ok(opcode) = Opcode::try_from(opcode_byte) else {
            return Err(MessageError::UnexpectedOpcode(opcode_byte));
        };

        let mut length = [0, 0];
        reader.read_bytes(&mut length).unwrap();
        let length = u16::from_le_bytes(length);

        // rand_ops!(trng::trng());

        Ok(Self {
            opcode,
            length,
            port,
        })
    }

    /// Reads buf.len() bytes from UART.
    pub fn read_body(port: MessagePort, buf: &mut [u8]) -> Result<(), MessageError> {
        let reader = MessageUart::new(port);

        for chunk in buf.chunks_mut(CHUNK_SIZE) {
            reader.read_bytes(chunk).unwrap();
            Self::send_ack(port);
        }

        // rand_ops!(trng::trng());

        Ok(())
    }

    /// Reads buf.len() bytes from UART.
    pub fn read_body_no_ack(port: MessagePort, buf: &mut [u8]) -> Result<(), MessageError> {
        let reader = MessageUart::new(port);

        for chunk in buf.chunks_mut(CHUNK_SIZE) {
            reader.read_bytes(chunk).unwrap();
        }

        // rand_ops!(trng::trng());

        Ok(())
    }

    /// Reads a complete message from UART.
    pub fn read(port: MessagePort, buf: &mut [u8]) -> Result<Self, MessageError> {
        let message = Self::read_header(port)?;
        if !NACKS.contains(&message.opcode) {
            Self::send_ack(port);
        }
        if message.length as usize > buf.len() {
            return Err(MessageError::BodyLengthError);
        }
        Self::read_body(port, &mut buf[..message.length as usize])?;
        Ok(message)
    }

    /// Writes an ack to UART.
    pub fn send_ack(port: MessagePort) {
        Self::write_header(Opcode::Ack, 0, port);
    }

    /// Reads an ack from UART.
    pub fn read_ack(port: MessagePort) -> Result<(), MessageError> {
        let message = Self::read_header(port)?;

        if message.opcode != Opcode::Ack {
            Err(MessageError::UnexpectedAckOpcode(message.opcode))
        } else if message.length != 0 {
            Err(MessageError::AckError)
        } else {
            Ok(())
        }
    }

    pub fn write_header(opcode: Opcode, length: u16, port: MessagePort) {
        let writer = MessageUart::new(port);
        writer.write_bytes(&[MAGIC, opcode.into()]);
        writer.write_bytes(&length.to_le_bytes());

        // rand_ops!(trng::trng());
    }

    /// Writes a message from a slice
    /// This will fail if the buffer is too large (u16 limit)
    pub fn write(opcode: Opcode, port: MessagePort, buf: &[u8]) -> Result<(), MessageError> {
        Self::write_header(opcode, buf.len().try_into().unwrap(), port);
        if !NACKS.contains(&opcode) {
            Self::read_ack(port)?;
        }
        // trailing rand ops in write_body
        Self::write_body(buf, port, &opcode)
    }

    pub fn write_body(data: &[u8], port: MessagePort, opcode: &Opcode) -> Result<(), MessageError> {
        let writer = MessageUart::new(port);
        if !data.is_empty() {
            for chunk in data.chunks(CHUNK_SIZE) {
                writer.write_bytes(chunk);
                if !NACKS.contains(opcode) {
                    Self::read_ack(port)?;
                }
            }
        }

        // rand_ops!(trng::trng());

        Ok(())
    }
}

const ASYNC_RECV_BUFFER_SIZE: usize = size_of::<protocol::EncryptedTransferResponseBody>();

struct AsyncRecvBuffer {
    target_count: Option<usize>,
    current_count: usize,
    buffer: [u8; ASYNC_RECV_BUFFER_SIZE],
}

// this should be set to values that cause it to end up with all 0s, so it ends in bss section
static ASYNC_RECV_BUFFER: Mutex<RefCell<AsyncRecvBuffer>> =
    Mutex::new(RefCell::new(AsyncRecvBuffer {
        target_count: None,
        current_count: 0,
        buffer: [0; _],
    }));

pub fn start_async_recv(size: usize) {
    assert!(size <= ASYNC_RECV_BUFFER_SIZE);

    interrupt::free(|token| {
        let mut recv_buffer = ASYNC_RECV_BUFFER.borrow(token).borrow_mut();
        recv_buffer.target_count = Some(size);
        recv_buffer.current_count = 0;
    });

    uart1().enable_rx_threshold_interrupt(RxInterruptThreshold::ThreeQuartersFull);
}

pub fn await_async_recv_done(buffer: &mut [u8]) {
    // disable interrupts then read the rest out of recv buffer
    uart1().disable_rx_threshold_interrupt();

    interrupt::free(|token| {
        let mut recv_buffer = ASYNC_RECV_BUFFER.borrow(token).borrow_mut();
        // panic if await done not paired with start
        let target_count = recv_buffer.target_count.unwrap();
        let current_count = recv_buffer.current_count;

        // read remaining bytes
        uart1()
            .read_bytes(&mut recv_buffer.buffer[current_count..target_count])
            .unwrap();

        // assert after reading bytes
        assert!(buffer.len() >= target_count);

        buffer[..target_count].copy_from_slice(&mut recv_buffer.buffer);

        recv_buffer.target_count = None;
        recv_buffer.current_count = 0;
    })
}

fn handle_uart_async_recv() {
    interrupt::free(|token| {
        let mut recv_buffer = ASYNC_RECV_BUFFER.borrow(token).borrow_mut();
        let Some(target_count) = recv_buffer.target_count else {
            return;
        };
        let current_count = recv_buffer.current_count;

        if current_count >= target_count {
            return;
        }

        let read_count = uart1()
            .read_bytes_until_empty(&mut recv_buffer.buffer[current_count..target_count])
            .unwrap();

        recv_buffer.current_count += read_count;
    })
}

// unsafe to call directly, only called by interrupts
#[allow(non_snake_case)]
#[unsafe(no_mangle)]
unsafe extern "C" fn UART1() {
    if let Some(cause) = uart1().interrupt_cause() {
        match cause {
            InterruptCause::Threshold => handle_uart_async_recv(),
            _ => uart1().clear_interrupt_cause(cause),
        }
    }
}
