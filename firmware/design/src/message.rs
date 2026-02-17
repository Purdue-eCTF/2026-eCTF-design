use bytemuck::bytes_of_mut;
use mspm0l222x_hal::uart::uart0;
use thiserror::Error;

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

// TODO: how to chunk files for sending? 8kb is like 1/4 of RAM
/// Maximum body size for a message: 4.5 KiB
pub const MAX_BODY_SIZE: usize = 4608;
/// Messages get sent in 256-byte chunks, with an ack for each chunk
pub const CHUNK_SIZE: usize = 256;

/// Opcodes that don't require an ack response.
const NACKS: [Opcode; 2] = [Opcode::Debug, Opcode::Ack];

#[derive(Debug)]
pub struct Message {
    pub opcode: Opcode,
    pub length: u16,
    pub body: [u8; MAX_BODY_SIZE],
}

impl Message {
    /// Creates a new message from the given opcode, length, and body.
    pub fn new(opcode: Opcode, length: u16, body: [u8; MAX_BODY_SIZE]) -> Self {
        Self {
            opcode,
            length,
            body,
        }
    }

    /// Creates a new message from the given opcode and byte slice.
    #[inline]
    pub fn from_data(opcode: Opcode, data: &[u8]) -> Result<Self, MessageError> {
        if data.len() > MAX_BODY_SIZE {
            return Err(MessageError::BodyLengthError);
        }

        let mut body = [0; MAX_BODY_SIZE];
        body[..data.len()].copy_from_slice(data);

        Ok(Self::new(opcode, data.len() as u16, body))
    }

    /// Gets the message body as a mutable byte slice.
    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.body[..self.length.into()]
    }

    /// Reads a message header from UART without reading the body.
    #[inline]
    pub fn read_header() -> Result<Self, MessageError> {
        // TODO: once uart0/uart1 support is merged:
        // - replace uart with uart0
        // - replace read_bytes(1) with read_byte
        let reader = uart0();

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
        Ok(Self {
            opcode,
            length,
            body: [0; MAX_BODY_SIZE],
        })
    }

    /// Reads a complete message from UART.
    pub fn read() -> Result<Self, MessageError> {
        let reader = uart0();
        let mut message = Self::read_header()?;

        Self::send_ack();

        if message.length != 0 {
            for chunk in message.body[..message.length.into()].chunks_mut(CHUNK_SIZE) {
                reader.read_bytes(chunk).unwrap();
                Self::send_ack();
            }
        }

        Ok(message)
    }

    /// Reads up to CHUNK_SIZE bytes from UART, skipping the header.
    pub fn read_block() -> Result<[u8; CHUNK_SIZE], MessageError> {
        let mut content: [u8; CHUNK_SIZE] = [0; CHUNK_SIZE];
        let reader = uart0();
        reader.read_bytes(&mut content).unwrap();
        Self::send_ack();

        Ok(content)
    }

    /// Writes an ack to UART.
    pub fn send_ack() {
        let ack = Self::ack();
        ack.write_header();
    }

    /// Reads an ack from UART.
    pub fn read_ack() -> Result<(), MessageError> {
        let message = Self::read_header()?;

        if message.length != 0 {
            Err(MessageError::AckError)
        } else {
            Ok(())
        }
    }

    /// Writes this message's header to UART.
    pub fn write_header(&self) {
        let writer = uart0();

        writer.write_bytes(&[MAGIC, self.opcode.into()]);
        writer.write_bytes(&self.length.to_le_bytes());
    }

    pub fn write_header_helper(opcode: Opcode, length: u16) {
        let writer = uart0();
        writer.write_bytes(&[MAGIC, opcode.into()]);
        writer.write_bytes(&length.to_le_bytes());
    }

    /// Writes this message to UART.
    pub fn write(&self) -> Result<(), MessageError> {
        self.write_header();
        if !NACKS.contains(&self.opcode) {
            Self::read_ack()?;
        }
        let writer = uart0();

        if self.length != 0 {
            for chunk in self.body[..self.length.into()].chunks(CHUNK_SIZE) {
                writer.write_bytes(chunk);
                if !NACKS.contains(&self.opcode) {
                    Self::read_ack()?;
                }
            }
        }
        Ok(())
    }

    /// Writes up to CHUNK_SIZE bytes to UART without sending a header.
    pub fn write_block(data: &[u8]) -> Result<(), MessageError> {
        if data.len() > CHUNK_SIZE {
            return Err(MessageError::BodyLengthError);
        }

        let writer = uart0();
        writer.write_bytes(data);
        Self::read_ack()?;
        Ok(())
    }

    /// Convenience method to immediately create and send a message from the given
    /// opcode and byte slice.
    pub fn send_data(opcode: Opcode, data: &[u8]) -> Result<(), MessageError> {
        if data.len() > MAX_BODY_SIZE {
            return Err(MessageError::BodyLengthError);
        }
        let msg = Message::from_data(opcode, data)?;
        msg.write()
    }

    /// Static method to generate an ack message.
    pub const fn ack() -> Self {
        Self {
            opcode: Opcode::Ack,
            length: 0,
            body: [0; MAX_BODY_SIZE],
        }
    }
}


// TODO: inter-device messaging over UART1
