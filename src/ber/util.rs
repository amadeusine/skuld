use super::{DeserializeError, Length, Tag};

pub(crate) trait VecExt {
    fn write(&mut self, slice: &[u8]);
    fn write_byte(&mut self, byte: u8);
}

impl VecExt for Vec<u8> {
    fn write(&mut self, slice: &[u8]) {
        use std::io::Write;
        self.write_all(slice).unwrap();
    }
    fn write_byte(&mut self, byte: u8) {
        self.write(&[byte]);
    }
}

pub(crate) trait ReadExt {
    fn byte(&mut self) -> Result<u8, DeserializeError>;
    fn uint(&mut self, size: Length) -> Result<u64, DeserializeError>;
    fn int(&mut self, size: Length) -> Result<i64, DeserializeError>;
    fn slice(&mut self, size: Length) -> Result<&[u8], DeserializeError>;
    fn tag(&mut self, expected: Tag) -> Result<Tag, DeserializeError>;
}

impl ReadExt for &'_ [u8] {
    fn byte(&mut self) -> Result<u8, DeserializeError> {
        let byte = *self.get(0).ok_or(DeserializeError::BufferTooShort)?;
        *self = &self[1..];
        Ok(byte)
    }

    fn uint(&mut self, size: Length) -> Result<u64, DeserializeError> {
        let size = size.0 as usize;

        if size > 8 {
            return Err(DeserializeError::IntegerTooLarge);
        } else if size == 0 {
            return Ok(0);
        }

        let mut bytes = [0; 8];
        bytes[8 - size..][..size].copy_from_slice(&self[..size]);

        *self = &self[size..];

        Ok(u64::from_be_bytes(bytes))
    }

    fn int(&mut self, size: Length) -> Result<i64, DeserializeError> {
        let size = size.0 as usize;

        if size > 8 {
            return Err(DeserializeError::IntegerTooLarge);
        } else if size == 0 {
            return Ok(0);
        }

        let mut bytes = if self[0] & 0x80 == 0x80 { [0xFF; 8] } else { [0x00; 8] };

        bytes[8 - size..][..size].copy_from_slice(&self[..size]);

        *self = &self[size..];

        Ok(i64::from_be_bytes(bytes))
    }

    fn slice(&mut self, size: Length) -> Result<&[u8], DeserializeError> {
        let size = size.0 as usize;

        if size == 0 {
            return Ok(&[]);
        }

        let slice = &self[..size];
        *self = &self[size..];

        Ok(slice)
    }

    fn tag(&mut self, expected: Tag) -> Result<Tag, DeserializeError> {
        let tag = Tag::new(self.byte()?);

        if tag != expected {
            Err(DeserializeError::BadTag { expected, got: tag })
        } else {
            Ok(tag)
        }
    }
}

/// This helper function creates a premade size and fills it in after the
/// function is complete
pub fn serialize_sequence<F: Fn(&mut Vec<u8>)>(buffer: &mut Vec<u8>, f: F) {
    // long length, 2 bytes
    buffer.write_byte(0x82);

    let length_idx = buffer.len();
    buffer.write(&[0, 0]);

    let start_length = buffer.len();

    f(buffer);

    let sequence_length = buffer.len() - start_length;
    debug_assert!(sequence_length <= u16::max_value() as usize);

    buffer[length_idx..length_idx + 2].copy_from_slice(&(sequence_length as u16).to_be_bytes()[..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ber::Serialize;

    #[test]
    fn serialize_seq() {
        let mut buffer = Vec::new();
        serialize_sequence(&mut buffer, |buffer| {
            10i32.serialize(buffer);
        });

        assert_eq!(buffer, &[0x82, 0x00, 0x03, 0x02, 0x01, 0x0a]);
    }
}
