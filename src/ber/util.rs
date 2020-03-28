use super::{DeserializeError, Length, Serialize, Tag};
use tinyvec::TinyVec;

pub trait VecExt {
    fn write(&mut self, slice: &[u8]);
    fn write_byte(&mut self, byte: u8);
}

impl VecExt for Vec<u8> {
    fn write(&mut self, slice: &[u8]) {
        self.extend_from_slice(slice);
    }
    fn write_byte(&mut self, byte: u8) {
        self.push(byte);
    }
}

impl VecExt for TinyVec<[u8; 32]> {
    fn write(&mut self, slice: &[u8]) {
        self.extend_from_slice(slice);
    }
    fn write_byte(&mut self, byte: u8) {
        self.push(byte);
    }
}

pub trait ReadExt {
    fn peek(&mut self) -> Result<u8, DeserializeError>;
    fn byte(&mut self) -> Result<u8, DeserializeError>;
    fn uint(&mut self, size: Length) -> Result<u64, DeserializeError>;
    fn int(&mut self, size: Length) -> Result<i64, DeserializeError>;
    fn slice(&mut self, size: Length) -> Result<&[u8], DeserializeError>;
    fn tag(&mut self, expected: Tag) -> Result<Tag, DeserializeError>;
    fn peek_tag(&mut self, expected: Tag) -> Result<Tag, DeserializeError>;
}

impl ReadExt for &'_ [u8] {
    fn peek(&mut self) -> Result<u8, DeserializeError> {
        Ok(*self.get(0).ok_or(DeserializeError::BufferTooShort)?)
    }

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

    fn peek_tag(&mut self, expected: Tag) -> Result<Tag, DeserializeError> {
        let tag = Tag::new(self.peek()?);

        if tag != expected {
            Err(DeserializeError::BadTag { expected, got: tag })
        } else {
            Ok(tag)
        }
    }
}

/// This helper function creates a premade size and fills it in after the
/// function is complete
pub(crate) fn serialize_sequence<F: Fn(&mut dyn VecExt)>(buffer: &mut dyn VecExt, f: F) {
    let mut temp_vec: TinyVec<[u8; 32]> = TinyVec::new();
    f(&mut temp_vec);
    Length::new(temp_vec.len() as u64).serialize(buffer);
    buffer.write(&temp_vec);
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

        assert_eq!(buffer, &[0x03, 0x02, 0x01, 0x0a]);
    }
}
