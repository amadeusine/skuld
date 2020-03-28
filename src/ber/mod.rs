//! # `ber`
//!
//! This module contains the types and traits for serializing and deserializing
//! the ASN.1 LDAP types from the Basic Encoding Rules (BER) scheme.
//!

pub mod util;

use util::{ReadExt, VecExt};

pub const OCTET_STRING: Tag = Tag::from_parts(Class::Universal, Aspect::Primitive, 0x04);
pub const INTEGER: Tag = Tag::from_parts(Class::Universal, Aspect::Primitive, 0x02);
pub const SEQUENCE: Tag = Tag::from_parts(Class::Universal, Aspect::Constructed, 0x10);
pub const SET: Tag = Tag::from_parts(Class::Universal, Aspect::Constructed, 0x11);
pub const ENUMERATED: Tag = Tag::from_parts(Class::Universal, Aspect::Primitive, 0x0a);
pub const NULL: Tag = Tag::from_parts(Class::Universal, Aspect::Primitive, 0x05);
pub const BOOL: Tag = Tag::from_parts(Class::Universal, Aspect::Primitive, 0x01);

#[derive(Debug, PartialEq)]
pub enum DeserializeError {
    BadTag { expected: Tag, got: Tag },
    BufferTooShort,
    IndefiniteLength,
    IntegerTooLarge,
    InvalidOid,
    InvalidUtf8,
    InvalidValue,
}

pub trait Serialize {
    fn serialize(&self, buffer: &mut dyn VecExt);
}

pub trait Deserialize: Sized {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError>;
}

/// Represents the class of the tag
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum Class {
    Universal = 0,
    Application = 1,
    ContextSpecific = 2,
    Private = 3,
}

/// Represents whether or not the type is Primitive or Constructed
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum Aspect {
    Primitive = 0,
    Constructed = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tag(u8);

impl Tag {
    /// Construct a new `Tag`
    pub const fn new(byte: u8) -> Self {
        Tag(byte)
    }

    pub const fn from_parts(class: Class, aspect: Aspect, tag: u8) -> Self {
        Tag((tag & 0x1F) | ((class as u8) << 6) | ((aspect as u8) << 5))
    }

    /// Get the `Class` of the tag
    pub fn class(self) -> Class {
        match self.0 >> 6 {
            0 => Class::Universal,
            1 => Class::Application,
            2 => Class::ContextSpecific,
            3 => Class::Private,
            _ => unreachable!("matching on two bits"),
        }
    }

    /// Get the `Aspect` of the tag
    pub fn aspect(self) -> Aspect {
        match (self.0 >> 5) & 1 {
            0 => Aspect::Primitive,
            1 => Aspect::Constructed,
            _ => unreachable!("matching on one bit"),
        }
    }

    /// Get the tag number
    pub fn number(self) -> u8 {
        self.0 & 0x1F
    }

    /// Get the raw value of the tag
    pub const fn raw(self) -> u8 {
        self.0
    }
}

impl Serialize for Tag {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        buffer.write_byte(self.raw());
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Length(u64);

impl Length {
    pub fn new(len: u64) -> Self {
        Self(len)
    }
}

impl Deserialize for Length {
    fn deserialize(bytes: &mut &[u8]) -> Result<Self, DeserializeError> {
        const MASK_LENGTH_DEFINITE: u8 = 0b1000_0000;
        const LENGTH_DEFINITE_SHORT: u8 = 0b0000_0000;

        let length_type = bytes.byte()?;
        let length_value = u64::from(length_type & 0x7F);

        match length_type & MASK_LENGTH_DEFINITE {
            LENGTH_DEFINITE_SHORT => Ok(Self::new(length_value)),
            _ if length_value > 0 => Ok(Self::new(bytes.uint(Length::new(length_value))?)),
            _ => Err(DeserializeError::IndefiniteLength),
        }
    }
}

impl Serialize for Length {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        if self.0 > 127 {
            let ns = self.0.to_be_bytes();
            let start = ns.iter().copied().position(|n| n != 0).unwrap_or(7);
            buffer.write_byte(0x80 | (8 - start as u8));
            buffer.write(&ns[start..]);
        } else {
            buffer.write_byte(self.0 as u8);
        }
    }
}

impl std::ops::Add for Length {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl Serialize for str {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        let length = Length::new(self.as_bytes().len() as u64);

        OCTET_STRING.serialize(buffer);
        Length::serialize(&length, buffer);
        buffer.write(self.as_bytes());
    }
}

impl Serialize for String {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        str::serialize(&*self, buffer);
    }
}

impl Deserialize for String {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError> {
        buffer.tag(OCTET_STRING)?;
        let length = Length::deserialize(buffer)?;

        match std::str::from_utf8(buffer.slice(length)?) {
            Ok(s) => Ok(s.to_string()),
            Err(_) => Err(DeserializeError::InvalidUtf8),
        }
    }
}

impl Deserialize for i32 {
    fn deserialize(bytes: &mut &[u8]) -> Result<Self, DeserializeError> {
        bytes.tag(INTEGER)?;
        let length = Length::deserialize(bytes)?;
        Ok(bytes.int(length)? as i32)
    }
}

impl Serialize for i32 {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        INTEGER.serialize(buffer);
        let ns = self.to_be_bytes();
        let start = if self.is_negative() {
            0
        } else {
            let start = ns.iter().copied().position(|n| n != 0).unwrap_or(3);

            if start != 0 && ns[start] & 0x80 == 0x80 {
                start - 1
            } else {
                start
            }
        };

        let length = Length::new(4 - start as u64);

        length.serialize(buffer);
        buffer.write(&ns[start..]);
    }
}

impl Deserialize for u32 {
    fn deserialize(bytes: &mut &[u8]) -> Result<Self, DeserializeError> {
        bytes.tag(INTEGER)?;
        let length = Length::deserialize(bytes)?;
        Ok(bytes.uint(length)? as u32)
    }
}

impl Serialize for u32 {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        (*self as i32).serialize(buffer);
    }
}

impl Serialize for i64 {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        INTEGER.serialize(buffer);
        let ns = self.to_be_bytes();
        let start = if self.is_negative() {
            0
        } else {
            let start = ns.iter().copied().position(|n| n != 0).unwrap_or(7);

            if start != 0 && ns[start] & 0x80 == 0x80 {
                start - 1
            } else {
                start
            }
        };

        let length = Length::new(4 - start as u64);

        length.serialize(buffer);
        buffer.write(&ns[start..]);
    }
}

impl Deserialize for u64 {
    fn deserialize(bytes: &mut &[u8]) -> Result<Self, DeserializeError> {
        bytes.tag(INTEGER)?;
        let length = Length::deserialize(bytes)?;
        Ok(bytes.uint(length)? as u64)
    }
}

impl Serialize for u64 {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        (*self as i64).serialize(buffer);
    }
}

pub struct Null;

impl Deserialize for Null {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError> {
        buffer.tag(NULL)?;
        let length = Length::deserialize(buffer)?;
        let _ = buffer.slice(length)?;

        Ok(Null)
    }
}

impl Serialize for Null {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        NULL.serialize(buffer);
        Length::new(0).serialize(buffer);
    }
}

impl<T: Serialize> Serialize for Vec<T> {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        SEQUENCE.serialize(buffer);

        util::serialize_sequence(buffer, |buffer| {
            for item in self {
                item.serialize(buffer);
            }
        });
    }
}

impl<T: Deserialize> Deserialize for Vec<T> {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError> {
        buffer.tag(SEQUENCE)?;
        let length = Length::deserialize(buffer)?;
        let slice = &mut buffer.slice(length)?;

        let mut vec = Vec::new();
        while !slice.is_empty() {
            vec.push(T::deserialize(slice)?);
        }

        Ok(vec)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Set<T>(Vec<T>);

impl<T> From<Vec<T>> for Set<T> {
    fn from(v: Vec<T>) -> Self {
        Self(v)
    }
}

impl<T: Serialize> Serialize for Set<T> {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        SET.serialize(buffer);
        util::serialize_sequence(buffer, |buffer| {
            for item in &self.0 {
                item.serialize(buffer);
            }
        });
    }
}

impl<T: Deserialize> Deserialize for Set<T> {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError> {
        buffer.tag(SET)?;
        let length = Length::deserialize(buffer)?;
        let slice = &mut buffer.slice(length)?;

        let mut vec = Vec::new();
        while !slice.is_empty() {
            vec.push(T::deserialize(slice)?);
        }

        Ok(Self(vec))
    }
}

/// LDAP defines a BOOLEAN `true` to be `0xFF` and any other value `false`
impl Serialize for bool {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        BOOL.serialize(buffer);
        Length::new(1).serialize(buffer);

        match self {
            true => buffer.write_byte(0xFF),
            false => buffer.write_byte(0x00),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags() {
        assert_eq!(Tag::from_parts(Class::Universal, Aspect::Primitive, 0), Tag::new(0x00));
        assert_eq!(Tag::from_parts(Class::Application, Aspect::Primitive, 0), Tag::new(0x40));
        assert_eq!(Tag::from_parts(Class::ContextSpecific, Aspect::Constructed, 1), Tag::new(0xa1));
        assert_eq!(Tag::from_parts(Class::Universal, Aspect::Constructed, 5), Tag::new(0x25));
    }
}
