//! # `ber`
//!
//! This module contains the types and traits for serializing and deserializing
//! the ASN.1 LDAP types from the Basic Encoding Rules (BER) scheme. This
//! documentation serves to help explain the concepts used in the protocol
//! definition to contributors and those who are interested
//!
//! ## How to read ASN.1
//!
//! ### Base types
//!
//! ASN.1 has a number of "universal" types that are available for
//! specifications to build off of. Each of these types has a name, what we call
//! the "aspect" of the type which is whether it is `Primitive` or
//! `Constructed`, and a tag number. The format of the tag is discussed later.
//! The most commonly used ones in the LDAP specification are shown in the table
//! below:
//!
//! | Name                   | Aspect      | Tag Number dec [hex] |
//! |------------------------|------------------------|----------------------|
//! | BOOLEAN                | Primitive              | 1 [0x01]             |
//! | INTEGER                | Primitive              | 2 [0x02]             |
//! | OCTET STRING           | Primitive<sup>1</sup>  | 4 [0x04]             |
//! | SEQUENCE / SEQUENCE OF | Constructed            | 16 [0x10]            |
//! | SET / SET OF           | Constructed            | 17 [0x11]            |
//!
//! <sup>1</sup> `OCTET STRING` is defined as both primitive and constructed but
//! the LDAP specification restricts it to the Primitive encoding only
//!
//! `OCTET STRING` is simply a series of bytes
//!
//! `SEQUENCE` / `SEQUENCE OF` define an ordered sequence of types (`SEQUENCE
//! OF` restricts this to zero or more of the same type)
//!
//! `SET` / `SET OF` define an unordered sequence of types (`SET OF` restricts
//! this to zero or more of the same type)
//!
//! #### Type classes
//!
//! Each type is part of one of four different classes defined in ASN.1:
//!
//! | Class            | Value | Description                                                                            |
//! |------------------|-------|----------------------------------------------------------------------------------------|
//! | Universal        | 0     | The type is native to ASN.1                                                            |
//! | Application      | 1     | The type is only valid for one specific application                                    |
//! | Context-specific | 2     | Meaning of this type depends on the context (such as within a sequence, set or choice) |
//! | Private          | 3     | Defined in private specifications                                                      |
//!
//! ### Definition of new types
//!
//! #### Type aliases
//!
//! The LDAP specification defines many new types that are used throughout the
//! RFCs, the most basic being equivalent to a type alias in Rust:
//!
//! `AssertionValue ::= OCTET STRING`
//!
//! This defines `AssertionValue` as having the same representation as `OCTET
//! STRING`
//!
//! #### Sequence types
//!
//! Types which are defined as a sequence of other types are the most common
//! type definition in the LDAP specification. The most basic form of this is a
//! bare sequence with named fields, for example:
//!
//! ```notrust
//! AttributeValueAssertion ::= SEQUENCE {
//!     attributeDesc   AttributeDescription,
//!     assertionValue  AssertionValue }
//! ```
//!
//! `AttributeValueAssertion` is now defined as a sequence which contains
//! `attributeDesc` of type `AttributeDescription`, and `assertionValue` of type
//! `AssertionValue`
//!
//! #### Application specific types
//!
//! One of the other most common type definitions are ones which specify an
//! `APPLICATION` tag value, for example:
//!
//! ```notrust
//! BindRequest ::= [APPLICATION 0] SEQUENCE {
//!     version                 INTEGER (1 ..  127),
//!     name                    LDAPDN,
//!     authentication          AuthenticationChoice }
//! ```
//!
//! (Note: the `(1 ..  127)` after `INTEGER` restricts the valid values)
//!
//! Here `[APPLICATION 0]` means that this type is marked as being
//! application-specific and does not use the `SEQUENCE` tag, though
//! importantly: it inherits the aspect of the type its defined on which means
//! that `BindRequest` is also marked as Constructed.
//!
//! #### Choice and Context-Specific types
//!
//! A good example of a `CHOICE` type is the `AuthenticationChoice`:
//!
//! ```notrust
//! AuthenticationChoice ::= CHOICE {
//!     simple                  [0] OCTET STRING,
//!     -- 1 and 2 reserved
//!     sasl                    [3] SaslCredentials,
//!     ...  }
//! ```
//!
//! Unsurprisingly, there is no type tag for `CHOICE` types, instead its defined
//! by the types inside the `CHOICE`, so it can be any of the type tags of types
//! listed within. Usually, the types within a `CHOICE` type are prefixed by
//! `[<NUMBER>]`, which denotes a `Context-Specific` type tag. As with the
//! `APPLICATION` type tags, the type tags for these inherit the aspect of the
//! type they're defined on. So `[0] OCTET STRING` forms a type tag that's class
//! is `Context-Specific`, aspect is `Primitive`, and tag number is `0`. `[3]
//! SaslCredentials` has a type tag that's class is `Context-Specific`, aspect
//! is `Constructed` and tag number is `3`.
//!
//! #### Optional types
//!
//! Some types are suffixed with the `OPTIONAL` specifier. These types are
//! usually also context specific so they are not ambiguous with other types
//! that could follow. Optional types are simply not encoded into the message if
//! they are not present, which means you must check for end-of-message or peek
//! the tag of the next type to see if you should decode it. A good example of
//! this is the referral field on the `LDAPResult` type ([section
//! 4.1.9](https://tools.ietf.org/html/rfc4511#section-4.1.9)).
//!
//! ## Basic Encoding Rules (BER)
//!
//! Basic Encoding Rules is one codec for de/serializing ASN.1 and as the name
//! implies is fairly simple. Each type is encoded in the following way:
//!
//! ```notrust
//! <tag> <content length> <contents>
//! ```
//!
//! The tag byte format is:
//!
//! ```notrust
//! | 7-6 (2 bits) | 5 (1 bit) | 4-0 (5 bits) |
//! |--------------|-----------|--------------|
//! | Class        | Aspect    | Tag Number   |
//! ```
//!
//! The value of the `Class` can be found above, and the aspect is `0` for
//! `Primitive` and `1` for `Constructed`.
//!
//! BER defines four total forms of the length field: definite (short), definite
//! (long), indefinite, and reserved. We don't care about the reserved, and the
//! LDAP specification disallows usage of the indefinite form, so the only
//! remaining forms are the short and long definite forms which are encoded as
//! follows:
//!
//! ```notrust
//! | Form             | Bit 7 | Bits 6-0                                                                                    |
//! |------------------|-------|---------------------------------------------------------------------------------------------|
//! | Definite (Short) | 0     | Length of the content                                                                       |
//! | Definite (Long)  | 1     | Size of following big-endian integer (1 to 126 bytes) which gives the length of the content |
//! ```
//!
//! For example, `02` has the following bit pattern: 0|0000010, which means its
//! a short form length and the content is 2 bytes long following the length.
//! `82 01 FF` has the following bit pattern: 1|0000010 ..., which denotes a
//! long form length. We then read the next two bytes, `01 FF`, as a big endian
//! integer, `01FF`, which tells us that the content length following the length
//! bytes is 511 bytes long. Lengths for content may be 0, indicating that there
//! is no content following. Types are then recursively de/serialized in the
//! order defined in the specification.
//!
//! ## Putting it all together
//!
//! Here is an example of all of these concepts put together. Suppose we have
//! the type defined in [section
//! 4.9](https://tools.ietf.org/html/rfc4511#section-4.9): `ModifyDNRequest`
//!
//! ```notrust
//! ModifyDNRequest ::= [APPLICATION 12] SEQUENCE {
//!     entry           LDAPDN,
//!     newrdn          RelativeLDAPDN,
//!     deleteoldrdn    BOOLEAN,
//!     newSuperior     [0] LDAPDN OPTIONAL }
//! ```
//!
//! `LDAPDN` and `RelativeLDAPDN` are both `LDAPString`s which are further
//! restricted, and `LDAPString` is an `OCTET STRING` restricted to UTF-8, so
//! all of them are encoded as as `OCTET STRING`s, which has a tag of `04`, a
//! universal, primitive type with a tag number of 4. So lets decode a
//! `ModifyDNRequest` (decoding is slightly easier because you're given the
//! lengths and need not calculate them yourself).
//!
//! Full packet:
//! ```notrust
//! 30 49 02 01 02 6c 44 04 1d 63 6e 3d 73 6f
//! 6d 65 75 73 65 72 2c 64 63 3d 65 78 61 6d
//! 70 6c 65 2c 64 63 3d 63 6f 6d 04 0c 75 69
//! 64 3d 74 65 73 74 2e 75 73 72 01 01 00 80
//! 12 64 63 3d 64 6f 65 73 6e 74 2c 64 63 3d
//! 65 78 69 73 74
//! ```
//!
//! All operations in LDAP are done through the `LDAPMessage` type which has
//! some additional fields to the ones in `ModifyDNRequest` above, see [section
//! 4.1.1](https://tools.ietf.org/html/rfc4511#section-4.1.1) for the full
//! definition of `LDAPMessage`. So we need to decode that as well. Looking at
//! the first byte we see `30`, the expected type tag of `SEQUENCE`, a
//! universal, constructed type with a type tag value of `10` (hex). Now onto
//! the length: `49`, which has a bit pattern of: 0|1001001. This means we're
//! dealing with a short definite length and the content is 73 bytes long.
//! Decoding the next portion is the `messageID` field of `LDAPMessage` which is
//! an integer, length 1, with a value of 2 (`02 01 02`).
//!
//! The protocol operation is the next thing up -- our `ModifyDNRequest` of
//! which we expect to find an application-specific, constructed type with a tag
//! number of 12, which we do! `6c` has a bit pattern of `01|1|01100` which
//! confirms we're parsing the right type. The length is again in short form,
//! `44` which means that our `ModifyDNRequest` content is 68 bytes in total.
//! `entry` is the first field, which is of type `LDAPDN` (which is reall just
//! an `OCTET STRING`, remember), so we have an `OCTET STRING` tag, a length of
//! 29, and the content bytes, which in textual form are:
//! `cn=someuser,dc=example,dc=com`. `newrdn` is another `OCTET STRING` in
//! disguise, with the bytes defining it: `04 0c 75 69 64 3d 74 65 73 74 2e 75
//! 73 72`, easy enough: `uid=test.usr`. `deletoldrdn` is a bool, which has a
//! tag number of 1, and only has a length of one, whose value is `00`. LDAP
//! defines boolean `TRUE` to be `FF`, so this is `FALSE`.
//!
//! The next field, `newSuperior`, is an optional context-specific `LDAPDN`. So
//! we check to see if we're at the end of the message yet -- nope! still have
//! more bytes to process, then we check the tag: `80` has a bit pattern of
//! `10|0|00000` which tells us its a context-specific, universal type with a
//! tag number of 0, that's our type! The length and content are decoded as
//! usual. We're still not done however, we finished decoding `ModifyDNRequest`,
//! but we still have the `controls` field of `LDAPMessage`, which is also an
//! optional type. Check one: have we reached the end of the packet? As a matter
//! of fact, yes, we have! Therefore `controls` is `None` and we've finished
//! decoding the entire packet!
//!
//! Here's a more graphical representation of the above packet (lengths in
//! brackets):
//!
//! ```notrust
//! 30 [49] -- Sequence, length 73
//!     02 [01] -- Integer, length 1
//!     02      -- Value of 2
//!     6c [44] -- ModifyDNRequest, length 68
//!     04 [1d] -- OCTET STRING, length 29
//!         63 6e 3d 73 6f 6d 65 75
//!         73 65 72 2c 64 63 3d 65
//!         78 61 6d 70 6c 65 2c 64
//!         63 3d 63 6f 6d
//!         -- Value "cn=someuser,dc=example,dc=com"
//!     04 [0c] -- OCTET STRING, length 12
//!         75 69 64 3d 74 65 73 74
//!         2e 75 73 72
//!         -- Value "uid=test.usr"
//!     01 [01]
//!         00  -- Value FALSE
//!     80 [12] -- Context-specific + Primitive
//!             -- tag number 0
//!         64 63 3d 64 6f 65 73 6e
//!         74 2c 64 63 3d 65 78 69
//!         73 74
//!         -- Value "dc=doesnt,dc=exist"
//! ```
//!

pub(crate) mod util;

use util::{ReadExt, VecExt};

pub(crate) const OCTET_STRING: Tag = Tag::from_parts(Class::Universal, Aspect::Primitive, 0x04);
pub(crate) const INTEGER: Tag = Tag::from_parts(Class::Universal, Aspect::Primitive, 0x02);
pub(crate) const SEQUENCE: Tag = Tag::from_parts(Class::Universal, Aspect::Constructed, 0x10);
pub(crate) const SET: Tag = Tag::from_parts(Class::Universal, Aspect::Constructed, 0x11);
pub(crate) const ENUMERATED: Tag = Tag::from_parts(Class::Universal, Aspect::Primitive, 0x0a);
pub(crate) const NULL: Tag = Tag::from_parts(Class::Universal, Aspect::Primitive, 0x05);
pub(crate) const BOOL: Tag = Tag::from_parts(Class::Universal, Aspect::Primitive, 0x01);

#[derive(Debug, PartialEq)]
pub(crate) enum DeserializeError {
    BadTag { expected: Tag, got: Tag },
    BufferTooShort,
    IndefiniteLength,
    IntegerTooLarge,
    InvalidOid,
    InvalidUtf8,
    InvalidValue,
}

pub(crate) trait Serialize {
    fn serialize(&self, buffer: &mut dyn VecExt);
}

pub(crate) trait Deserialize: Sized {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError>;
}

/// Represents the class of the tag
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub(crate) enum Class {
    Universal = 0,
    Application = 1,
    ContextSpecific = 2,
    Private = 3,
}

/// Represents whether or not the type is Primitive or Constructed
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub(crate) enum Aspect {
    Primitive = 0,
    Constructed = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Tag(u8);

impl Tag {
    /// Construct a new `Tag`
    pub(crate) const fn new(byte: u8) -> Self {
        Tag(byte)
    }

    pub(crate) const fn from_parts(class: Class, aspect: Aspect, tag: u8) -> Self {
        Tag((tag & 0x1F) | ((class as u8) << 6) | ((aspect as u8) << 5))
    }

    /// Get the `Class` of the tag
    pub(crate) fn class(self) -> Class {
        match self.0 >> 6 {
            0 => Class::Universal,
            1 => Class::Application,
            2 => Class::ContextSpecific,
            3 => Class::Private,
            _ => unreachable!("matching on two bits"),
        }
    }

    /// Get the `Aspect` of the tag
    pub(crate) fn aspect(self) -> Aspect {
        match (self.0 >> 5) & 1 {
            0 => Aspect::Primitive,
            1 => Aspect::Constructed,
            _ => unreachable!("matching on one bit"),
        }
    }

    /// Get the tag number
    pub(crate) fn number(self) -> u8 {
        self.0 & 0x1F
    }

    /// Get the raw value of the tag
    pub(crate) const fn raw(self) -> u8 {
        self.0
    }
}

impl Serialize for Tag {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        buffer.write_byte(self.raw());
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Length(u64);

impl Length {
    pub(crate) fn new(len: u64) -> Self {
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

pub(crate) struct Null;

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
pub(crate) struct Set<T>(Vec<T>);

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
