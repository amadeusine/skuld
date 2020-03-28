use super::*;

pub const EXTENDED_REQUEST: Tag = Tag::from_parts(Class::Application, Aspect::Primitive, 23);

#[derive(Clone, Debug, PartialEq)]
pub struct ExtendedRequest {
    pub request_name: LdapOid,
    pub request_value: Option<String>,
}

impl Serialize for ExtendedRequest {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        const REQUEST_NAME: Tag = Tag::from_parts(Class::ContextSpecific, Aspect::Primitive, 0);
        const REQUEST_VALUE: Tag = Tag::from_parts(Class::ContextSpecific, Aspect::Primitive, 1);

        EXTENDED_REQUEST.serialize(buffer);
        serialize_sequence(buffer, |buffer| {
            REQUEST_NAME.serialize(buffer);
            Length::new(self.request_name.0.as_bytes().len() as u64).serialize(buffer);
            buffer.write(self.request_name.0.as_bytes());

            if let Some(request_value) = &self.request_value {
                REQUEST_VALUE.serialize(buffer);
                Length::new(request_value.as_bytes().len() as u64).serialize(buffer);
                buffer.write(request_value.as_bytes());
            }
        });
    }
}

pub const EXTENDED_RESPONSE: Tag = Tag::from_parts(Class::Application, Aspect::Primitive, 24);

#[derive(Clone, Debug, PartialEq)]
pub struct ExtendedResponse {
    pub result: LdapResult,
    pub response_name: Option<LdapOid>,
    pub response_value: Option<String>,
}

impl Deserialize for ExtendedResponse {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError> {
        const REQUEST_NAME: Tag = Tag::from_parts(Class::ContextSpecific, Aspect::Primitive, 10);
        const REQUEST_VALUE: Tag = Tag::from_parts(Class::ContextSpecific, Aspect::Primitive, 11);

        buffer.tag(EXTENDED_RESPONSE)?;
        let length = Length::deserialize(buffer)?;
        let buffer = &mut buffer.slice(length)?;

        let result = ComponentsOfLdapResult::deserialize(buffer)?.into_inner();

        let response_name = match buffer.peek_tag(REQUEST_NAME) {
            Ok(_) => {
                buffer.byte()?;
                let length = Length::deserialize(buffer)?;

                Some(LdapOid(
                    std::str::from_utf8(buffer.slice(length)?)
                        .map(Into::into)
                        .map_err(|_| DeserializeError::InvalidUtf8)?,
                ))
            }
            Err(DeserializeError::BufferTooShort) => None,
            Err(DeserializeError::BadTag { .. }) => None,
            Err(e) => return Err(e),
        };

        let response_value = match buffer.peek_tag(REQUEST_VALUE) {
            Ok(_) => {
                buffer.byte()?;
                let length = Length::deserialize(buffer)?;

                Some(
                    std::str::from_utf8(buffer.slice(length)?)
                        .map(Into::into)
                        .map_err(|_| DeserializeError::InvalidUtf8)?,
                )
            }
            Err(DeserializeError::BufferTooShort) => None,
            Err(DeserializeError::BadTag { .. }) => None,
            Err(e) => return Err(e),
        };

        Ok(Self { result, response_name, response_value })
    }
}

pub const INTERMEDIATE_RESPONSE: Tag = Tag::from_parts(Class::Application, Aspect::Primitive, 25);

#[derive(Clone, Debug, PartialEq)]
pub struct IntermediateResponse {
    pub response_name: Option<LdapOid>,
    pub response_value: Option<String>,
}

impl Deserialize for IntermediateResponse {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError> {
        const REQUEST_NAME: Tag = Tag::from_parts(Class::ContextSpecific, Aspect::Primitive, 0);
        const REQUEST_VALUE: Tag = Tag::from_parts(Class::ContextSpecific, Aspect::Primitive, 1);

        buffer.tag(INTERMEDIATE_RESPONSE)?;
        let length = Length::deserialize(buffer)?;
        let buffer = &mut buffer.slice(length)?;

        let response_name = match buffer.peek_tag(REQUEST_NAME) {
            Ok(_) => {
                buffer.byte()?;
                let length = Length::deserialize(buffer)?;

                Some(LdapOid(
                    std::str::from_utf8(buffer.slice(length)?)
                        .map(Into::into)
                        .map_err(|_| DeserializeError::InvalidUtf8)?,
                ))
            }
            Err(DeserializeError::BufferTooShort) => None,
            Err(DeserializeError::BadTag { .. }) => None,
            Err(e) => return Err(e),
        };

        let response_value = match buffer.peek_tag(REQUEST_VALUE) {
            Ok(_) => {
                buffer.byte()?;
                let length = Length::deserialize(buffer)?;

                Some(
                    std::str::from_utf8(buffer.slice(length)?)
                        .map(Into::into)
                        .map_err(|_| DeserializeError::InvalidUtf8)?,
                )
            }
            Err(DeserializeError::BufferTooShort) => None,
            Err(DeserializeError::BadTag { .. }) => None,
            Err(e) => return Err(e),
        };

        Ok(Self { response_name, response_value })
    }
}
