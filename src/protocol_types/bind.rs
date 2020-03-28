use super::*;

pub const BIND_REQUEST: Tag = Tag::from_parts(Class::Application, Aspect::Constructed, 0);

/// A Bind request providing any supplied authentication credentials
#[derive(Clone, Debug, PartialEq)]
pub struct BindRequest {
    /// LDAP version -- should always be 3
    pub version: u32,
    /// The DN of the user
    pub name: LdapDn,
    /// The authentication method (Simple or SASL)
    pub authentication: AuthenticationChoice,
}

impl Serialize for BindRequest {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        BIND_REQUEST.serialize(buffer);

        serialize_sequence(buffer, |buffer| {
            self.version.serialize(buffer);
            self.name.serialize(buffer);
            self.authentication.serialize(buffer);
        });
    }
}

const SIMPLE: Tag = Tag::from_parts(Class::ContextSpecific, Aspect::Primitive, 0);
const SASL: Tag = Tag::from_parts(Class::ContextSpecific, Aspect::Constructed, 3);

/// The authentication method in a Bind request
#[derive(Clone, Debug, PartialEq)]
pub enum AuthenticationChoice {
    /// Simple, password based authentication
    Simple(String),
    /// SASL authentication
    Sasl(SaslCredentials),
}

impl Serialize for AuthenticationChoice {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        match self {
            AuthenticationChoice::Simple(s) => {
                SIMPLE.serialize(buffer);
                let length = Length::new(s.as_bytes().len() as u64);
                length.serialize(buffer);
                buffer.write(s.as_bytes());
            }
            AuthenticationChoice::Sasl(_) => {
                SASL.serialize(buffer);
                todo!("sasl support");
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SaslCredentials {
    pub mechanism: String,
    pub credentials: Option<String>,
}

pub const BIND_RESPONSE: Tag = Tag::from_parts(Class::Application, Aspect::Constructed, 1);

/// The server response to a Bind request
#[derive(Clone, Debug, PartialEq)]
pub struct BindResponse {
    /// Result of the Bind request
    pub result: LdapResult,
    pub server_sasl_creds: Option<String>,
}

impl Deserialize for BindResponse {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError> {
        buffer.tag(BIND_RESPONSE)?;
        let length = Length::deserialize(buffer)?;
        let buffer = &mut buffer.slice(length)?;
        let result = ComponentsOfLdapResult::deserialize(buffer)?.into_inner();
        let server_sasl_creds =
            match buffer.peek_tag(Tag::from_parts(Class::ContextSpecific, Aspect::Primitive, 7)) {
                Ok(_) => {
                    buffer.byte()?;
                    let length = Length::deserialize(buffer)?;
                    let buffer = buffer.slice(length)?;
                    Some(
                        std::str::from_utf8(buffer)
                            .map(Into::into)
                            .map_err(|_| DeserializeError::InvalidUtf8)?,
                    )
                }
                Err(DeserializeError::BufferTooShort) => None,
                Err(DeserializeError::BadTag { .. }) => None,
                Err(e) => return Err(e),
            };

        Ok(Self { result, server_sasl_creds })
    }
}

pub const UNBIND_REQUEST: Tag = Tag::from_parts(Class::Application, Aspect::Primitive, 2);

/// A termination request to gracefully end communication
#[derive(Clone, Debug, PartialEq)]
pub struct UnbindRequest;

impl Serialize for UnbindRequest {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        UNBIND_REQUEST.serialize(buffer);
        Length::new(0).serialize(buffer);
    }
}
