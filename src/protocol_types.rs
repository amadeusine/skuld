use crate::ber::{
    util::{serialize_sequence, ReadExt, VecExt},
    Aspect, Class, Deserialize, DeserializeError, Length, Serialize, Tag, SEQUENCE_TAG,
};

pub struct LdapMessage {
    message_id: i32,
    protocol_operation: ProtocolOperation,
    controls: Option<Vec<Control>>,
}

impl Serialize for LdapMessage {
    fn serialize(&self, buffer: &mut Vec<u8>) {
        SEQUENCE_TAG.serialize(buffer);

        serialize_sequence(buffer, |buffer| {
            self.message_id.serialize(buffer);
            self.protocol_operation.serialize(buffer);

            if let Some(_) = &self.controls {
                todo!("controls serialization")
            }
        });
    }
}

pub enum ProtocolOperation {
    BindRequest(BindRequest),
}

impl Serialize for ProtocolOperation {
    fn serialize(&self, buffer: &mut Vec<u8>) {
        match self {
            ProtocolOperation::BindRequest(br) => br.serialize(buffer),
        }
    }
}

pub struct Control {
    control_type: LdapOid,
    criticality: bool,
    control_value: Option<String>,
}

pub struct LdapOid(String);

impl Deserialize for LdapOid {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError> {
        let string = String::deserialize(buffer)?;

        // TODO: Validate string format

        Ok(LdapOid(string))
    }
}

impl Serialize for LdapOid {
    fn serialize(&self, buffer: &mut Vec<u8>) {
        self.0.serialize(buffer);
    }
}

pub struct LdapDn(String);

impl Deserialize for LdapDn {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError> {
        let string = String::deserialize(buffer)?;

        // TODO: Validate string format

        Ok(LdapDn(string))
    }
}

impl Serialize for LdapDn {
    fn serialize(&self, buffer: &mut Vec<u8>) {
        self.0.serialize(buffer);
    }
}

type Uri = String;

pub struct LdapResult {
    result_code: ResultCode,
    matched_dn: LdapDn,
    diagnostic_message: String,
    // Referral ::= SEQUENCE SIZE (1..MAX) OF uri URI
    //
    // URI ::= LDAPString     -- limited to characters permitted in URIs
    referral: Option<Vec<Uri>>,
}

impl Deserialize for LdapResult {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError> {
        buffer.tag(SEQUENCE_TAG)?;
        let result_code = ResultCode::deserialize(buffer)?;
        let matched_dn = LdapDn::deserialize(buffer)?;
        let diagnostic_message = String::deserialize(buffer)?;
        let referral =
            match buffer.tag(Tag::from_parts(Class::ContextSpecific, Aspect::Constructed, 3)) {
                Ok(_) => todo!("referral deserialization"),
                Err(DeserializeError::BadTag { .. }) => None,
                Err(DeserializeError::BufferTooShort) => None,
                Err(e) => return Err(e),
            };

        Ok(Self { result_code, matched_dn, diagnostic_message, referral })
    }
}

pub enum ResultCode {
    Success = 0,
    OperationsError = 1,
    ProtocolError = 2,
    TimeLimitExceeded = 3,
    SizeLimitExceeded = 4,
    CompareFalse = 5,
    CompareTrue = 6,
    AuthMethodNotSupported = 7,
    StrongerAuthRequired = 8,
    Referral = 10,
    AdminLimitExceeded = 11,
    UnavailableCriticalExtension = 12,
    ConfidentialityRequired = 13,
    SaslBindInProgress = 14,
    NoSuchAttribute = 16,
    UndefinedAttributeType = 17,
    InappropriateMatching = 18,
    ConstraintViolation = 19,
    AttributeOrValueExists = 20,
    InvalidAttributeSyntax = 21,
    NoSuchObject = 32,
    AliasProblem = 33,
    InvalidDnSyntax = 34,
    AliasDereferencingProblem = 36,
    InappropriateAuthentication = 48,
    InvalidCredentials = 49,
    InsufficientAccessRights = 50,
    Busy = 51,
    Unavailable = 52,
    UnwillingToPerform = 53,
    LoopDetect = 54,
    NamingViolation = 64,
    ObjectClassViolation = 65,
    NotAllowedOnNonLeaf = 66,
    NotAllowedOnRdn = 67,
    EntryAlreadyExists = 68,
    ObjectClassModsProhibited = 69,
    AffectsMultipleDsAs = 71,
    Other = 80,
}

impl Deserialize for ResultCode {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError> {
        let n = i32::deserialize(buffer)?;

        Ok(match n {
            0 => ResultCode::Success,
            1 => ResultCode::OperationsError,
            2 => ResultCode::ProtocolError,
            3 => ResultCode::TimeLimitExceeded,
            4 => ResultCode::SizeLimitExceeded,
            5 => ResultCode::CompareFalse,
            6 => ResultCode::CompareTrue,
            7 => ResultCode::AuthMethodNotSupported,
            8 => ResultCode::StrongerAuthRequired,
            10 => ResultCode::Referral,
            11 => ResultCode::AdminLimitExceeded,
            12 => ResultCode::UnavailableCriticalExtension,
            13 => ResultCode::ConfidentialityRequired,
            14 => ResultCode::SaslBindInProgress,
            16 => ResultCode::NoSuchAttribute,
            17 => ResultCode::UndefinedAttributeType,
            18 => ResultCode::InappropriateMatching,
            19 => ResultCode::ConstraintViolation,
            20 => ResultCode::AttributeOrValueExists,
            21 => ResultCode::InvalidAttributeSyntax,
            32 => ResultCode::NoSuchObject,
            33 => ResultCode::AliasProblem,
            34 => ResultCode::InvalidDnSyntax,
            36 => ResultCode::AliasDereferencingProblem,
            48 => ResultCode::InappropriateAuthentication,
            49 => ResultCode::InvalidCredentials,
            50 => ResultCode::InsufficientAccessRights,
            51 => ResultCode::Busy,
            52 => ResultCode::Unavailable,
            53 => ResultCode::UnwillingToPerform,
            54 => ResultCode::LoopDetect,
            64 => ResultCode::NamingViolation,
            65 => ResultCode::ObjectClassViolation,
            66 => ResultCode::NotAllowedOnNonLeaf,
            67 => ResultCode::NotAllowedOnRdn,
            68 => ResultCode::EntryAlreadyExists,
            69 => ResultCode::ObjectClassModsProhibited,
            71 => ResultCode::AffectsMultipleDsAs,
            80 => ResultCode::Other,
            _ => return Err(DeserializeError::InvaludValue),
        })
    }
}

const BIND_REQUEST_TAG: Tag = Tag::from_parts(Class::Application, Aspect::Constructed, 0);

pub struct BindRequest {
    /// LDAP version -- should always be 3
    version: u32,
    name: LdapDn,
    authentication: AuthenticationChoice,
}

impl Serialize for BindRequest {
    fn serialize(&self, buffer: &mut Vec<u8>) {
        BIND_REQUEST_TAG.serialize(buffer);

        serialize_sequence(buffer, |buffer| {
            self.version.serialize(buffer);
            self.name.serialize(buffer);
            self.authentication.serialize(buffer);
        });
    }
}

const SIMPLE_TAG: Tag = Tag::from_parts(Class::ContextSpecific, Aspect::Primitive, 0);
const SASL_TAG: Tag = Tag::from_parts(Class::ContextSpecific, Aspect::Constructed, 3);

pub enum AuthenticationChoice {
    Simple(String),
    Sasl(SaslCredentials),
}

impl Serialize for AuthenticationChoice {
    fn serialize(&self, buffer: &mut Vec<u8>) {
        match self {
            AuthenticationChoice::Simple(s) => {
                SIMPLE_TAG.serialize(buffer);
                let length = Length::new(s.as_bytes().len() as u64);
                length.serialize(buffer);
                buffer.write(s.as_bytes());
            }
            AuthenticationChoice::Sasl(_) => {
                SASL_TAG.serialize(buffer);
                todo!("sasl support");
            }
        }
    }
}

pub struct SaslCredentials {
    mechanism: String,
    credentials: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ldap_message() {
        let bind_request = BindRequest {
            version: 3,
            name: LdapDn(String::from("cn=hecc")),
            authentication: AuthenticationChoice::Simple(String::from("no u")),
        };

        let ldap_message = LdapMessage {
            message_id: 1,
            protocol_operation: ProtocolOperation::BindRequest(bind_request),
            controls: None,
        };

        let mut buffer = Vec::new();
        ldap_message.serialize(&mut buffer);

        #[rustfmt::skip]
        assert_eq!(
            buffer,
            &[
                0x30, 0x82, 0x00, 0x19, 0x02, 0x01, 0x01, 0x60,
                0x82, 0x00, 0x12, 0x02, 0x01, 0x03, 0x04, 0x07,
                b'c', b'n', b'=', b'h', b'e', b'c', b'c', 0x80,
                0x04, b'n', b'o', b' ', b'u',
            ]
        );
    }

    #[test]
    fn bind_request() {
        let bind_request = BindRequest {
            version: 3,
            name: LdapDn(String::from("")),
            authentication: AuthenticationChoice::Simple(String::from("")),
        };

        let mut buffer = Vec::new();
        bind_request.serialize(&mut buffer);

        assert_eq!(buffer, &[0x60, 0x82, 0x00, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00]);
    }
}
