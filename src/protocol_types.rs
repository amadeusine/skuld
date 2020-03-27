use crate::ber::{
    util::{serialize_sequence, ReadExt, VecExt},
    Aspect, Class, Deserialize, DeserializeError, Length, Null, Serialize, Tag, ENUMERATED_TAG,
    SEQUENCE_TAG,
};

const CONTROLS_TAG: Tag = Tag::from_parts(Class::ContextSpecific, Aspect::Constructed, 0);

#[derive(Clone, Debug, PartialEq)]
pub struct LdapMessage {
    pub message_id: i32,
    pub protocol_operation: ProtocolOperation,
    pub controls: Option<Vec<Control>>,
}

impl Serialize for LdapMessage {
    fn serialize(&self, buffer: &mut dyn VecExt) {
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

impl Deserialize for LdapMessage {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError> {
        buffer.tag(SEQUENCE_TAG)?;
        let length = Length::deserialize(buffer)?;
        let buffer = &mut buffer.slice(length)?;

        let message_id = i32::deserialize(buffer)?;
        let protocol_operation = ProtocolOperation::deserialize(buffer)?;
        let controls = match buffer.peek_tag(CONTROLS_TAG) {
            Ok(_) => todo!("controls deserialization"),
            Err(DeserializeError::BadTag { .. }) => None,
            Err(DeserializeError::BufferTooShort) => None,
            Err(e) => return Err(e),
        };

        Ok(Self { message_id, protocol_operation, controls })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ProtocolOperation {
    BindRequest(BindRequest),
    BindResponse(BindResponse),
    UnbindRequest(UnbindRequest),
    SearchRequest(SearchRequest),
}

impl Serialize for ProtocolOperation {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        match self {
            ProtocolOperation::BindRequest(br) => br.serialize(buffer),
            ProtocolOperation::BindResponse(_) => unreachable!("we don't serialize bind responses"),
            ProtocolOperation::UnbindRequest(ubr) => ubr.serialize(buffer),
            ProtocolOperation::SearchRequest(sr) => sr.serialize(buffer),
        }
    }
}

impl Deserialize for ProtocolOperation {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError> {
        match Tag::new(buffer.peek()?) {
            BIND_REQUEST_TAG => unreachable!("we don't deserialize bind requests"),
            BIND_RESPONSE_TAG => Ok(Self::BindResponse(BindResponse::deserialize(buffer)?)),
            UNBIND_REQUEST_TAG => unreachable!("we don't deserialize unbind requests"),
            _ => Err(DeserializeError::InvalidValue),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Control {
    pub control_type: LdapOid,
    pub criticality: bool,
    pub control_value: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct LdapOid(String);

impl Deserialize for LdapOid {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError> {
        let string = String::deserialize(buffer)?;

        // TODO: Validate string format

        Ok(LdapOid(string))
    }
}

impl Serialize for LdapOid {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        self.0.serialize(buffer);
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct LdapDn(pub String);

impl Deserialize for LdapDn {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError> {
        let string = String::deserialize(buffer)?;

        // TODO: Validate string format

        Ok(LdapDn(string))
    }
}

impl Serialize for LdapDn {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        self.0.serialize(buffer);
    }
}

type Uri = String;

#[derive(Clone, Debug, PartialEq)]
pub struct LdapResult {
    pub result_code: ResultCode,
    pub matched_dn: LdapDn,
    pub diagnostic_message: String,
    // Referral ::= SEQUENCE SIZE (1..MAX) OF uri URI
    //
    // URI ::= LDAPString     -- limited to characters permitted in URIs
    pub referral: Option<Vec<Uri>>,
}

impl Deserialize for LdapResult {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError> {
        buffer.tag(SEQUENCE_TAG)?;
        let result_code = ResultCode::deserialize(buffer)?;
        let matched_dn = LdapDn::deserialize(buffer)?;
        let diagnostic_message = String::deserialize(buffer)?;
        let referral = match buffer.peek_tag(Tag::from_parts(
            Class::ContextSpecific,
            Aspect::Constructed,
            3,
        )) {
            Ok(_) => todo!("referral deserialization"),
            Err(DeserializeError::BadTag { .. }) => None,
            Err(DeserializeError::BufferTooShort) => None,
            Err(e) => return Err(e),
        };

        Ok(Self { result_code, matched_dn, diagnostic_message, referral })
    }
}

pub struct ComponentsOfLdapResult(pub LdapResult);

impl ComponentsOfLdapResult {
    pub fn into_inner(self) -> LdapResult {
        self.0
    }
}

impl Deserialize for ComponentsOfLdapResult {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError> {
        let result_code = ResultCode::deserialize(buffer)?;
        let matched_dn = LdapDn::deserialize(buffer)?;
        let diagnostic_message = String::deserialize(buffer)?;
        let referral = match buffer.peek_tag(Tag::from_parts(
            Class::ContextSpecific,
            Aspect::Constructed,
            3,
        )) {
            Ok(_) => todo!("referral deserialization"),
            Err(DeserializeError::BadTag { .. }) => None,
            Err(DeserializeError::BufferTooShort) => None,
            Err(e) => return Err(e),
        };

        Ok(Self(LdapResult { result_code, matched_dn, diagnostic_message, referral }))
    }
}

#[derive(Clone, Debug, PartialEq)]
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
        buffer.tag(ENUMERATED_TAG)?;
        let length = Length::deserialize(buffer)?;
        let n = buffer.uint(length)?;

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
            _ => return Err(DeserializeError::InvalidValue),
        })
    }
}

const BIND_REQUEST_TAG: Tag = Tag::from_parts(Class::Application, Aspect::Constructed, 0);

#[derive(Clone, Debug, PartialEq)]
pub struct BindRequest {
    /// LDAP version -- should always be 3
    pub version: u32,
    pub name: LdapDn,
    pub authentication: AuthenticationChoice,
}

impl Serialize for BindRequest {
    fn serialize(&self, buffer: &mut dyn VecExt) {
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

#[derive(Clone, Debug, PartialEq)]
pub enum AuthenticationChoice {
    Simple(String),
    Sasl(SaslCredentials),
}

impl Serialize for AuthenticationChoice {
    fn serialize(&self, buffer: &mut dyn VecExt) {
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

#[derive(Clone, Debug, PartialEq)]
pub struct SaslCredentials {
    pub mechanism: String,
    pub credentials: Option<String>,
}

const BIND_RESPONSE_TAG: Tag = Tag::from_parts(Class::Application, Aspect::Constructed, 1);

#[derive(Clone, Debug, PartialEq)]
pub struct BindResponse {
    pub result: LdapResult,
    pub server_sasl_creds: Option<String>,
}

impl Deserialize for BindResponse {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError> {
        buffer.tag(BIND_RESPONSE_TAG)?;
        let length = Length::deserialize(buffer)?;
        let mut slice = buffer.slice(length)?;
        let result = ComponentsOfLdapResult::deserialize(&mut slice)?.into_inner();
        let server_sasl_creds =
            match buffer.peek_tag(Tag::from_parts(Class::ContextSpecific, Aspect::Primitive, 7)) {
                Ok(_) => {
                    buffer.byte()?;
                    let length = Length::deserialize(buffer)?;
                    let slice = buffer.slice(length)?;
                    Some(
                        std::str::from_utf8(slice)
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

const UNBIND_REQUEST_TAG: Tag = Tag::from_parts(Class::Application, Aspect::Primitive, 2);

#[derive(Clone, Debug, PartialEq)]
pub struct UnbindRequest;

impl Serialize for UnbindRequest {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        UNBIND_REQUEST_TAG.serialize(buffer);
        Length::new(0).serialize(buffer);
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SearchRequest {
    base_object: LdapDn,
    scope: Scope,
    deref_alias: DerefAlias,
    size_limit: i32,
    time_limit: i32,
    types_only: bool,
    filter: Filter,
    attributes: Vec<String>,
}

const SEARCH_REQUEST_TAG: Tag = Tag::from_parts(Class::Application, Aspect::Constructed, 3);

impl Serialize for SearchRequest {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        SEARCH_REQUEST_TAG.serialize(buffer);

        serialize_sequence(buffer, |buffer| {
            self.base_object.serialize(buffer);
            self.scope.serialize(buffer);
            self.deref_alias.serialize(buffer);
            self.size_limit.serialize(buffer);
            self.time_limit.serialize(buffer);
            self.types_only.serialize(buffer);
            self.filter.serialize(buffer);
            self.attributes.serialize(buffer);
        });
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
pub enum Scope {
    BaseObject = 0,
    SingleLevel = 1,
    WholeSubtree = 2,
}

impl Serialize for Scope {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        ENUMERATED_TAG.serialize(buffer);
        Length::new(1).serialize(buffer);
        buffer.write_byte(*self as u8)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
pub enum DerefAlias {
    NeverDerefAlias = 0,
    DerefInSearching = 1,
    DerefFindingBaseObj = 2,
    DerefAlways = 3,
}

impl Serialize for DerefAlias {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        ENUMERATED_TAG.serialize(buffer);
        Length::new(1).serialize(buffer);
        buffer.write_byte(*self as u8)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Filter {
    And(Vec<Filter>),
    Or(Vec<Filter>),
    Not(Box<Filter>),
    EqualityMatch(AttributeValueAssertion),
    Substrings(SubstringFilter),
    GreaterOrEqual(AttributeValueAssertion),
    LessOrEqual(AttributeValueAssertion),
    Present(AttributeDescription),
    ApproximateMatch(AttributeValueAssertion),
    ExtensibleMatch(MatchingRuleAssertion),
}

impl Serialize for Filter {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        const AND: Tag = Tag::from_parts(Class::ContextSpecific, Aspect::Constructed, 0);
        const OR: Tag = Tag::from_parts(Class::ContextSpecific, Aspect::Constructed, 1);
        const NOT: Tag = Tag::from_parts(Class::ContextSpecific, Aspect::Constructed, 2);
        const EQUALITY_MATCH: Tag = Tag::from_parts(Class::ContextSpecific, Aspect::Constructed, 3);
        const SUBSTRINGS: Tag = Tag::from_parts(Class::ContextSpecific, Aspect::Constructed, 4);
        const GREATER_OR_EQUAL: Tag =
            Tag::from_parts(Class::ContextSpecific, Aspect::Constructed, 5);
        const LESS_OR_EQUAL: Tag = Tag::from_parts(Class::ContextSpecific, Aspect::Constructed, 6);
        const PRESENT: Tag = Tag::from_parts(Class::ContextSpecific, Aspect::Primitive, 7);
        const APPROXIMATE_MATCH: Tag =
            Tag::from_parts(Class::ContextSpecific, Aspect::Constructed, 8);
        const EXTENSIBLE_MATCH: Tag =
            Tag::from_parts(Class::ContextSpecific, Aspect::Constructed, 9);

        match self {
            Filter::And(filters) => {
                AND.serialize(buffer);
                serialize_sequence(buffer, |buffer| {
                    for filter in filters {
                        filter.serialize(buffer);
                    }
                });
            }
            Filter::Or(filters) => {
                OR.serialize(buffer);
                serialize_sequence(buffer, |buffer| {
                    for filter in filters {
                        filter.serialize(buffer);
                    }
                });
            }
            Filter::Not(filter) => {
                NOT.serialize(buffer);
                serialize_sequence(buffer, |buffer| {
                    filter.serialize(buffer);
                });
            }
            Filter::EqualityMatch(ava) => {
                EQUALITY_MATCH.serialize(buffer);
                serialize_sequence(buffer, |buffer| {
                    ava.attribute_description.0.serialize(buffer);
                    ava.assertion_value.0.serialize(buffer);
                });
            }
            Filter::Substrings(substrs) => {
                SUBSTRINGS.serialize(buffer);
                serialize_sequence(buffer, |buffer| {
                    substrs.r#type.0.serialize(buffer);
                    substrs.substrings.serialize(buffer);
                });
            }
            Filter::GreaterOrEqual(ava) => {
                GREATER_OR_EQUAL.serialize(buffer);
                serialize_sequence(buffer, |buffer| {
                    ava.attribute_description.0.serialize(buffer);
                    ava.assertion_value.0.serialize(buffer);
                });
            }
            Filter::LessOrEqual(ava) => {
                LESS_OR_EQUAL.serialize(buffer);
                serialize_sequence(buffer, |buffer| {
                    ava.attribute_description.0.serialize(buffer);
                    ava.assertion_value.0.serialize(buffer);
                });
            }
            Filter::Present(ad) => {
                PRESENT.serialize(buffer);
                Length::new(ad.0.as_bytes().len() as u64).serialize(buffer);
                buffer.write(ad.0.as_bytes());
            }
            Filter::ApproximateMatch(ava) => {
                APPROXIMATE_MATCH.serialize(buffer);
                serialize_sequence(buffer, |buffer| {
                    ava.attribute_description.0.serialize(buffer);
                    ava.assertion_value.0.serialize(buffer);
                });
            }
            Filter::ExtensibleMatch(_) => todo!("extensible match serialization"),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct AssertionValue(String);

#[derive(Clone, Debug, PartialEq)]
pub struct AttributeDescription(String);

#[derive(Clone, Debug, PartialEq)]
pub struct SubstringFilter {
    r#type: AttributeDescription,
    substrings: Vec<Substring>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Substring {
    Initial(AssertionValue),
    Any(AssertionValue),
    Final(AssertionValue),
}

impl Serialize for Substring {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        const INITIAL: Tag = Tag::from_parts(Class::ContextSpecific, Aspect::Primitive, 0);
        const ANY: Tag = Tag::from_parts(Class::ContextSpecific, Aspect::Primitive, 1);
        const FINAL: Tag = Tag::from_parts(Class::ContextSpecific, Aspect::Primitive, 2);

        match self {
            Substring::Initial(av) => {
                INITIAL.serialize(buffer);
                Length::new(av.0.as_bytes().len() as u64).serialize(buffer);
                buffer.write(av.0.as_bytes());
            }
            Substring::Any(av) => {
                ANY.serialize(buffer);
                Length::new(av.0.as_bytes().len() as u64).serialize(buffer);
                buffer.write(av.0.as_bytes());
            }
            Substring::Final(av) => {
                FINAL.serialize(buffer);
                Length::new(av.0.as_bytes().len() as u64).serialize(buffer);
                buffer.write(av.0.as_bytes());
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct AttributeValueAssertion {
    attribute_description: AttributeDescription,
    assertion_value: AssertionValue,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MatchingRuleAssertion {
    matching_rule: Option<String>,
    r#type: Option<AttributeDescription>,
    match_value: AssertionValue,
    dn_attributes: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! s {
        () => {{
            String::new()
        }};
        ($s:literal) => {{
            $s.to_string()
        }};
    }

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
                0x30, 0x17, 0x02, 0x01, 0x01, 0x60,
                0x12, 0x02, 0x01, 0x03, 0x04, 0x07,
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

        assert_eq!(buffer, &[0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00]);
    }

    #[test]
    fn bind_response() {
        let message = b"\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x00\x04\x00\x04\x00";
        assert_eq!(
            LdapMessage::deserialize(&mut &message[..]),
            Ok(LdapMessage {
                message_id: 1,
                protocol_operation: ProtocolOperation::BindResponse(BindResponse {
                    result: LdapResult {
                        result_code: ResultCode::Success,
                        matched_dn: LdapDn(String::new()),
                        diagnostic_message: String::new(),
                        referral: None,
                    },
                    server_sasl_creds: None,
                }),
                controls: None,
            })
        );
    }

    #[test]
    fn unbind_request() {
        let mut buffer = Vec::new();
        UnbindRequest.serialize(&mut buffer);

        assert_eq!(buffer, &[0x42, 0x00])
    }

    #[test]
    fn search_request() {
        // and + substrings
        let message = LdapMessage {
            message_id: 2,
            protocol_operation: ProtocolOperation::SearchRequest(SearchRequest {
                base_object: LdapDn(s!()),
                scope: Scope::WholeSubtree,
                deref_alias: DerefAlias::NeverDerefAlias,
                size_limit: 0,
                time_limit: 0,
                types_only: false,
                filter: Filter::And(vec![
                    Filter::Substrings(SubstringFilter {
                        r#type: AttributeDescription(s!("cn")),
                        substrings: vec![Substring::Any(AssertionValue(s!("fred")))],
                    }),
                    Filter::EqualityMatch(AttributeValueAssertion {
                        attribute_description: AttributeDescription(s!("dn")),
                        assertion_value: AssertionValue(s!("joe")),
                    }),
                ]),
                attributes: vec![],
            }),
            controls: None,
        };

        let encoded = &[
            0x30, 0x33, 0x02, 0x01, 0x02, 0x63, 0x2e, 0x04, 0x00, 0x0a, 0x01, 0x02, 0x0a, 0x01,
            0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0x00, 0xa0, 0x19, 0xa4, 0x0c,
            0x04, 0x02, 0x63, 0x6e, 0x30, 0x06, 0x81, 0x04, 0x66, 0x72, 0x65, 0x64, 0xa3, 0x09,
            0x04, 0x02, 0x64, 0x6e, 0x04, 0x03, 0x6a, 0x6f, 0x65, 0x30, 0x00,
        ];

        let mut buffer = Vec::new();
        message.serialize(&mut buffer);
        assert_eq!(buffer, &encoded[..]);
    }
}
