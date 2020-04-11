mod abandon;
mod bind;
mod compare;
mod extended;
mod modify;
mod search;

use crate::ber::{
    util::{serialize_sequence, ReadExt, VecExt},
    Aspect, Class, Deserialize, DeserializeError, Length, Serialize, Set, Tag, BOOL, ENUMERATED,
    OCTET_STRING, SEQUENCE,
};

pub(crate) use {abandon::*, bind::*, compare::*, extended::*, modify::*, search::*};

pub(crate) type AssertionValue = String;
pub(crate) type AttributeValue = String;
pub(crate) type Uri = String;

/// A UTF-8 string that is constrained to <attributedescription>
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AttributeDescription(String);

impl Deserialize for AttributeDescription {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError> {
        let string = String::deserialize(buffer)?;

        // TODO: Validate string format

        Ok(AttributeDescription(string))
    }
}

impl Serialize for AttributeDescription {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        self.0.serialize(buffer);
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct LdapRelativeDn(pub(crate) String);

/// Wrapper type around a UTF-8 encoded string that is restricted to
/// <numericoid> -- which I assume to be of the format:
///
/// [012].(\d)+(\.\d+)+
///
/// Can't actually find the definition point for it
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct LdapOid(String);

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

/// Wrapper type around a UTF-8 encoded string that is restricted to
/// <distinguishedName> which seems to be a comma separated list of
/// <relativeDistinguishedName>
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct LdapDn(pub(crate) String);

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

const CONTROLS: Tag = Tag::from_parts(Class::ContextSpecific, Aspect::Constructed, 0);

/// The main packet type of the protocol
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct LdapMessage {
    /// A non-zero, session-unique message ID
    pub(crate) message_id: i32,
    /// The protocol operation
    pub(crate) protocol_operation: ProtocolOperation,
    /// Optional controls contained by this message
    pub(crate) controls: Option<Vec<Control>>,
}

impl Serialize for LdapMessage {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        SEQUENCE.serialize(buffer);

        serialize_sequence(buffer, |buffer| {
            self.message_id.serialize(buffer);
            self.protocol_operation.serialize(buffer);

            if let Some(controls) = &self.controls {
                CONTROLS.serialize(buffer);
                serialize_sequence(buffer, |buffer| {
                    for control in controls {
                        control.serialize(buffer);
                    }
                });
            }
        });
    }
}

impl Deserialize for LdapMessage {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError> {
        buffer.tag(SEQUENCE)?;
        let length = Length::deserialize(buffer)?;
        let buffer = &mut buffer.slice(length)?;

        let message_id = i32::deserialize(buffer)?;
        let protocol_operation = ProtocolOperation::deserialize(buffer)?;
        let controls = match buffer.peek_tag(CONTROLS) {
            Ok(_) => {
                buffer.tag(CONTROLS)?;
                let length = Length::deserialize(buffer)?;
                let buffer = &mut buffer.slice(length)?;
                let mut controls = Vec::new();

                while !buffer.is_empty() {
                    controls.push(Control::deserialize(buffer)?);
                }

                Some(controls)
            }
            Err(DeserializeError::BadTag { .. }) => None,
            Err(DeserializeError::BufferTooShort) => None,
            Err(e) => return Err(e),
        };

        Ok(Self { message_id, protocol_operation, controls })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum ProtocolOperation {
    BindRequest(BindRequest),
    BindResponse(BindResponse),
    UnbindRequest(UnbindRequest),
    SearchRequest(SearchRequest),
    SearchResultEntry(SearchResultEntry),
    SearchResultDone(SearchResultDone),
    SearchResultReference(SearchResultReference),
    ModifyRequest(ModifyRequest),
    ModifyResponse(ModifyResponse),
    AddRequest(AddRequest),
    AddResponse(AddResponse),
    DeleteRequest(DeleteRequest),
    DeleteResponse(DeleteResponse),
    ModifyDnRequest(ModifyDnRequest),
    ModifyDnResponse(ModifyDnResponse),
    CompareRequest(CompareRequest),
    CompareResponse(CompareResponse),
    AbandonRequest(AbandonRequest),
    ExtendedRequest(ExtendedRequest),
    ExtendedResponse(ExtendedResponse),
    IntermediateResponse(IntermediateResponse),
}

impl Serialize for ProtocolOperation {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        match self {
            ProtocolOperation::BindRequest(br) => br.serialize(buffer),
            ProtocolOperation::BindResponse(_) => unreachable!("we don't serialize bind responses"),
            ProtocolOperation::UnbindRequest(ubr) => ubr.serialize(buffer),
            ProtocolOperation::SearchRequest(sr) => sr.serialize(buffer),
            ProtocolOperation::SearchResultEntry(_) => {
                unreachable!("we don't serialize search result entries")
            }
            ProtocolOperation::SearchResultDone(_) => {
                unreachable!("we don't serialize search result dones")
            }
            ProtocolOperation::SearchResultReference(_) => {
                unreachable!("we don't serialize search result references")
            }
            ProtocolOperation::ModifyRequest(mr) => mr.serialize(buffer),
            ProtocolOperation::ModifyResponse(_) => {
                unreachable!("we don't serialize search modify responses")
            }
            ProtocolOperation::AddRequest(ar) => ar.serialize(buffer),
            ProtocolOperation::AddResponse(_) => {
                unreachable!("we don't serialize search add responses")
            }
            ProtocolOperation::DeleteRequest(dr) => dr.serialize(buffer),
            ProtocolOperation::DeleteResponse(_) => {
                unreachable!("we don't serialize search delete responses")
            }
            ProtocolOperation::ModifyDnRequest(mdr) => mdr.serialize(buffer),
            ProtocolOperation::ModifyDnResponse(_) => {
                unreachable!("we don't serialize search modify dn responses")
            }
            ProtocolOperation::CompareRequest(cr) => cr.serialize(buffer),
            ProtocolOperation::CompareResponse(_) => {
                unreachable!("we don't serialize compare responses")
            }
            ProtocolOperation::AbandonRequest(ar) => ar.serialize(buffer),
            ProtocolOperation::ExtendedRequest(er) => er.serialize(buffer),
            ProtocolOperation::ExtendedResponse(_) => {
                unreachable!("we don't serialize extended responses")
            }
            ProtocolOperation::IntermediateResponse(_) => {
                unreachable!("we don't serialize intermediate responses")
            }
        }
    }
}

impl Deserialize for ProtocolOperation {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError> {
        match Tag::new(buffer.peek()?) {
            BIND_RESPONSE => Ok(Self::BindResponse(BindResponse::deserialize(buffer)?)),
            SEARCH_RESULT_ENTRY => {
                Ok(Self::SearchResultEntry(SearchResultEntry::deserialize(buffer)?))
            }
            SEARCH_RESULT_DONE => {
                Ok(Self::SearchResultDone(SearchResultDone::deserialize(buffer)?))
            }
            SEARCH_RESULT_REFERENCE => {
                Ok(Self::SearchResultReference(SearchResultReference::deserialize(buffer)?))
            }
            MODIFY_RESPONSE => Ok(Self::ModifyResponse(ModifyResponse::deserialize(buffer)?)),
            ADD_RESPONSE => Ok(Self::AddResponse(AddResponse::deserialize(buffer)?)),
            DELETE_RESPONSE => Ok(Self::DeleteResponse(DeleteResponse::deserialize(buffer)?)),
            MODIFY_DN_RESPONSE => {
                Ok(Self::ModifyDnResponse(ModifyDnResponse::deserialize(buffer)?))
            }
            COMPARE_RESPONSE => Ok(Self::CompareResponse(CompareResponse::deserialize(buffer)?)),
            EXTENDED_RESPONSE => Ok(Self::ExtendedResponse(ExtendedResponse::deserialize(buffer)?)),
            INTERMEDIATE_RESPONSE => {
                Ok(Self::IntermediateResponse(IntermediateResponse::deserialize(buffer)?))
            }
            _ => Err(DeserializeError::InvalidValue),
        }
    }
}

/// As specified by RFC4511:
///
/// Controls provide a mechanism whereby the semantics and arguments of
/// existing LDAP operations may be extended.  One or more controls may
/// be attached to a single LDAP message.  A control only affects the
/// semantics of the message it is attached to.
///
/// Controls sent by clients are termed 'request controls', and those
/// sent by servers are termed 'response controls'.
/// ```notrust
/// Controls ::= SEQUENCE OF control Control
///   
/// Control ::= SEQUENCE {
///      controlType             LDAPOID,
///      criticality             BOOLEAN DEFAULT FALSE,
///      controlValue            OCTET STRING OPTIONAL }
/// ```
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Control {
    pub(crate) control_type: LdapOid,
    pub(crate) criticality: bool,
    pub(crate) control_value: Option<String>,
}

impl Serialize for Control {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        SEQUENCE.serialize(buffer);
        serialize_sequence(buffer, |buffer| {
            self.control_type.serialize(buffer);

            if self.criticality {
                self.criticality.serialize(buffer);
            }

            if let Some(control_value) = &self.control_value {
                control_value.serialize(buffer);
            }
        });
    }
}

impl Deserialize for Control {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError> {
        buffer.tag(SEQUENCE)?;
        let length = Length::deserialize(buffer)?;
        let buffer = &mut buffer.slice(length)?;

        let control_type = LdapOid::deserialize(buffer)?;
        let criticality = match buffer.peek_tag(BOOL) {
            Ok(_) => bool::deserialize(buffer)?,
            Err(DeserializeError::BadTag { .. }) => false,
            Err(DeserializeError::BufferTooShort) => false,
            Err(e) => return Err(e),
        };
        let control_value = match buffer.peek_tag(OCTET_STRING) {
            Ok(_) => Some(String::deserialize(buffer)?),
            Err(DeserializeError::BadTag { .. }) => None,
            Err(DeserializeError::BufferTooShort) => None,
            Err(e) => return Err(e),
        };

        Ok(Self { control_type, control_value, criticality })
    }
}

/// The result of an operation
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct LdapResult {
    /// Success or error code
    pub(crate) result_code: ResultCode,
    pub(crate) matched_dn: LdapDn,
    /// Additional diagnostic message
    pub(crate) diagnostic_message: String,
    // Referral ::= SEQUENCE SIZE (1..MAX) OF uri URI
    //
    // URI ::= LDAPString     -- limited to characters permitted in URIs
    pub(crate) referral: Option<Vec<Uri>>,
}

impl Deserialize for LdapResult {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError> {
        const REFERRAL: Tag = Tag::from_parts(Class::ContextSpecific, Aspect::Constructed, 3);

        buffer.tag(SEQUENCE)?;
        let result_code = ResultCode::deserialize(buffer)?;
        let matched_dn = LdapDn::deserialize(buffer)?;
        let diagnostic_message = String::deserialize(buffer)?;
        let referral = match buffer.peek_tag(REFERRAL) {
            Ok(_) => {
                buffer.tag(REFERRAL)?;
                let length = Length::deserialize(buffer)?;
                let buffer = &mut buffer.slice(length)?;
                let mut referrals = Vec::new();

                while !buffer.is_empty() {
                    // FIXME: replace with a wrapper type that validates the
                    // characters in the URI
                    referrals.push(String::deserialize(buffer)?);
                }

                Some(referrals)
            }
            Err(DeserializeError::BadTag { .. }) => None,
            Err(DeserializeError::BufferTooShort) => None,
            Err(e) => return Err(e),
        };

        Ok(Self { result_code, matched_dn, diagnostic_message, referral })
    }
}

/// A wrapper around `LdapResult` that deserializes just the fields as some
/// operations return `COMPONENTS OF LDAPResult`
pub(crate) struct ComponentsOfLdapResult(LdapResult);

impl ComponentsOfLdapResult {
    pub(crate) fn into_inner(self) -> LdapResult {
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

/// The result code of the operation, non-error codes are marked as such
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum ResultCode {
    /// No error occurred
    Success = 0,
    /// The operation is not properly sequenced with relation to other
    /// operations
    OperationsError = 1,
    /// The server received data that is not well-formed
    ///
    /// OR
    ///
    /// When returned from a Bind operation, this error code can be used to
    /// indicate lack of support for the requested protocol version
    ///
    /// OR
    ///
    /// When returned from an Extended operation, this error code can be used to
    /// indicate the server does not support the Extended operation associated
    /// with the request name
    ///
    /// OR
    ///
    /// When returned from a request with multiple controls, this error code can
    /// be used to indicate that the server cannot ignore the order of the
    /// controls as specified or that the combination of controls is invalid or
    /// unspecified
    ProtocolError = 2,
    /// The time limit specified by the client was exceeded before the operation
    /// could complete
    TimeLimitExceeded = 3,
    /// The size limit specified by the client was exceeded before the operation
    /// could complete
    SizeLimitExceeded = 4,
    /// (Non-error) The compare operation completed but the assertion evaluated
    /// to `FALSE` or `Undefined`
    CompareFalse = 5,
    /// (Non-error) The compare operation completed but the assertion evaluated
    /// to `TRUE`
    CompareTrue = 6,
    /// The server does not support the authentication method or mechanism
    AuthMethodNotSupported = 7,
    /// The server requires a stronger authentication to complete the operation
    ///
    /// OR
    ///
    /// When returned in a Notice of Disconnection operation, this error code
    /// can be used to represent the security association between the client and
    /// server unexpectedly failed or has been compromised
    StrongerAuthRequired = 8,
    /// (Non-error) A referral must be chased to complete the operation
    Referral = 10,
    /// An administration limit has been exceeded
    AdminLimitExceeded = 11,
    /// A critical control in the request was not recognized
    UnavailableCriticalExtension = 12,
    /// Data confidentiality protections are required
    ConfidentialityRequired = 13,
    /// (Non-error) The server requires the client to send a new bind request
    /// with the same SASL mechanism to continue authentication
    SaslBindInProgress = 14,
    /// The named entry does not contain the specified attribute or attribute
    /// value
    NoSuchAttribute = 16,
    /// A request field contains an unrecognized attribute description
    UndefinedAttributeType = 17,
    /// An attempt was made to use a matching rule not defined for an attribute
    /// type
    InappropriateMatching = 18,
    /// An attribute value was supplied that does not conform to the contraints
    /// specified by it's data model
    ConstraintViolation = 19,
    /// An attribute or attribute value already exists
    AttributeOrValueExists = 20,
    /// An invalid attribute value was supplied
    InvalidAttributeSyntax = 21,
    /// The requested object does not exist in the DIT
    NoSuchObject = 32,
    /// An alias problem has occurred
    AliasProblem = 33,
    /// The supplied DN or a supplied relative DN is malformed
    InvalidDnSyntax = 34,
    /// A problem occurred during dereferencing an alias
    AliasDereferencingProblem = 36,
    /// The server requires credentials to be provided
    InappropriateAuthentication = 48,
    /// The provided credentials are invalid
    InvalidCredentials = 49,
    /// The provided credentials have insufficient access to perform the
    /// requested operation
    InsufficientAccessRights = 50,
    /// The server is too busy to service the operation
    Busy = 51,
    /// The server is shutting down or a subsystem necessary to complete the
    /// operation is offline
    Unavailable = 52,
    /// The server is unwilling to perform the requested operation
    UnwillingToPerform = 53,
    /// The server detected an internal loop
    LoopDetect = 54,
    /// The entry's name violates naming restrictions
    NamingViolation = 64,
    /// The entry violates object class restrictions
    ObjectClassViolation = 65,
    /// The requested operation is inappropriate on a non-leaf entry
    NotAllowedOnNonLeaf = 66,
    /// The operation is inappropriately attempting to remove a value that forms
    /// the entry's relative DN
    NotAllowedOnRdn = 67,
    /// The requested operation cannot complete because the target entry already
    /// exists
    EntryAlreadyExists = 68,
    /// An attempt to modify the object class(es) of an entry's `objectClass`
    /// attribute value is prohibited
    ObjectClassModsProhibited = 69,
    /// The requested operation cannot be performed as it would affect multiple
    /// servers (DSAs)
    AffectsMultipleDSAs = 71,
    /// The server encountered an internal error
    Other = 80,
}

impl Deserialize for ResultCode {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError> {
        buffer.tag(ENUMERATED)?;
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
            71 => ResultCode::AffectsMultipleDSAs,
            80 => ResultCode::Other,
            _ => return Err(DeserializeError::InvalidValue),
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AttributeValueAssertion {
    /// The attribute description to match on
    pub(crate) attribute_description: AttributeDescription,
    /// The attribute value to match on
    pub(crate) assertion_value: AssertionValue,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct PartialAttribute {
    /// The attribute description
    pub(crate) r#type: AttributeDescription,
    /// Zero or more attribute values associated with the attribute description
    pub(crate) vals: Set<AttributeValue>,
}

impl Deserialize for PartialAttribute {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError> {
        buffer.tag(SEQUENCE)?;
        let length = Length::deserialize(buffer)?;
        let buffer = &mut buffer.slice(length)?;

        let r#type = AttributeDescription::deserialize(buffer)?;
        let vals = Set::deserialize(buffer)?;

        Ok(Self { r#type, vals })
    }
}

impl Serialize for PartialAttribute {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        SEQUENCE.serialize(buffer);
        serialize_sequence(buffer, |buffer| {
            self.r#type.serialize(buffer);
            self.vals.serialize(buffer);
        });
    }
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

        assert_eq!(
            buffer,
            &[
                0x30, 0x17, 0x02, 0x01, 0x01, 0x60, 0x12, 0x02, 0x01, 0x03, 0x04, 0x07, b'c', b'n',
                b'=', b'h', b'e', b'c', b'c', 0x80, 0x04, b'n', b'o', b' ', b'u',
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
        let message =
            &[0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00];

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
                        substrings: vec![Substring::Any(s!("fred"))],
                    }),
                    Filter::EqualityMatch(AttributeValueAssertion {
                        attribute_description: AttributeDescription(s!("dn")),
                        assertion_value: s!("joe"),
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

        let message = LdapMessage {
            message_id: 2,
            protocol_operation: ProtocolOperation::SearchRequest(SearchRequest {
                base_object: LdapDn(s!("dc=example,dc=org")),
                scope: Scope::WholeSubtree,
                deref_alias: DerefAlias::NeverDerefAlias,
                size_limit: 0,
                time_limit: 0,
                types_only: false,
                filter: Filter::ExtensibleMatch(MatchingRuleAssertion {
                    matching_rule: Some(s!("2.4.6.8.10")),
                    r#type: Some(AttributeDescription(s!("sn"))),
                    match_value: s!("Barney Rubble"),
                    dn_attributes: true,
                }),
                attributes: vec![],
            }),
            controls: None,
        };

        let encoded = &[
            0x30, 0x4d, 0x02, 0x01, 0x02, 0x63, 0x48, 0x04, 0x11, 0x64, 0x63, 0x3d, 0x65, 0x78,
            0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2c, 0x64, 0x63, 0x3d, 0x6f, 0x72, 0x67, 0x0a, 0x01,
            0x02, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0x00, 0xa9,
            0x22, 0x81, 0x0a, 0x32, 0x2e, 0x34, 0x2e, 0x36, 0x2e, 0x38, 0x2e, 0x31, 0x30, 0x82,
            0x02, 0x73, 0x6e, 0x83, 0x0d, 0x42, 0x61, 0x72, 0x6e, 0x65, 0x79, 0x20, 0x52, 0x75,
            0x62, 0x62, 0x6c, 0x65, 0x84, 0x01, 0xff, 0x30, 0x00,
        ];

        let mut buffer = Vec::new();
        message.serialize(&mut buffer);
        assert_eq!(buffer, &encoded[..]);

        let message = LdapMessage {
            message_id: 2,
            protocol_operation: ProtocolOperation::SearchRequest(SearchRequest {
                base_object: LdapDn(s!("dc=example,dc=org")),
                scope: Scope::WholeSubtree,
                deref_alias: DerefAlias::NeverDerefAlias,
                size_limit: 0,
                time_limit: 0,
                types_only: false,
                filter: Filter::ExtensibleMatch(MatchingRuleAssertion {
                    matching_rule: Some(s!("2.4.6.8.10")),
                    r#type: Some(AttributeDescription(s!("sn"))),
                    match_value: s!("Barney Rubble"),
                    dn_attributes: false,
                }),
                attributes: vec![],
            }),
            controls: None,
        };

        let encoded = &[
            0x30, 0x4a, 0x02, 0x01, 0x02, 0x63, 0x45, 0x04, 0x11, 0x64, 0x63, 0x3d, 0x65, 0x78,
            0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2c, 0x64, 0x63, 0x3d, 0x6f, 0x72, 0x67, 0x0a, 0x01,
            0x02, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0x00, 0xa9,
            0x1f, 0x81, 0x0a, 0x32, 0x2e, 0x34, 0x2e, 0x36, 0x2e, 0x38, 0x2e, 0x31, 0x30, 0x82,
            0x02, 0x73, 0x6e, 0x83, 0x0d, 0x42, 0x61, 0x72, 0x6e, 0x65, 0x79, 0x20, 0x52, 0x75,
            0x62, 0x62, 0x6c, 0x65, 0x30, 0x00,
        ];

        let mut buffer = Vec::new();
        message.serialize(&mut buffer);
        assert_eq!(buffer, &encoded[..]);

        let message = LdapMessage {
            message_id: 2,
            protocol_operation: ProtocolOperation::SearchRequest(SearchRequest {
                base_object: LdapDn(s!("dc=example,dc=org")),
                scope: Scope::WholeSubtree,
                deref_alias: DerefAlias::NeverDerefAlias,
                size_limit: 0,
                time_limit: 0,
                types_only: false,
                filter: Filter::And(vec![
                    Filter::EqualityMatch(AttributeValueAssertion {
                        attribute_description: AttributeDescription(s!("objectClass")),
                        assertion_value: s!("Person"),
                    }),
                    Filter::Or(vec![
                        Filter::EqualityMatch(AttributeValueAssertion {
                            attribute_description: AttributeDescription(s!("sn")),
                            assertion_value: s!("Jensen"),
                        }),
                        Filter::Substrings(SubstringFilter {
                            r#type: AttributeDescription(s!("cn")),
                            substrings: vec![Substring::Initial(s!("Babs J"))],
                        }),
                    ]),
                ]),
                attributes: vec![],
            }),
            controls: None,
        };

        let encoded = &[
            0x30, 0x62, 0x02, 0x01, 0x02, 0x63, 0x5d, 0x04, 0x11, 0x64, 0x63, 0x3d, 0x65, 0x78,
            0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2c, 0x64, 0x63, 0x3d, 0x6f, 0x72, 0x67, 0x0a, 0x01,
            0x02, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0x00, 0xa0,
            0x37, 0xa3, 0x15, 0x04, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61,
            0x73, 0x73, 0x04, 0x06, 0x50, 0x65, 0x72, 0x73, 0x6f, 0x6e, 0xa1, 0x1e, 0xa3, 0x0c,
            0x04, 0x02, 0x73, 0x6e, 0x04, 0x06, 0x4a, 0x65, 0x6e, 0x73, 0x65, 0x6e, 0xa4, 0x0e,
            0x04, 0x02, 0x63, 0x6e, 0x30, 0x08, 0x80, 0x06, 0x42, 0x61, 0x62, 0x73, 0x20, 0x4a,
            0x30, 0x00,
        ];

        let mut buffer = Vec::new();
        message.serialize(&mut buffer);
        assert_eq!(buffer, &encoded[..]);

        let message = LdapMessage {
            message_id: 2,
            protocol_operation: ProtocolOperation::SearchRequest(SearchRequest {
                base_object: LdapDn(s!("dc=example,dc=org")),
                scope: Scope::WholeSubtree,
                deref_alias: DerefAlias::NeverDerefAlias,
                size_limit: 0,
                time_limit: 0,
                types_only: false,
                filter: Filter::Present(AttributeDescription(s!("o"))),
                attributes: vec![],
            }),
            controls: None,
        };

        let encoded = &[
            0x30, 0x2c, 0x02, 0x01, 0x02, 0x63, 0x27, 0x04, 0x11, 0x64, 0x63, 0x3d, 0x65, 0x78,
            0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2c, 0x64, 0x63, 0x3d, 0x6f, 0x72, 0x67, 0x0a, 0x01,
            0x02, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0x00, 0x87,
            0x01, 0x6f, 0x30, 0x00,
        ];

        let mut buffer = Vec::new();
        message.serialize(&mut buffer);
        assert_eq!(buffer, &encoded[..]);

        let message = LdapMessage {
            message_id: 2,
            protocol_operation: ProtocolOperation::SearchRequest(SearchRequest {
                base_object: LdapDn(s!("dc=example,dc=org")),
                scope: Scope::WholeSubtree,
                deref_alias: DerefAlias::NeverDerefAlias,
                size_limit: 0,
                time_limit: 0,
                types_only: false,
                filter: Filter::And(vec![
                    Filter::Not(Box::new(Filter::EqualityMatch(AttributeValueAssertion {
                        attribute_description: AttributeDescription(s!("org")),
                        assertion_value: s!("Example Co"),
                    }))),
                    Filter::And(vec![
                        Filter::GreaterOrEqual(AttributeValueAssertion {
                            attribute_description: AttributeDescription(s!("count")),
                            assertion_value: s!("1"),
                        }),
                        Filter::LessOrEqual(AttributeValueAssertion {
                            attribute_description: AttributeDescription(s!("losses")),
                            assertion_value: s!("5"),
                        }),
                        Filter::ApproximateMatch(AttributeValueAssertion {
                            attribute_description: AttributeDescription(s!("name")),
                            assertion_value: s!("Pickle Rick"),
                        }),
                    ]),
                ]),
                attributes: vec![],
            }),
            controls: None,
        };

        let encoded = &[
            0x30, 0x70, 0x02, 0x01, 0x02, 0x63, 0x6b, 0x04, 0x11, 0x64, 0x63, 0x3d, 0x65, 0x78,
            0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2c, 0x64, 0x63, 0x3d, 0x6f, 0x72, 0x67, 0x0a, 0x01,
            0x02, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0x00, 0xa0,
            0x45, 0xa2, 0x13, 0xa3, 0x11, 0x04, 0x03, 0x6f, 0x72, 0x67, 0x04, 0x0a, 0x45, 0x78,
            0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x43, 0x6f, 0xa0, 0x2e, 0xa5, 0x0a, 0x04, 0x05,
            0x63, 0x6f, 0x75, 0x6e, 0x74, 0x04, 0x01, 0x31, 0xa6, 0x0b, 0x04, 0x06, 0x6c, 0x6f,
            0x73, 0x73, 0x65, 0x73, 0x04, 0x01, 0x35, 0xa8, 0x13, 0x04, 0x04, 0x6e, 0x61, 0x6d,
            0x65, 0x04, 0x0b, 0x50, 0x69, 0x63, 0x6b, 0x6c, 0x65, 0x20, 0x52, 0x69, 0x63, 0x6b,
            0x30, 0x00,
        ];

        let mut buffer = Vec::new();
        message.serialize(&mut buffer);
        assert_eq!(buffer, &encoded[..]);
    }

    #[test]
    fn search_result_entry() {
        let message = &[
            0x30, 0x6e, 0x02, 0x01, 0x02, 0x64, 0x69, 0x04, 0x11, 0x64, 0x63, 0x3d, 0x65, 0x78,
            0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2c, 0x64, 0x63, 0x3d, 0x6f, 0x72, 0x67, 0x30, 0x54,
            0x30, 0x2c, 0x04, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x43, 0x6c, 0x61, 0x73,
            0x73, 0x31, 0x1d, 0x04, 0x03, 0x74, 0x6f, 0x70, 0x04, 0x08, 0x64, 0x63, 0x4f, 0x62,
            0x6a, 0x65, 0x63, 0x74, 0x04, 0x0c, 0x6f, 0x72, 0x67, 0x61, 0x6e, 0x69, 0x7a, 0x61,
            0x74, 0x69, 0x6f, 0x6e, 0x30, 0x13, 0x04, 0x01, 0x6f, 0x31, 0x0e, 0x04, 0x0c, 0x45,
            0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x30, 0x0f, 0x04,
            0x02, 0x64, 0x63, 0x31, 0x09, 0x04, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        ];

        assert_eq!(
            LdapMessage::deserialize(&mut &message[..]),
            Ok(LdapMessage {
                message_id: 2,
                protocol_operation: ProtocolOperation::SearchResultEntry(SearchResultEntry {
                    object_name: LdapDn(s!("dc=example,dc=org")),
                    attribute_list: vec![
                        PartialAttribute {
                            r#type: AttributeDescription(s!("objectClass")),
                            vals: Set::from(vec![s!("top"), s!("dcObject"), s!("organization"),]),
                        },
                        PartialAttribute {
                            r#type: AttributeDescription(s!("o")),
                            vals: Set::from(vec![s!("Example Inc.")]),
                        },
                        PartialAttribute {
                            r#type: AttributeDescription(s!("dc")),
                            vals: Set::from(vec![s!("example")]),
                        }
                    ],
                }),
                controls: None,
            })
        )
    }

    #[test]
    fn search_result_done() {
        let message =
            &[0x30, 0x0c, 0x02, 0x01, 0x02, 0x65, 0x07, 0x0a, 0x01, 0x20, 0x04, 0x00, 0x04, 0x00];

        assert_eq!(
            LdapMessage::deserialize(&mut &message[..]),
            Ok(LdapMessage {
                message_id: 2,
                protocol_operation: ProtocolOperation::SearchResultDone(SearchResultDone {
                    result: LdapResult {
                        result_code: ResultCode::NoSuchObject,
                        matched_dn: LdapDn(s!()),
                        diagnostic_message: s!(),
                        referral: None,
                    }
                }),
                controls: None,
            })
        );
    }

    #[test]
    fn modify_request() {
        let packet = &[
            0x30, 0x81, 0x8a, 0x02, 0x01, 0x02, 0x66, 0x81, 0x84, 0x04, 0x1a, 0x63, 0x6e, 0x3d,
            0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2c, 0x64, 0x63, 0x3d, 0x65, 0x78, 0x61, 0x6d, 0x70,
            0x6c, 0x65, 0x2c, 0x64, 0x63, 0x3d, 0x63, 0x6f, 0x6d, 0x30, 0x66, 0x30, 0x31, 0x0a,
            0x01, 0x02, 0x30, 0x2c, 0x04, 0x0b, 0x64, 0x65, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74,
            0x69, 0x6f, 0x6e, 0x31, 0x1d, 0x04, 0x1b, 0x4d, 0x6f, 0x64, 0x69, 0x66, 0x69, 0x65,
            0x64, 0x20, 0x4c, 0x44, 0x41, 0x50, 0x20, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x69, 0x73,
            0x74, 0x72, 0x61, 0x74, 0x6f, 0x72, 0x30, 0x10, 0x0a, 0x01, 0x00, 0x30, 0x0b, 0x04,
            0x04, 0x68, 0x65, 0x63, 0x63, 0x31, 0x03, 0x04, 0x01, 0x75, 0x30, 0x11, 0x0a, 0x01,
            0x00, 0x30, 0x0c, 0x04, 0x03, 0x6e, 0x6f, 0x75, 0x31, 0x05, 0x04, 0x03, 0x79, 0x65,
            0x73, 0x30, 0x0c, 0x0a, 0x01, 0x01, 0x30, 0x07, 0x04, 0x03, 0x6e, 0x6f, 0x75, 0x31,
            0x00,
        ];

        let message = LdapMessage {
            message_id: 2,
            protocol_operation: ProtocolOperation::ModifyRequest(ModifyRequest {
                object: LdapDn(s!("cn=admin,dc=example,dc=com")),
                changes: vec![
                    Change {
                        operation: ModifyOperation::Replace,
                        modification: PartialAttribute {
                            r#type: AttributeDescription(s!("description")),
                            vals: Set::from(vec![s!("Modified LDAP administrator")]),
                        },
                    },
                    Change {
                        operation: ModifyOperation::Add,
                        modification: PartialAttribute {
                            r#type: AttributeDescription(s!("hecc")),
                            vals: Set::from(vec![s!("u")]),
                        },
                    },
                    Change {
                        operation: ModifyOperation::Add,
                        modification: PartialAttribute {
                            r#type: AttributeDescription(s!("nou")),
                            vals: Set::from(vec![s!("yes")]),
                        },
                    },
                    Change {
                        operation: ModifyOperation::Delete,
                        modification: PartialAttribute {
                            r#type: AttributeDescription(s!("nou")),
                            vals: Set::from(vec![]),
                        },
                    },
                ],
            }),
            controls: None,
        };

        let mut buffer = Vec::new();
        message.serialize(&mut buffer);

        assert_eq!(buffer, &packet[..]);
    }

    #[test]
    fn modify_response() {
        let message = &[
            0x30, 0x2a, 0x02, 0x01, 0x02, 0x67, 0x25, 0x0a, 0x01, 0x11, 0x04, 0x00, 0x04, 0x1e,
            0x68, 0x65, 0x63, 0x63, 0x3a, 0x20, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74,
            0x65, 0x20, 0x74, 0x79, 0x70, 0x65, 0x20, 0x75, 0x6e, 0x64, 0x65, 0x66, 0x69, 0x6e,
            0x65, 0x64,
        ];

        assert_eq!(
            LdapMessage::deserialize(&mut &message[..]),
            Ok(LdapMessage {
                message_id: 2,
                protocol_operation: ProtocolOperation::ModifyResponse(ModifyResponse {
                    result: LdapResult {
                        result_code: ResultCode::UndefinedAttributeType,
                        matched_dn: LdapDn(s!()),
                        diagnostic_message: s!("hecc: attribute type undefined"),
                        referral: None,
                    }
                }),
                controls: None,
            })
        )
    }

    #[test]
    fn add_request() {
        let packet = &[
            0x30, 0x31, 0x02, 0x01, 0x02, 0x68, 0x2c, 0x04, 0x1a, 0x63, 0x6e, 0x3d, 0x61, 0x64,
            0x6d, 0x69, 0x6e, 0x2c, 0x64, 0x63, 0x3d, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
            0x2c, 0x64, 0x63, 0x3d, 0x63, 0x6f, 0x6d, 0x30, 0x0e, 0x30, 0x0c, 0x04, 0x03, 0x6e,
            0x6f, 0x75, 0x31, 0x05, 0x04, 0x03, 0x79, 0x65, 0x73,
        ];
        let message = LdapMessage {
            message_id: 2,
            protocol_operation: ProtocolOperation::AddRequest(AddRequest {
                entry: LdapDn(s!("cn=admin,dc=example,dc=com")),
                attributes: vec![Attribute {
                    r#type: AttributeDescription(s!("nou")),
                    vals: Set::from(vec![s!("yes")]),
                }],
            }),
            controls: None,
        };

        let mut buffer = Vec::new();
        message.serialize(&mut buffer);

        assert_eq!(buffer, &packet[..]);
    }

    #[test]
    fn add_response() {
        let message = &[
            0x30, 0x29, 0x02, 0x01, 0x02, 0x69, 0x24, 0x0a, 0x01, 0x11, 0x04, 0x00, 0x04, 0x1d,
            0x6e, 0x6f, 0x75, 0x3a, 0x20, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65,
            0x20, 0x74, 0x79, 0x70, 0x65, 0x20, 0x75, 0x6e, 0x64, 0x65, 0x66, 0x69, 0x6e, 0x65,
            0x64,
        ];

        assert_eq!(
            LdapMessage::deserialize(&mut &message[..]),
            Ok(LdapMessage {
                message_id: 2,
                protocol_operation: ProtocolOperation::AddResponse(AddResponse {
                    result: LdapResult {
                        result_code: ResultCode::UndefinedAttributeType,
                        matched_dn: LdapDn(s!()),
                        diagnostic_message: s!("nou: attribute type undefined"),
                        referral: None,
                    }
                }),
                controls: None,
            })
        );
    }

    #[test]
    fn delete_request() {
        let packet = &[
            0x30, 0x22, 0x02, 0x01, 0x02, 0x4a, 0x1d, 0x63, 0x6e, 0x3d, 0x73, 0x6f, 0x6d, 0x65,
            0x75, 0x73, 0x65, 0x72, 0x2c, 0x64, 0x63, 0x3d, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
            0x65, 0x2c, 0x64, 0x63, 0x3d, 0x63, 0x6f, 0x6d,
        ];

        let message = LdapMessage {
            message_id: 2,
            protocol_operation: ProtocolOperation::DeleteRequest(DeleteRequest {
                entry: LdapDn(s!("cn=someuser,dc=example,dc=com")),
            }),
            controls: None,
        };

        let mut buffer = Vec::new();
        message.serialize(&mut buffer);

        assert_eq!(buffer, &packet[..]);
    }

    #[test]
    fn delete_response() {
        let message = &[
            0x30, 0x28, 0x02, 0x01, 0x02, 0x6b, 0x23, 0x0a, 0x01, 0x35, 0x04, 0x00, 0x04, 0x1c,
            0x6e, 0x6f, 0x20, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x20, 0x73, 0x75, 0x70, 0x65,
            0x72, 0x69, 0x6f, 0x72, 0x20, 0x6b, 0x6e, 0x6f, 0x77, 0x6c, 0x65, 0x64, 0x67, 0x65,
        ];

        assert_eq!(
            LdapMessage::deserialize(&mut &message[..]),
            Ok(LdapMessage {
                message_id: 2,
                protocol_operation: ProtocolOperation::DeleteResponse(DeleteResponse {
                    result: LdapResult {
                        result_code: ResultCode::UnwillingToPerform,
                        matched_dn: LdapDn(s!()),
                        diagnostic_message: s!("no global superior knowledge"),
                        referral: None,
                    }
                }),
                controls: None,
            })
        );
    }

    #[test]
    fn modify_dn_request() {
        let packet = &[
            0x30, 0x49, 0x02, 0x01, 0x02, 0x6c, 0x44, 0x04, 0x1d, 0x63, 0x6e, 0x3d, 0x73, 0x6f,
            0x6d, 0x65, 0x75, 0x73, 0x65, 0x72, 0x2c, 0x64, 0x63, 0x3d, 0x65, 0x78, 0x61, 0x6d,
            0x70, 0x6c, 0x65, 0x2c, 0x64, 0x63, 0x3d, 0x63, 0x6f, 0x6d, 0x04, 0x0c, 0x75, 0x69,
            0x64, 0x3d, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x75, 0x73, 0x72, 0x01, 0x01, 0x00, 0x80,
            0x12, 0x64, 0x63, 0x3d, 0x64, 0x6f, 0x65, 0x73, 0x6e, 0x74, 0x2c, 0x64, 0x63, 0x3d,
            0x65, 0x78, 0x69, 0x73, 0x74,
        ];

        let message = LdapMessage {
            message_id: 2,
            protocol_operation: ProtocolOperation::ModifyDnRequest(ModifyDnRequest {
                entry: LdapDn(s!("cn=someuser,dc=example,dc=com")),
                new_rdn: LdapRelativeDn(s!("uid=test.usr")),
                delete_old_rdn: false,
                new_superior: Some(LdapDn(s!("dc=doesnt,dc=exist"))),
            }),
            controls: None,
        };

        let mut buffer = Vec::new();
        message.serialize(&mut buffer);

        assert_eq!(buffer, &packet[..]);
    }

    #[test]
    fn modify_dn_response() {
        let message = &[
            0x30, 0x28, 0x02, 0x01, 0x02, 0x6d, 0x23, 0x0a, 0x01, 0x35, 0x04, 0x00, 0x04, 0x1c,
            0x6e, 0x6f, 0x20, 0x67, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x20, 0x73, 0x75, 0x70, 0x65,
            0x72, 0x69, 0x6f, 0x72, 0x20, 0x6b, 0x6e, 0x6f, 0x77, 0x6c, 0x65, 0x64, 0x67, 0x65,
        ];

        assert_eq!(
            LdapMessage::deserialize(&mut &message[..]),
            Ok(LdapMessage {
                message_id: 2,
                protocol_operation: ProtocolOperation::ModifyDnResponse(ModifyDnResponse {
                    result: LdapResult {
                        result_code: ResultCode::UnwillingToPerform,
                        matched_dn: LdapDn(s!()),
                        diagnostic_message: s!("no global superior knowledge"),
                        referral: None,
                    }
                }),
                controls: None,
            })
        );
    }

    #[test]
    fn compare_request() {
        let packet = &[
            0x30, 0x44, 0x02, 0x01, 0x02, 0x6e, 0x3f, 0x04, 0x1a, 0x63, 0x6e, 0x3d, 0x61, 0x64,
            0x6d, 0x69, 0x6e, 0x2c, 0x64, 0x63, 0x3d, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
            0x2c, 0x64, 0x63, 0x3d, 0x6f, 0x72, 0x67, 0x30, 0x21, 0x04, 0x0b, 0x64, 0x65, 0x73,
            0x63, 0x72, 0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x04, 0x12, 0x4c, 0x44, 0x41, 0x50,
            0x20, 0x41, 0x64, 0x6d, 0x69, 0x6e, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74, 0x6f, 0x72,
        ];

        let message = LdapMessage {
            message_id: 2,
            protocol_operation: ProtocolOperation::CompareRequest(CompareRequest {
                entry: LdapDn(s!("cn=admin,dc=example,dc=org")),
                attribute_value_assertion: AttributeValueAssertion {
                    attribute_description: AttributeDescription(s!("description")),
                    assertion_value: s!("LDAP Administrator"),
                },
            }),
            controls: None,
        };

        let mut buffer = Vec::new();
        message.serialize(&mut buffer);

        assert_eq!(buffer, &packet[..]);
    }

    #[test]
    fn compare_response() {
        let message =
            &[0x30, 0x0c, 0x02, 0x01, 0x02, 0x6f, 0x07, 0x0a, 0x01, 0x06, 0x04, 0x00, 0x04, 0x00];

        assert_eq!(
            LdapMessage::deserialize(&mut &message[..]),
            Ok(LdapMessage {
                message_id: 2,
                protocol_operation: ProtocolOperation::CompareResponse(CompareResponse {
                    result: LdapResult {
                        result_code: ResultCode::CompareTrue,
                        matched_dn: LdapDn(s!()),
                        diagnostic_message: s!(),
                        referral: None,
                    }
                }),
                controls: None,
            })
        );
    }
}
