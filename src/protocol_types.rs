use crate::ber::{
    util::{serialize_sequence, ReadExt, VecExt},
    Aspect, Class, Deserialize, DeserializeError, Length, Serialize, Tag, ENUMERATED_TAG,
    SEQUENCE_TAG,
};

const CONTROLS_TAG: Tag = Tag::from_parts(Class::ContextSpecific, Aspect::Constructed, 0);

/// The main packet type of the protocol
#[derive(Clone, Debug, PartialEq)]
pub struct LdapMessage {
    /// A non-zero, session-unique message ID
    pub message_id: i32,
    /// The protocol operation
    pub protocol_operation: ProtocolOperation,
    /// Optional controls contained by this message
    pub controls: Option<Vec<Control>>,
}

impl Serialize for LdapMessage {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        SEQUENCE_TAG.serialize(buffer);

        serialize_sequence(buffer, |buffer| {
            self.message_id.serialize(buffer);
            self.protocol_operation.serialize(buffer);

            if let Some(_controls) = &self.controls {
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
pub struct Control {
    pub control_type: LdapOid,
    pub criticality: bool,
    pub control_value: Option<String>,
}

/// Wrapper type around a UTF-8 encoded string that is restricted to
/// <numericoid> -- which I assume to be of the format:
///
/// [012].(\d)+(\.\d+)+
///
/// Can't actually find the definition point for it
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

/// Wrapper type around a UTF-8 encoded string that is restricted to
/// <distinguishedName> which seems to be a comma separated list of
/// <relativeDistinguishedName>
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

/// The result of an operation
#[derive(Clone, Debug, PartialEq)]
pub struct LdapResult {
    /// Success or error code
    pub result_code: ResultCode,
    pub matched_dn: LdapDn,
    /// Additional diagnostic message
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

/// A wrapper around `LdapResult` that deserializes just the fields as some
/// operations return `COMPONENTS OF LDAPResult`
pub struct ComponentsOfLdapResult(LdapResult);

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

/// The result code of the operation, non-error codes are marked as such
#[derive(Clone, Debug, PartialEq)]
pub enum ResultCode {
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
            71 => ResultCode::AffectsMultipleDSAs,
            80 => ResultCode::Other,
            _ => return Err(DeserializeError::InvalidValue),
        })
    }
}

const BIND_REQUEST_TAG: Tag = Tag::from_parts(Class::Application, Aspect::Constructed, 0);

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

/// The server response to a Bind request
#[derive(Clone, Debug, PartialEq)]
pub struct BindResponse {
    /// Result of the Bind request
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

/// A termination request to gracefully end communication
#[derive(Clone, Debug, PartialEq)]
pub struct UnbindRequest;

impl Serialize for UnbindRequest {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        UNBIND_REQUEST_TAG.serialize(buffer);
        Length::new(0).serialize(buffer);
    }
}

/// A search request
#[derive(Clone, Debug, PartialEq)]
pub struct SearchRequest {
    /// The base object to search
    pub base_object: LdapDn,
    /// The scope in which to search
    pub scope: Scope,
    /// Behavior when encountering aliases
    pub deref_alias: DerefAlias,
    /// The max number of entries to be returned, with 0 indicating no size
    /// limit
    pub size_limit: i32,
    /// A time limit in seconds to process the search request
    pub time_limit: i32,
    /// Whether the search results contain both attribute descriptions and
    /// values or only attribute descriptions
    pub types_only: bool,
    /// The filter of which to match entries with
    pub filter: Filter,
    ///
    pub attributes: Vec<String>,
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
    /// The scope is constrained to the entry named by `baseObject`
    BaseObject = 0,
    /// The scope is constrained to the immediate subordinates of the entry
    /// named by `baseObject`
    SingleLevel = 1,
    /// The scope is constrained to the entry named by `baseObject` and to all
    /// its subordinates
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
    /// Do not dereference aliases during processing of the search
    NeverDerefAlias = 0,
    /// While searching subordinates of the base object, dereference any alias
    /// within the search scope
    DerefInSearching = 1,
    /// Dereference aliases in locating the base object of the search, but not
    /// when searching subordinates of the base object.
    DerefFindingBaseObj = 2,
    /// Dereference aliases both in searching and in locating the base object of
    /// the search
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
    /// A combination filter where all subfilters must match to return a result
    And(Vec<Filter>),
    /// A combination filter where at least one subfilter must match to return a
    /// result
    Or(Vec<Filter>),
    /// A combination filter where the subfilter must NOT match to return a
    /// result
    Not(Box<Filter>),
    /// The provided attribute description and value match exactly to one in the
    /// entry
    EqualityMatch(AttributeValueAssertion),
    /// The attribute value of the provided attribute description matches the
    /// pattern specified
    Substrings(SubstringFilter),
    /// The attribute value is greater than or equal to the provided attribute
    /// value of the provided attribute description
    GreaterOrEqual(AttributeValueAssertion),
    /// The attribute value is greater than or equal to the provided attribute
    /// value of the provided attribute description
    LessOrEqual(AttributeValueAssertion),
    /// The attribute description exists
    Present(AttributeDescription),
    /// The attribute value of the provided attribute description approximately
    /// matches the provided attribute value in some way
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
                    ava.assertion_value.serialize(buffer);
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
                    ava.assertion_value.serialize(buffer);
                });
            }
            Filter::LessOrEqual(ava) => {
                LESS_OR_EQUAL.serialize(buffer);
                serialize_sequence(buffer, |buffer| {
                    ava.attribute_description.0.serialize(buffer);
                    ava.assertion_value.serialize(buffer);
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
                    ava.assertion_value.serialize(buffer);
                });
            }
            Filter::ExtensibleMatch(_) => todo!("extensible match serialization"),
        }
    }
}

pub type AssertionValue = String;

/// A UTF-8 string that is constrained to <attributedescription>
#[derive(Clone, Debug, PartialEq)]
pub struct AttributeDescription(String);

/// A substring filter
#[derive(Clone, Debug, PartialEq)]
pub struct SubstringFilter {
    /// The attribute description whose attribute value to match the substrings
    /// on
    pub r#type: AttributeDescription,
    /// The substrings to match on
    pub substrings: Vec<Substring>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Substring {
    /// The initial value of the substring match, at most one and must be the
    /// first element in `SubstringFilter.substrings`
    Initial(AssertionValue),
    /// A substring value to match on partially
    Any(AssertionValue),
    /// The last value of the substring match, at most one and must be the last
    /// element in `SubstringFilter.substrings`
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
                Length::new(av.as_bytes().len() as u64).serialize(buffer);
                buffer.write(av.as_bytes());
            }
            Substring::Any(av) => {
                ANY.serialize(buffer);
                Length::new(av.as_bytes().len() as u64).serialize(buffer);
                buffer.write(av.as_bytes());
            }
            Substring::Final(av) => {
                FINAL.serialize(buffer);
                Length::new(av.as_bytes().len() as u64).serialize(buffer);
                buffer.write(av.as_bytes());
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct AttributeValueAssertion {
    /// The attribute description to match on
    pub attribute_description: AttributeDescription,
    /// The attribute value to match on
    pub assertion_value: AssertionValue,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MatchingRuleAssertion {
    pub matching_rule: Option<String>,
    pub r#type: Option<AttributeDescription>,
    pub match_value: AssertionValue,
    pub dn_attributes: bool,
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
    }
}
