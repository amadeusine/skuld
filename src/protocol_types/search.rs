use super::*;

pub(crate) const SEARCH_REQUEST: Tag = Tag::from_parts(Class::Application, Aspect::Constructed, 3);

/// A search request
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SearchRequest {
    /// The base object to search
    pub(crate) base_object: LdapDn,
    /// The scope in which to search
    pub(crate) scope: Scope,
    /// Behavior when encountering aliases
    pub(crate) deref_alias: DerefAlias,
    /// The max number of entries to be returned, with 0 indicating no size
    /// limit
    pub(crate) size_limit: i32,
    /// A time limit in seconds to process the search request
    pub(crate) time_limit: i32,
    /// Whether the search results contain both attribute descriptions and
    /// values or only attribute descriptions
    pub(crate) types_only: bool,
    /// The filter of which to match entries with
    pub(crate) filter: Filter,
    ///
    pub(crate) attributes: Vec<String>,
}

impl Serialize for SearchRequest {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        SEARCH_REQUEST.serialize(buffer);

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
pub(crate) enum Scope {
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
        ENUMERATED.serialize(buffer);
        Length::new(1).serialize(buffer);
        buffer.write_byte(*self as u8)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
#[allow(clippy::enum_variant_names)]
#[repr(u8)]
pub(crate) enum DerefAlias {
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
        ENUMERATED.serialize(buffer);
        Length::new(1).serialize(buffer);
        buffer.write_byte(*self as u8)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Filter {
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

/// A substring filter
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SubstringFilter {
    /// The attribute description whose attribute value to match the substrings
    /// on
    pub(crate) r#type: AttributeDescription,
    /// The substrings to match on
    pub(crate) substrings: Vec<Substring>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Substring {
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
pub(crate) struct MatchingRuleAssertion {
    pub(crate) matching_rule: Option<String>,
    pub(crate) r#type: Option<AttributeDescription>,
    pub(crate) match_value: AssertionValue,
    pub(crate) dn_attributes: bool,
}

pub(crate) const SEARCH_RESULT_ENTRY: Tag =
    Tag::from_parts(Class::Application, Aspect::Constructed, 4);

/// A result from a Search operation
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SearchResultEntry {
    /// The object name of this result
    pub(crate) object_name: LdapDn,
    /// The list of attributes for
    pub(crate) attribute_list: Vec<PartialAttribute>,
}

impl Deserialize for SearchResultEntry {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError> {
        buffer.tag(SEARCH_RESULT_ENTRY)?;
        let length = Length::deserialize(buffer)?;
        let buffer = &mut buffer.slice(length)?;

        let object_name = LdapDn::deserialize(buffer)?;
        let attribute_list = Vec::deserialize(buffer)?;

        Ok(Self { object_name, attribute_list })
    }
}

pub(crate) const SEARCH_RESULT_REFERENCE: Tag =
    Tag::from_parts(Class::Application, Aspect::Constructed, 19);

/// Search results that have not been visited that reside on another LDAP server
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SearchResultReference {
    /// URIs of the LDAP servers with query
    pub(crate) uris: Vec<Uri>,
}

impl Deserialize for SearchResultReference {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError> {
        buffer.tag(SEARCH_RESULT_REFERENCE)?;
        let length = Length::deserialize(buffer)?;
        let buffer = &mut buffer.slice(length)?;

        let mut uris = Vec::new();
        while !buffer.is_empty() {
            uris.push(Uri::deserialize(buffer)?);
        }

        Ok(Self { uris })
    }
}

pub(crate) const SEARCH_RESULT_DONE: Tag =
    Tag::from_parts(Class::Application, Aspect::Constructed, 5);

/// All search result entries have been returned
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SearchResultDone {
    /// The result of the search
    pub(crate) result: LdapResult,
}

impl Deserialize for SearchResultDone {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError> {
        buffer.tag(SEARCH_RESULT_DONE)?;
        let length = Length::deserialize(buffer)?;
        let buffer = &mut buffer.slice(length)?;

        let result = ComponentsOfLdapResult::deserialize(buffer)?.into_inner();

        Ok(Self { result })
    }
}
