use super::*;

pub(crate) const COMPARE_REQUEST: Tag =
    Tag::from_parts(Class::Application, Aspect::Constructed, 14);

/// Compare an attribute description and value with a specific entry
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CompareRequest {
    /// Entry to compare to
    pub(crate) entry: LdapDn,
    /// Attribute description and value pair
    pub(crate) attribute_value_assertion: AttributeValueAssertion,
}

impl Serialize for CompareRequest {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        COMPARE_REQUEST.serialize(buffer);
        serialize_sequence(buffer, |buffer| {
            self.entry.serialize(buffer);

            SEQUENCE.serialize(buffer);
            serialize_sequence(buffer, |buffer| {
                self.attribute_value_assertion.attribute_description.serialize(buffer);
                self.attribute_value_assertion.assertion_value.serialize(buffer);
            });
        });
    }
}

pub(crate) const COMPARE_RESPONSE: Tag =
    Tag::from_parts(Class::Application, Aspect::Constructed, 15);

/// Compare operation response
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CompareResponse {
    /// The result of the Compare operation
    pub(crate) result: LdapResult,
}

impl Deserialize for CompareResponse {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError> {
        buffer.tag(COMPARE_RESPONSE)?;
        let length = Length::deserialize(buffer)?;
        let buffer = &mut buffer.slice(length)?;

        let result = ComponentsOfLdapResult::deserialize(buffer)?.into_inner();

        Ok(Self { result })
    }
}
