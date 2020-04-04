use super::*;

pub(crate) const ABANDON_REQUEST: Tag = Tag::from_parts(Class::Application, Aspect::Primitive, 16);

/// Request the server abandon a previously sent request
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AbandonRequest {
    /// Message ID to abandon
    pub(crate) message_id: i32,
}

impl Serialize for AbandonRequest {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        ABANDON_REQUEST.serialize(buffer);
        serialize_sequence(buffer, |buffer| {
            self.message_id.serialize(buffer);
        });
    }
}
