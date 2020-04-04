use super::*;

pub(crate) const MODIFY_REQUEST: Tag = Tag::from_parts(Class::Application, Aspect::Constructed, 6);

/// Request to modify an object
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ModifyRequest {
    /// The object to modify
    pub(crate) object: LdapDn,
    /// Sequence of changes to apply to the object
    pub(crate) changes: Vec<Change>,
}

impl Serialize for ModifyRequest {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        MODIFY_REQUEST.serialize(buffer);
        serialize_sequence(buffer, |buffer| {
            self.object.serialize(buffer);
            self.changes.serialize(buffer);
        });
    }
}

/// An individual change to make to some object
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Change {
    /// The operation to perform on the object
    pub(crate) operation: ModifyOperation,
    /// Attributes to modify
    pub(crate) modification: PartialAttribute,
}

impl Serialize for Change {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        SEQUENCE.serialize(buffer);
        serialize_sequence(buffer, |buffer| {
            self.operation.serialize(buffer);
            self.modification.serialize(buffer);
        });
    }
}

/// The types of operations that can be applied to an object
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
pub(crate) enum ModifyOperation {
    Add = 0,
    Delete = 1,
    Replace = 2,
}

impl Serialize for ModifyOperation {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        ENUMERATED.serialize(buffer);
        Length::new(1).serialize(buffer);
        buffer.write_byte(*self as u8);
    }
}

pub(crate) const MODIFY_RESPONSE: Tag = Tag::from_parts(Class::Application, Aspect::Constructed, 7);

/// Modify operation response
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ModifyResponse {
    /// The result of the Modify operation
    pub(crate) result: LdapResult,
}

impl Deserialize for ModifyResponse {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError> {
        buffer.tag(MODIFY_RESPONSE)?;
        let length = Length::deserialize(buffer)?;
        let buffer = &mut buffer.slice(length)?;

        let result = ComponentsOfLdapResult::deserialize(buffer)?.into_inner();

        Ok(Self { result })
    }
}

pub(crate) const ADD_REQUEST: Tag = Tag::from_parts(Class::Application, Aspect::Constructed, 8);

/// For all intents and purposes these types are no different from each other
/// EXCEPT that `Attribute` MUST have at least one value inside of it
pub(crate) type Attribute = PartialAttribute;

/// Request to add an entry
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AddRequest {
    /// DN of the entry to add attributes to
    pub(crate) entry: LdapDn,
    /// Attributes to add to the above entry
    pub(crate) attributes: Vec<Attribute>,
}

impl Serialize for AddRequest {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        ADD_REQUEST.serialize(buffer);
        serialize_sequence(buffer, |buffer| {
            self.entry.serialize(buffer);
            self.attributes.serialize(buffer);
        });
    }
}

pub(crate) const ADD_RESPONSE: Tag = Tag::from_parts(Class::Application, Aspect::Constructed, 9);

/// Add operation response
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AddResponse {
    /// The result of the Add operation
    pub(crate) result: LdapResult,
}

impl Deserialize for AddResponse {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError> {
        buffer.tag(ADD_RESPONSE)?;
        let length = Length::deserialize(buffer)?;
        let buffer = &mut buffer.slice(length)?;

        let result = ComponentsOfLdapResult::deserialize(buffer)?.into_inner();

        Ok(Self { result })
    }
}

pub(crate) const DELETE_REQUEST: Tag = Tag::from_parts(Class::Application, Aspect::Primitive, 10);

/// Request to delete an object
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DeleteRequest {
    /// DN of the object to be deleted
    pub(crate) entry: LdapDn,
}

impl Serialize for DeleteRequest {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        DELETE_REQUEST.serialize(buffer);
        Length::new(self.entry.0.as_bytes().len() as u64).serialize(buffer);
        buffer.write(self.entry.0.as_bytes());
    }
}

pub(crate) const DELETE_RESPONSE: Tag =
    Tag::from_parts(Class::Application, Aspect::Constructed, 11);

/// Delete operation response
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DeleteResponse {
    /// The result of the Delete operation
    pub(crate) result: LdapResult,
}

impl Deserialize for DeleteResponse {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError> {
        buffer.tag(DELETE_RESPONSE)?;
        let length = Length::deserialize(buffer)?;
        let buffer = &mut buffer.slice(length)?;

        let result = ComponentsOfLdapResult::deserialize(buffer)?.into_inner();

        Ok(Self { result })
    }
}

pub(crate) const MODIFY_DN_REQUEST: Tag =
    Tag::from_parts(Class::Application, Aspect::Constructed, 12);

/// The Modify DN operation allows a client to change the Relative Distinguished
/// Name (RDN) of an entry in the Directory and/or to move a subtree of entries
/// to a new location in the Directory
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ModifyDnRequest {
    /// The name of the entry to modify
    pub(crate) entry: LdapDn,
    /// The new Relative DN of the entry
    pub(crate) new_rdn: LdapRelativeDn,
    /// Whether the old Relative DN attribute values are to be retained as
    /// attributes of the entry or deleted
    pub(crate) delete_old_rdn: bool,
    /// The name of an existing object entry that becomes the parent of the
    /// existing entry, if supplied
    pub(crate) new_superior: Option<LdapDn>,
}

impl Serialize for ModifyDnRequest {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        const NEW_SUPERIOR: Tag = Tag::from_parts(Class::ContextSpecific, Aspect::Primitive, 0);

        MODIFY_DN_REQUEST.serialize(buffer);
        serialize_sequence(buffer, |buffer| {
            self.entry.serialize(buffer);
            self.new_rdn.0.serialize(buffer);
            self.delete_old_rdn.serialize(buffer);

            if let Some(new_superior) = &self.new_superior {
                NEW_SUPERIOR.serialize(buffer);
                Length::new(new_superior.0.as_bytes().len() as u64).serialize(buffer);
                buffer.write(new_superior.0.as_bytes());
            }
        });
    }
}

pub(crate) const MODIFY_DN_RESPONSE: Tag =
    Tag::from_parts(Class::Application, Aspect::Constructed, 13);

/// Modify DN operation response
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ModifyDnResponse {
    /// The result of the Modify DN operation
    pub(crate) result: LdapResult,
}

impl Deserialize for ModifyDnResponse {
    fn deserialize(buffer: &mut &[u8]) -> Result<Self, DeserializeError> {
        buffer.tag(MODIFY_DN_RESPONSE)?;
        let length = Length::deserialize(buffer)?;
        let buffer = &mut buffer.slice(length)?;

        let result = ComponentsOfLdapResult::deserialize(buffer)?.into_inner();

        Ok(Self { result })
    }
}
