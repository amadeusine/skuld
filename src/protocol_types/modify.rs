use super::*;

pub const MODIFY_REQUEST: Tag = Tag::from_parts(Class::Application, Aspect::Constructed, 6);

/// Request to modify an object
#[derive(Clone, Debug, PartialEq)]
pub struct ModifyRequest {
    /// The object to modify
    pub object: LdapDn,
    /// Sequence of changes to apply to the object
    pub changes: Vec<Change>,
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
pub struct Change {
    /// The operation to perform on the object
    pub operation: ModifyOperation,
    /// Attributes to modify
    pub modification: PartialAttribute,
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
pub enum ModifyOperation {
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

pub const MODIFY_RESPONSE: Tag = Tag::from_parts(Class::Application, Aspect::Constructed, 7);

/// Modify operation response
#[derive(Clone, Debug, PartialEq)]
pub struct ModifyResponse {
    /// The result of the Modify operation
    pub result: LdapResult,
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

pub const ADD_REQUEST: Tag = Tag::from_parts(Class::Application, Aspect::Constructed, 8);

/// For all intents and purposes these types are no different from each other
/// EXCEPT that `Attribute` MUST have at least one value inside of it
pub type Attribute = PartialAttribute;

/// Request to add an entry
#[derive(Clone, Debug, PartialEq)]
pub struct AddRequest {
    /// DN of the entry to add attributes to
    pub entry: LdapDn,
    /// Attributes to add to the above entry
    pub attributes: Vec<Attribute>,
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

pub const ADD_RESPONSE: Tag = Tag::from_parts(Class::Application, Aspect::Constructed, 9);

/// Add operation response
#[derive(Clone, Debug, PartialEq)]
pub struct AddResponse {
    /// The result of the Add operation
    pub result: LdapResult,
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

pub const DELETE_REQUEST: Tag = Tag::from_parts(Class::Application, Aspect::Primitive, 10);

/// Request to delete an object
#[derive(Clone, Debug, PartialEq)]
pub struct DeleteRequest {
    /// DN of the object to be deleted
    pub entry: LdapDn,
}

impl Serialize for DeleteRequest {
    fn serialize(&self, buffer: &mut dyn VecExt) {
        DELETE_REQUEST.serialize(buffer);
        Length::new(self.entry.0.as_bytes().len() as u64).serialize(buffer);
        buffer.write(self.entry.0.as_bytes());
    }
}

pub const DELETE_RESPONSE: Tag = Tag::from_parts(Class::Application, Aspect::Constructed, 11);

/// Delete operation response
#[derive(Clone, Debug, PartialEq)]
pub struct DeleteResponse {
    /// The result of the Delete operation
    pub result: LdapResult,
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

pub const MODIFY_DN_REQUEST: Tag = Tag::from_parts(Class::Application, Aspect::Constructed, 12);

/// The Modify DN operation allows a client to change the Relative Distinguished
/// Name (RDN) of an entry in the Directory and/or to move a subtree of entries
/// to a new location in the Directory
#[derive(Clone, Debug, PartialEq)]
pub struct ModifyDnRequest {
    /// The name of the entry to modify
    pub entry: LdapDn,
    /// The new Relative DN of the entry
    pub new_rdn: LdapRelativeDn,
    /// Whether the old Relative DN attribute values are to be retained as
    /// attributes of the entry or deleted
    pub delete_old_rdn: bool,
    /// The name of an existing object entry that becomes the parent of the
    /// existing entry, if supplied
    pub new_superior: Option<LdapDn>,
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

pub const MODIFY_DN_RESPONSE: Tag = Tag::from_parts(Class::Application, Aspect::Constructed, 13);

/// Modify DN operation response
#[derive(Clone, Debug, PartialEq)]
pub struct ModifyDnResponse {
    /// The result of the Modify DN operation
    pub result: LdapResult,
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
