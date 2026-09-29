#[macro_use]
mod dispatch_macros;
mod add;
mod delete;
mod get;
mod get_list;
mod modify;
mod set;

pub(crate) use add::add_attribute;
pub(crate) use delete::delete_attribute;
pub(crate) use get::get_attributes;
pub(crate) use get_list::{get_attribute_list, get_attribute_list_with_protocol_version};
pub(crate) use modify::modify_attribute;
pub(crate) use set::set_attribute;
