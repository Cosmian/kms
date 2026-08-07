/// Generate the full match block for `AddAttribute` with simple (check-then-assign) arms
/// and custom arms for special-case attributes.
#[allow(unused_macros)]
macro_rules! match_add_attribute {
    (
        $scrutinee:expr, $attrs:expr,
        simple { $($variant:ident => $field:ident),* $(,)? }
        custom { $($custom:tt)* }
    ) => {
        match $scrutinee {
            $(
                Attribute::$variant(value) => {
                    trace!(concat!(stringify!($variant), ": {:?}"), value);
                    if $attrs.$field.is_some() {
                        return Err(KmsError::InvalidRequest(
                            concat!(stringify!($variant), " already exists").to_owned(),
                        ));
                    }
                    $attrs.$field = Some(value);
                }
            )*
            $($custom)*
        }
    };
}

/// Generate the full match block for `SetAttribute`/`ModifyAttribute` with simple
/// (unconditional assign) arms and custom arms for special-case attributes.
/// The `$prefix` is included in the trace output (e.g. "`SetAttribute`" or "`ModifyAttribute`").
#[allow(unused_macros)]
macro_rules! match_set_attribute {
    (
        $prefix:expr, $scrutinee:expr, $attrs:expr,
        simple { $($variant:ident => $field:ident),* $(,)? }
        custom { $($custom:tt)* }
    ) => {
        match $scrutinee {
            $(
                Attribute::$variant(value) => {
                    trace!(concat!($prefix, ": ", stringify!($variant), ": {:?}"), value);
                    $attrs.$field = Some(value);
                }
            )*
            $($custom)*
        }
    };
}

/// Generate the full match block for `DeleteAttribute` with simple (compare-then-clear) arms
/// and custom arms for special-case attributes.
#[allow(unused_macros)]
macro_rules! match_delete_attribute {
    (
        $scrutinee:expr, $attrs:expr,
        simple { $($variant:ident => $field:ident),* $(,)? }
        custom { $($custom:tt)* }
    ) => {
        match $scrutinee {
            $(
                Attribute::$variant(value) => {
                    if Some(value) == $attrs.$field {
                        $attrs.$field = None;
                    }
                }
            )*
            $($custom)*
        }
    };
}

/// Deletes an attribute identified by its `Tag` (rather than by value).
///
/// `DeleteAttribute` may reference an attribute either by value
/// (`CurrentAttribute`) or purely by name (`AttributeReference`). This macro
/// covers the name-based form, clearing the matching field unconditionally.
///
/// KMIP 1.4 §4.16 / KMIP 2.1 §6.1.13.
#[allow(unused_macros)]
macro_rules! match_delete_attribute_by_tag {
    (
        $scrutinee:expr, $attrs:expr,
        simple { $($variant:ident => $field:ident),* $(,)? }
        custom { $($custom:tt)* }
    ) => {
        match $scrutinee {
            $(
                Tag::$variant => {
                    $attrs.$field = None;
                }
            )*
            $($custom)*
        }
    };
}
