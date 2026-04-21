/// Helper macro to extract function name from the call site
#[macro_export]
macro_rules! __get_fn_name {
    () => {{
        let type_name = std::any::type_name_of_val(&|| {});
        let parts: Vec<&str> = type_name.split("::").collect();
        // Walk right-to-left, tracking angle-bracket depth so that generic
        // type arguments (e.g. `export_get::<Export>::{{closure}}` splits into
        // […, "export_get::<SomeCrate", "SomeMod", "Export>", "{{closure}}"]) are
        // skipped.  A part that contains '<' or '>' is either inside or is the
        // boundary of a generic parameter and must not be used as the function name.
        let mut depth = 0_i32;
        parts
            .iter()
            .rev()
            .filter(|&&part| part != "{{closure}}")
            .find(|&&part| {
                for c in part.chars() {
                    match c {
                        '>' => depth += 1,
                        '<' => depth -= 1,
                        _ => {}
                    }
                }
                depth == 0 && !part.contains('<') && !part.contains('>')
            })
            .unwrap_or(&"unknown")
            .to_string()
    }};
}

/// Macro to automatically add function name as prefix to info logs
/// Supports both simple format strings and structured logging with key-value
/// pairs
#[macro_export]
macro_rules! info {
    (target: $target:expr, $fmt:literal $(, $($args:tt)*)?) => {
        $crate::reexport::tracing::info!(target: $target, "[{}] {}", $crate::__get_fn_name!(), format!($fmt $(, $($args)*)?))
    };
    (target: $target:expr, $($field:ident = $value:expr,)+ $fmt:literal $(, $($args:tt)*)?) => {
        $crate::reexport::tracing::info!(target: $target, $($field = $value,)+ "[{}] {}", $crate::__get_fn_name!(), format!($fmt $(, $($args)*)?))
    };
    ($($field:ident = $value:expr),+ $(,)?; $($rest:tt)*) => {
        $crate::reexport::tracing::info!($($field = $value,)+ "[{}] {}", $crate::__get_fn_name!(), format!($($rest)*))
    };
    ($($field:ident = $value:expr,)+ $fmt:literal $(, $($args:tt)*)?) => {
        $crate::reexport::tracing::info!($($field = $value,)+ "[{}] {}", $crate::__get_fn_name!(), format!($fmt $(, $($args)*)?))
    };
    ($($arg:tt)*) => {
        $crate::reexport::tracing::info!("[{}] {}", $crate::__get_fn_name!(), format!($($arg)*))
    };
}

/// Macro to automatically add function name as prefix to debug logs
/// Supports both simple format strings and structured logging with key-value
/// pairs
#[macro_export]
macro_rules! debug {
    (target: $target:expr, $fmt:literal $(, $($args:tt)*)?) => {
        $crate::reexport::tracing::debug!(target: $target, "[{}] {}", $crate::__get_fn_name!(), format!($fmt $(, $($args)*)?))
    };
    (target: $target:expr, $($field:ident = $value:expr,)+ $fmt:literal $(, $($args:tt)*)?) => {
        $crate::reexport::tracing::debug!(target: $target, $($field = $value,)+ "[{}] {}", $crate::__get_fn_name!(), format!($fmt $(, $($args)*)?))
    };
    ($($field:ident = $value:expr),+ $(,)?; $($rest:tt)*) => {
        $crate::reexport::tracing::debug!($($field = $value,)+ "[{}] {}", $crate::__get_fn_name!(), format!($($rest)*))
    };
    ($($field:ident = $value:expr,)+ $fmt:literal $(, $($args:tt)*)?) => {
        $crate::reexport::tracing::debug!($($field = $value,)+ "[{}] {}", $crate::__get_fn_name!(), format!($fmt $(, $($args)*)?))
    };
    ($($arg:tt)*) => {
        $crate::reexport::tracing::debug!("[{}] {}", $crate::__get_fn_name!(), format!($($arg)*))
    };
}

/// Macro to automatically add function name as prefix to warn logs
/// Supports both simple format strings and structured logging with key-value
/// pairs
#[macro_export]
macro_rules! warn {
    (target: $target:expr, $fmt:literal $(, $($args:tt)*)?) => {
        $crate::reexport::tracing::warn!(target: $target, "[{}] {}", $crate::__get_fn_name!(), format!($fmt $(, $($args)*)?))
    };
    (target: $target:expr, $($field:ident = $value:expr,)+ $fmt:literal $(, $($args:tt)*)?) => {
        $crate::reexport::tracing::warn!(target: $target, $($field = $value,)+ "[{}] {}", $crate::__get_fn_name!(), format!($fmt $(, $($args)*)?))
    };
    ($($field:ident = $value:expr),+ $(,)?; $($rest:tt)*) => {
        $crate::reexport::tracing::warn!($($field = $value,)+ "[{}] {}", $crate::__get_fn_name!(), format!($($rest)*))
    };
    ($($field:ident = $value:expr,)+ $fmt:literal $(, $($args:tt)*)?) => {
        $crate::reexport::tracing::warn!($($field = $value,)+ "[{}] {}", $crate::__get_fn_name!(), format!($fmt $(, $($args)*)?))
    };
    ($($arg:tt)*) => {
        $crate::reexport::tracing::warn!("[{}] {}", $crate::__get_fn_name!(), format!($($arg)*))
    };
}

/// Macro to automatically add function name as prefix to error logs
/// Supports both simple format strings and structured logging with key-value
/// pairs
#[macro_export]
macro_rules! error {
    (target: $target:expr, $fmt:literal $(, $($args:tt)*)?) => {
        $crate::reexport::tracing::error!(target: $target, "[{}] {}", $crate::__get_fn_name!(), format!($fmt $(, $($args)*)?))
    };
    (target: $target:expr, $($field:ident = $value:expr,)+ $fmt:literal $(, $($args:tt)*)?) => {
        $crate::reexport::tracing::error!(target: $target, $($field = $value,)+ "[{}] {}", $crate::__get_fn_name!(), format!($fmt $(, $($args)*)?))
    };
    ($($field:ident = $value:expr),+ $(,)?; $($rest:tt)*) => {
        $crate::reexport::tracing::error!($($field = $value,)+ "[{}] {}", $crate::__get_fn_name!(), format!($($rest)*))
    };
    ($($field:ident = $value:expr,)+ $fmt:literal $(, $($args:tt)*)?) => {
        $crate::reexport::tracing::error!($($field = $value,)+ "[{}] {}", $crate::__get_fn_name!(), format!($fmt $(, $($args)*)?))
    };
    ($($arg:tt)*) => {
        $crate::reexport::tracing::error!("[{}] {}", $crate::__get_fn_name!(), format!($($arg)*))
    };
}

/// Macro to automatically add function name as prefix to trace logs
/// Supports both simple format strings and structured logging with key-value
/// pairs
#[macro_export]
macro_rules! trace {
    (target: $target:expr, $fmt:literal $(, $($args:tt)*)?) => {
        $crate::reexport::tracing::trace!(target: $target, "[{}] {}", $crate::__get_fn_name!(), format!($fmt $(, $($args)*)?))
    };
    (target: $target:expr, $($field:ident = $value:expr,)+ $fmt:literal $(, $($args:tt)*)?) => {
        $crate::reexport::tracing::trace!(target: $target, $($field = $value,)+ "[{}] {}", $crate::__get_fn_name!(), format!($fmt $(, $($args)*)?))
    };
    ($($field:ident = $value:expr),+ $(,)?; $($rest:tt)*) => {
        $crate::reexport::tracing::trace!($($field = $value,)+ "[{}] {}", $crate::__get_fn_name!(), format!($($rest)*))
    };
    ($($field:ident = $value:expr,)+ $fmt:literal $(, $($args:tt)*)?) => {
        $crate::reexport::tracing::trace!($($field = $value,)+ "[{}] {}", $crate::__get_fn_name!(), format!($fmt $(, $($args)*)?))
    };
    ($($arg:tt)*) => {
        $crate::reexport::tracing::trace!("[{}] {}", $crate::__get_fn_name!(), format!($($arg)*))
    };
}

#[cfg(test)]
#[allow(clippy::items_after_statements)]
mod macro_tests {
    use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};

    #[derive(Debug)]
    enum ObjectType {
        Document,
    }

    struct TestObject {
        obj_type: ObjectType,
    }

    impl TestObject {
        fn object_type(&self) -> &ObjectType {
            &self.obj_type
        }
    }

    fn init_test_logging() {
        let _guard = tracing_subscriber::registry().with(fmt::layer()).try_init();
    }

    #[test]
    fn test_structured_logging_macros() {
        init_test_logging();

        let uid = "test_uid";
        let owner = "test_owner";
        let object = TestObject {
            obj_type: ObjectType::Document,
        };

        // Test the exact pattern from the user's request
        info!(
            uid = uid,
            user = owner,
            "Created Object of type {:?}",
            &object.object_type()
        );

        // Test variations
        debug!(
            uid = uid,
            user = owner,
            "Debug message for object type {:?}",
            &object.object_type()
        );
        warn!(
            user = owner,
            "Warning about object type {:?}",
            &object.object_type()
        );
        error!(
            uid = uid,
            user = owner,
            "Error related to object type {:?}",
            &object.object_type()
        );
    }

    #[test]
    fn test_simple_logging_macros() {
        init_test_logging();

        info!("Simple info message");
        debug!("Simple debug message with arg: {}", 42);
        warn!("Simple warning: {}", "test");
    }

    #[test]
    fn test_target_with_structured_logging() {
        init_test_logging();

        let user = "test_user";

        // Mock TTLV structure for testing
        struct TestTag {
            tag: String,
        }

        impl TestTag {
            fn as_str(&self) -> &str {
                &self.tag
            }
        }

        struct TestTtlv {
            tag: TestTag,
        }

        let ttlv = TestTtlv {
            tag: TestTag {
                tag: "Create".to_owned(),
            },
        };

        // Test the exact pattern from the user's request
        info!(target: "kmip", user = user, tag = ttlv.tag.as_str(), "POST /kmip/2_1. Request: {:?} {}", ttlv.tag.as_str(), user);
    }

    #[test]
    fn test_all_macros_with_target() {
        init_test_logging();

        let user = "admin";
        let action = "test_action";

        // Test all macros with target support
        info!(target: "auth", user = user, action = action, "Info: User {} performed {}", user, action);
        debug!(target: "auth", user = user, action = action, "Debug: User {} performed {}", user, action);
        warn!(target: "auth", user = user, action = action, "Warning: User {} performed {}", user, action);
        error!(target: "auth", user = user, action = action, "Error: User {} performed {}", user, action);
        trace!(target: "auth", user = user, action = action, "Trace: User {} performed {}", user, action);
    }

    #[test]
    fn test_target_with_simple_message() {
        init_test_logging();

        let e = "parse error: invalid format";

        // Test the exact pattern from the user's request
        error!(target: "kmip", "Failed to parse RequestMessage: {}", e);
    }
}
