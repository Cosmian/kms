use std::pin::Pin;

use futures::Future;
use redis::{aio::ConnectionManager, cmd, pipe, Pipeline, RedisError, ToRedisArgs};

/// This function encapsulates the boilerplate required to establish a Redis transaction.
/// Do not use it directly but use the `transaction_async!` macro instead.
/// See the `transaction_async!` macro for more details.
pub(crate) async fn transaction_async<
    T,
    E: From<RedisError>,
    K: ToRedisArgs,
    F: Fn(
        ConnectionManager,
        &mut Pipeline,
        CTX,
    ) -> Pin<Box<dyn Future<Output = Result<Option<T>, E>> + Send>>,
    CTX: Clone,
>(
    mut mgr: ConnectionManager,
    keys: &[K],
    context: CTX,
    func: F,
) -> Result<T, E> {
    loop {
        cmd("WATCH").arg(keys).query_async(&mut mgr).await?;
        let mut p = pipe();
        let response: Option<T> = func(mgr.clone(), p.atomic(), context.clone()).await?;
        match response {
            None => continue,
            Some(response) => {
                // make sure no watch is left in the connection, even if
                // someone forgot to use the pipeline.
                cmd("UNWATCH").query_async(&mut mgr).await?;
                return Ok(response)
            }
        }
    }
}

/// Asynchronous transaction macro for Redis operations.
///
/// This macro encapsulates the boilerplate required to establish a Redis transaction
/// and apply a function to it. What it
/// does is automatically watching keys and then going into a transaction
/// loop util it succeeds.  Once it goes through the results are
/// returned.
///
/// To use the transaction two pieces of information are needed: a list
/// of all the keys that need to be watched for modifications and a
/// closure with the code that should be execute in the context of the
/// transaction.  The closure is invoked with a fresh pipeline in atomic
/// mode.  To use the transaction the function needs to return the result
/// from querying the pipeline with the connection.
///
/// The end result of the transaction is then available as the return
/// value from the function call.
///
/// # Parameters
///
/// - `$mgr`: A cloned connection manager for Redis.
/// - `$key`: A key (or array of keys) for the Redis operation.
/// - `$context`: An optional cloneable context passed to the function.
/// - `$func`: Either a path to a function or a lambda function. This function
///   should have the signature `async fn(ConnectionManager, Pipeline) -> Result<Option<T>, RedisError>`
///   where `T` is the expected return type.
///
/// # Examples
///
/// # Returns
///
/// Returns a `Result` containing the return value of the passed function, or an error.
///
/// Note: This macro is exported so it can be used in other modules.
#[macro_export]
macro_rules! transaction_async {
    ($mgr:expr, $key:expr, $context:expr, $func:path) => {{
        $crate::database::redis::transaction_async(
            $mgr,
            $key,
            $context,
            |mgr, pipeline, context| {
                let pipeline = pipeline.clone();
                Box::pin(async move { $func(mgr, pipeline, context).await })
            },
        )
        .await
    }};
    ($mgr:expr, $key:expr, $context:expr, $func:expr) => {{
        $crate::database::redis::transaction_async(
            $mgr,
            $key,
            $context,
            |mgr, pipeline, context| {
                let pipeline = pipeline.clone();
                Box::pin($func(mgr, pipeline, context))
            },
        )
        .await
    }};
}

#[cfg(test)]
mod tests {

    use redis::{aio::ConnectionManager, AsyncCommands, Pipeline, RedisError};
    use serial_test::serial;
    use tracing::trace;

    use crate::{log_init, result::KResult};

    const REDIS_URL: &str = "redis://localhost:6379";

    #[actix_web::test]
    #[serial]
    pub async fn test_async_transaction() -> KResult<()> {
        cosmian_logger::log_init(Some("test_permissions_db=info"));
        trace!("test_permissions_db");

        let client = redis::Client::open(REDIS_URL)?;
        let mgr = ConnectionManager::new(client).await?;

        #[derive(Clone)]
        struct Context {
            new_value: String,
        }

        async fn return_blah(
            mut mgr: ConnectionManager,
            mut pipeline: Pipeline,
            context: Context,
        ) -> KResult<Option<Vec<String>>> {
            let res = pipeline
                .set("key", context.new_value)
                .ignore()
                .get("key")
                .query_async(&mut mgr)
                .await?;
            Ok(res)
        }

        let res = transaction_async!(
            mgr.clone(),
            &["key"],
            Context {
                new_value: "blah".to_owned(),
            },
            return_blah
        )?;
        assert_eq!(res, vec!["blah".to_owned()]);

        let res: Vec<String> = transaction_async!(
            mgr.clone(),
            &["key"],
            Context {
                new_value: "blah".to_owned(),
            },
            |mut mgr: ConnectionManager, mut pipeline: Pipeline, context: Context| async move {
                pipeline
                    .set("key", context.new_value)
                    .ignore()
                    .get("key")
                    .query_async(&mut mgr)
                    .await
            }
        )?;
        assert_eq!(res, vec!["blah".to_owned()]);

        // now insert a key/value and modify it in a transaction
        mgr.clone().set("key", "value").await?;
        async fn modify_key(
            mut mgr: ConnectionManager,
            mut pipeline: Pipeline,
            context: Context,
        ) -> Result<Option<Vec<String>>, RedisError> {
            let value: String = mgr.get("key").await?;
            // do some dummy stuff
            let new_value = format!("{}->{}", value, context.new_value);
            pipeline
                .set("key", &new_value)
                .ignore()
                .get("key")
                .query_async(&mut mgr)
                .await
        }
        let new_value: Vec<String> = transaction_async!(
            mgr.clone(),
            &["key"],
            Context {
                new_value: "new".to_owned()
            },
            modify_key
        )?;
        let actual_value: String = mgr.clone().get("key").await?;
        assert_eq!(new_value[0], actual_value);

        Ok(())
    }
}
