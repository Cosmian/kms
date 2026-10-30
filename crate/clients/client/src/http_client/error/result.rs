use super::HttpClientError;

pub(crate) type HttpClientResult<R> = Result<R, HttpClientError>;
