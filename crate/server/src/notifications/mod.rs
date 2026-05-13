mod email;
#[cfg(test)]
mod tests;

pub use email::{EmailNotifier, SmtpParams};
