// Copyright 2025 Cosmian Tech SAS
// Changes made to the original code are
// licensed under the Business Source License version 1.1.
//
// Original code:
// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![allow(
    unsafe_code,
    non_snake_case, // case come from C
    clippy::missing_safety_doc,
    clippy::missing_errors_doc,
)]

pub mod core;
mod error;
mod objects_store;
pub mod pkcs11;
mod sessions;
#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]
mod tests;
pub mod traits;
mod utils;

use error::result::MResultHelper;
pub use error::{ModuleError, ModuleResult};
pub use utils::{test_decrypt, test_encrypt, test_generate_key};
