// Copyright 2024 Cosmian Tech SAS
// Changes made to the original code are
// licensed under the Business Source License version 1.1.
//
//Original code:
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

use std::fmt::{Debug, Display};

use bincode::Options;

use crate::MResult;

#[derive(serde::Serialize, serde::Deserialize, Hash)]
pub struct Id {
    pub label: String,
    pub hash: Vec<u8>,
}

impl Id {
    pub fn encode(&self) -> MResult<Vec<u8>> {
        Ok(bincode_opts().serialize(self)?)
    }

    pub fn decode(data: &[u8]) -> MResult<Id> {
        Ok(bincode_opts().deserialize(data)?)
    }
}

fn bincode_opts() -> impl Options {
    bincode::options()
        .with_limit(2048)
        .reject_trailing_bytes()
        .with_fixint_encoding()
}

impl Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {:x?}", self.label, self.hash)
    }
}

impl Debug for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// pub fn encode(id: &Id) -> MResult<Vec<u8>> {
//     Ok(bincode_opts().serialize(id)?)
// }
//
// pub fn decode(data: &[u8]) -> MResult<Id> {
//     Ok(bincode_opts().deserialize(data)?)
// }
