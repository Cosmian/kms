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

use bincode::Options;

use crate::MResult;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Id {
    pub label: Option<String>,
    pub hash: Vec<u8>,
}

fn bincode_opts() -> impl bincode::Options {
    bincode::options()
        .with_limit(2048)
        .reject_trailing_bytes()
        .with_fixint_encoding()
}

pub fn encode(id: &Id) -> MResult<Vec<u8>> {
    Ok(bincode_opts().serialize(id)?)
}

pub fn decode(data: &[u8]) -> MResult<Id> {
    Ok(bincode_opts().deserialize(data)?)
}
