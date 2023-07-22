use std::{
    collections::{HashMap, HashSet},
    fs,
};

use cosmian_findex::{Keyword, Location};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::trace;

use crate::{FindexError, RemovedLocationsFinder};

mod findex;
pub(crate) mod log_utils;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Employee {
    id: u32,
    #[serde(rename = "firstName")]
    first_name: String,
    #[serde(rename = "lastName")]
    last_name: String,
    phone: String,
    email: String,
    country: String,
    region: String,
    #[serde(rename = "employeeNumber")]
    employee_number: String,
    security: String,
}

impl Employee {
    fn keywords(&self) -> HashSet<Keyword> {
        let mut keywords = HashSet::new();
        keywords.insert(Keyword::from(self.first_name.as_bytes()));
        keywords.insert(Keyword::from(self.last_name.as_bytes()));
        keywords.insert(Keyword::from(self.phone.as_bytes()));
        keywords.insert(Keyword::from(self.email.as_bytes()));
        keywords.insert(Keyword::from(self.country.as_bytes()));
        keywords.insert(Keyword::from(self.region.as_bytes()));
        keywords.insert(Keyword::from(self.employee_number.as_bytes()));
        keywords.insert(Keyword::from(self.security.as_bytes()));
        keywords
    }
}

fn load_employees_from_file() -> HashMap<u16, Employee> {
    // Read the file to a string
    let data = fs::read_to_string("./src/tests/employees.json").unwrap();

    // Deserialize the string data into a vector of User objects
    let employees: Vec<Employee> = serde_json::from_str(&data).unwrap();
    let mut dataset = HashMap::new();
    for (index, employee) in employees.into_iter().enumerate() {
        dataset.insert(index as u16, employee);
    }
    dataset
}

struct Dataset(RwLock<HashMap<u16, Employee>>);
impl Dataset {
    fn new() -> Self {
        let dataset = load_employees_from_file();
        Self(RwLock::new(dataset))
    }

    async fn get(&self, index: u16) -> Option<Employee> {
        self.0.read().await.get(&index).cloned()
    }

    async fn remove(&self, index: u16) {
        self.0.write().await.remove(&index);
    }

    async fn len(&self) -> usize {
        self.0.read().await.len()
    }

    async fn all_values(&self) -> HashMap<u16, Employee> {
        self.0.read().await.clone()
    }
}

impl RemovedLocationsFinder for Dataset {
    async fn find_removed_locations(
        &self,
        locations: HashSet<Location>,
    ) -> Result<HashSet<Location>, FindexError> {
        trace!("find_removed_locations {}", locations.len());
        let mut removed_locations = HashSet::new();
        for location in &locations {
            let bytes: &[u8] = location;
            let index = u16::from_be_bytes(bytes.try_into()?);
            if !&self.0.read().await.contains_key(&index) {
                removed_locations.insert(location.clone());
            }
        }
        trace!("find_removed_locations: found {}", removed_locations.len());
        Ok(removed_locations)
    }
}
