use std::collections::{HashMap, HashSet};

use cloudproof::reexport::crypto_core::{reexport::rand_core::SeedableRng, CsRng};
use cosmian_findex::{
    parameters::MASTER_KEY_LENGTH, FindexCompact, FindexSearch, FindexUpsert, IndexedValue,
    KeyingMaterial, Keyword, Label, Location,
};
use serial_test::serial;
use tracing::trace;

use crate::{
    tests::{log_utils::log_init, Dataset},
    FindexError, FindexRedis, RemovedLocationsFinder,
};

// starting redis server
// docker run --name redis -p 6379:6379 -d redis

const REDIS_URL: &str = "redis://localhost:6379";
const FRANCE_LOCATIONS: [u16; 30] = [
    4, 5, 7, 8, 14, 17, 19, 20, 23, 34, 37, 43, 46, 48, 55, 56, 60, 61, 63, 65, 68, 70, 71, 77, 80,
    82, 83, 85, 86, 96,
];

#[tokio::test]
#[serial]
pub async fn test_upsert_and_compact() -> Result<(), FindexError> {
    log_init("cosmian_findex_redis=trace");
    trace!("test_upsert");

    // load the dataset and create the list of keywords to be indexed
    let dataset = Dataset::new();
    trace!("employees dataset size: {:?}", dataset.len().await);

    // let f: FindRemovedLocations = Box::new(|s| Box::pin(dataset.find_removed_locations(s)));
    let mut findex = FindexRedis::connect(REDIS_URL, &dataset).await?;
    findex.clear_indexes().await?;

    let mut rng = CsRng::from_entropy();
    let master_key = KeyingMaterial::<MASTER_KEY_LENGTH>::new(&mut rng);

    let label = Label::random(&mut rng);

    let mut additions: HashMap<IndexedValue, HashSet<Keyword>> = HashMap::new();
    for (index, employee) in dataset.all_values().await.iter() {
        // for the Location, we use the index of the employee in the dataset
        let iv = IndexedValue::from(Location::from(index.to_be_bytes().as_slice()));
        // for the keywords, we use the employee's attributes
        let keywords = employee.keywords();
        additions.insert(iv, keywords);
    }

    // perform inserts
    findex
        .upsert(&master_key, &label, additions, HashMap::new())
        .await?;

    //search for the "France" keyword
    assert_french_search(&mut findex, &master_key, &label, &FRANCE_LOCATIONS).await;

    // compact the index, changing the label
    let new_label = Label::random(&mut rng);
    findex
        .compact(&master_key, &master_key, &new_label, 1)
        .await?;

    // search should be empty with old label
    assert_french_search(&mut findex, &master_key, &label, &[]).await;

    // search should be ok with new label
    assert_french_search(&mut findex, &master_key, &new_label, &FRANCE_LOCATIONS).await;

    // remove the index 17 from the Dataset
    dataset.remove(17).await;

    // compact the dataset
    findex
        .compact(&master_key, &master_key, &new_label, 1)
        .await?;

    // search should be ok with new label
    let updated_result = FRANCE_LOCATIONS
        .into_iter()
        .filter(|v| *v != 17)
        .collect::<Vec<u16>>();
    assert_french_search(&mut findex, &master_key, &new_label, &updated_result).await;

    Ok(())
}

async fn assert_french_search<'a, F>(
    findex: &mut FindexRedis<'a, F>,
    master_key: &KeyingMaterial<MASTER_KEY_LENGTH>,
    label: &Label,
    expected_values: &[u16],
) where
    F: RemovedLocationsFinder,
{
    let keyword = Keyword::from("France".as_bytes());
    let search = findex
        .search(master_key, label, HashSet::from([keyword.clone()]))
        .await
        .unwrap();
    assert!(search.len() == 1);
    assert!(search.get(&keyword).is_some());
    let locations = search.get(&keyword).unwrap();
    assert!(locations.len() == expected_values.len());
    for location in locations {
        let bytes: &[u8] = location;
        let index = u16::from_be_bytes(bytes.try_into().unwrap());
        assert!(
            expected_values.contains(&index),
            "index {} not found",
            index
        );
    }
}
