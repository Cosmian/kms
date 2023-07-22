use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use async_trait::async_trait;
use cloudproof::reexport::crypto_core::{
    reexport::rand_core::{RngCore, SeedableRng},
    CsRng,
};
use cosmian_findex::{
    parameters::{MASTER_KEY_LENGTH, UID_LENGTH},
    EncryptedTable, FindexCallbacks, FindexCompact, FindexSearch, FindexUpsert, IndexedValue,
    KeyingMaterial, Keyword, Label, Location, Uid, UpsertData,
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
pub async fn test_compact() -> Result<(), FindexError> {
    log_init("cosmian_findex_redis=trace");
    trace!("test_compact");

    // load the dataset and create the list of keywords to be indexed
    let dataset = Arc::new(Dataset::new());
    trace!("employees dataset size: {:?}", dataset.len().await);

    // let f: FindRemovedLocations = Box::new(|s| Box::pin(dataset.find_removed_locations(s)));
    let mut findex = FindexRedis::connect(REDIS_URL, dataset.clone()).await?;
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

    // now remove the index 19 from Findex
    let employee_19 = dataset.get(19).await.unwrap();
    let keywords_19 = employee_19.keywords();
    let mut deletions: HashMap<IndexedValue, HashSet<Keyword>> = HashMap::new();
    deletions.insert(
        IndexedValue::from(Location::from(19_u16.to_be_bytes().as_slice())),
        keywords_19,
    );

    // employee 19 should not appear in search results anymore
    findex
        .upsert(&master_key, &new_label, HashMap::new(), deletions)
        .await?;
    let updated_result = FRANCE_LOCATIONS
        .into_iter()
        .filter(|v| *v != 17 && *v != 19)
        .collect::<Vec<u16>>();
    assert_french_search(&mut findex, &master_key, &new_label, &updated_result).await;

    // compact the dataset
    findex
        .compact(&master_key, &master_key, &new_label, 1)
        .await?;

    // search should still be the same
    let updated_result = FRANCE_LOCATIONS
        .into_iter()
        .filter(|v| *v != 17 && *v != 19)
        .collect::<Vec<u16>>();
    assert_french_search(&mut findex, &master_key, &new_label, &updated_result).await;

    // note: employee 19 is still in the database but not in the index anymore
    assert!(dataset.get(19).await.is_some());

    Ok(())
}

async fn assert_french_search(
    findex: &mut FindexRedis,
    master_key: &KeyingMaterial<MASTER_KEY_LENGTH>,
    label: &Label,
    expected_values: &[u16],
) {
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

#[tokio::test]
#[serial]
pub async fn test_upsert_conflict() -> Result<(), FindexError> {
    log_init("cosmian_findex_redis=trace");
    trace!("test_upsert_conflict");

    struct DummyDataset;

    #[async_trait]
    impl RemovedLocationsFinder for DummyDataset {
        async fn find_removed_locations(
            &self,
            _locations: HashSet<Location>,
        ) -> Result<HashSet<Location>, FindexError> {
            Ok(HashSet::new())
        }
    }
    let dummy = Arc::new(DummyDataset {});

    // let f: FindRemovedLocations = Box::new(|s| Box::pin(dataset.find_removed_locations(s)));
    let mut findex = FindexRedis::connect(REDIS_URL, dummy.clone()).await?;
    findex.clear_indexes().await?;

    // generate 333 random Uids
    let mut rng = CsRng::from_entropy();
    let mut uids: HashSet<Uid<UID_LENGTH>> = HashSet::with_capacity(333);
    loop {
        let mut buffer = [0_u8; UID_LENGTH];
        rng.fill_bytes(&mut buffer);
        uids.insert(Uid::from(buffer));
        if uids.len() == 333 {
            break
        }
    }
    let uids = uids.iter().collect::<Vec<&Uid<UID_LENGTH>>>();

    const ORIGINAL_BYTES: &[u8; 8] = b"original";
    const CHANGED_BYTES: &[u8; 7] = b"changed";
    const NEW_BYTES: &[u8; 3] = b"new";

    // the original state is what the user would have fetched before changing the table
    let mut original_state: HashMap<Uid<UID_LENGTH>, Vec<u8>> = HashMap::new();
    for uid in &uids {
        original_state.insert(**uid, ORIGINAL_BYTES.to_vec());
    }
    let rejected = findex
        .upsert_entry_table(UpsertData::new(
            &EncryptedTable::from(HashMap::new()),
            EncryptedTable::from(original_state.clone()),
        ))
        .await?;
    assert!(rejected.is_empty());

    // now simulate that an other user has changed the state of 111 Uids
    let mut changed_state: HashMap<Uid<UID_LENGTH>, Vec<u8>> = HashMap::new();
    for (idx, uid) in uids.iter().enumerate() {
        if idx % 3 == 0 {
            changed_state.insert(**uid, CHANGED_BYTES.to_vec());
        } else {
            changed_state.insert(**uid, ORIGINAL_BYTES.to_vec());
        }
    }
    let rejected = findex
        .upsert_entry_table(UpsertData::new(
            &EncryptedTable::from(original_state.clone()),
            EncryptedTable::from(changed_state.clone()),
        ))
        .await?;
    assert!(rejected.is_empty());

    // prepare a new state for the first user
    let mut new_state: HashMap<Uid<UID_LENGTH>, Vec<u8>> = HashMap::new();
    for uid in &uids {
        new_state.insert(**uid, NEW_BYTES.to_vec());
    }

    // the first user is trying to update the table with its new state but knowing the original state
    let rejected = findex
        .upsert_entry_table(UpsertData::new(
            &EncryptedTable::from(original_state),
            EncryptedTable::from(new_state),
        ))
        .await?;
    assert_eq!(111, rejected.len());
    for (uid, prev_value) in rejected {
        assert!(changed_state.contains_key(&uid));
        assert_eq!(prev_value, CHANGED_BYTES.to_vec());
    }

    Ok(())
}
