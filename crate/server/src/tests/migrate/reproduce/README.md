## About this folder

The folder contains the necessary material to reproduce in the most quick yet loyal manner the artifacts used for the redis migration tests, ie. `findex_redis_migration_tests`.

## Reproduction steps

1. Clone the cli repository : <https://github.com/Cosmian/cli> . For minimum hazards, pull `develop` branch and checkout the commit 961c7d2
2. Run a redis DB with the method of your choice on the default localhost port (6379)
3. Run the following command to pull the KMS :

```bash
docker run -p 9998:9998 --rm --name kms_demo \
  --network host \
  ghcr.io/cosmian/kms:5.2.0 \
  --database-type redis-findex \
  --database-url redis://127.0.0.1:6379 \
  --redis-master-password password \
  --redis-findex-label label
  --clear-database
```

4. Build the cli project (`cargo b --all-targets --all-features`)
5. From **the root folder**, copy paste the `populate_5_2_db.sh`, make it executable (chmod +x ...) and then execute it. The KMS will be populated.
6. Create (or open) some rust project, where you paste the content of the redis_dump_utils.rs file.
7. Run sequentially `dump_all` then `verify_dump`
8. For the test `from_5_1_0_to_5_12_0`, most the steps are identical (except step 5) - refer to the test comments for the step 5.
