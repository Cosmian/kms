## Testing

- Add 3 non-regression test vectors for FortiGate KMIP Locate name filtering:
    - `fortigate_locate_many_similar_names`: 8 keys with confusingly similar names, verifies strict isolation (40 steps)
    - `fortigate_locate_multi_tunnel`: 6 keys across 3 tunnel configs, verifies no cross-tunnel contamination (30 steps)
    - `fortigate_locate_no_match`: proves no partial/substring matching (substring, superstring, non-existent names all return 0 results)
