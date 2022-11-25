#!/bin/bash
#
# Before running this script, start a server (i.e.:`./crate/server/dev.sh`)
#

if [[ -z "$1" ]]; then
    BINARY="cargo run --all-features --"
else
    BINARY="$1"
fi


set -e
echo
echo "This runs a complete demo from the command line"
echo
echo "Generating the master keys:..."
res=$($BINARY cc init -p policy.json)
private_key_id=$(echo "$res" | awk -F 'Private key unique identifier: ' '{print $2}' | awk 'BEGIN {RS=""} {print $0}')
public_key_id=$(echo "$res" | awk -F 'Public key unique identifier: ' '{print $2}' | awk 'BEGIN {RS=""} {print $0}')
echo "Master keys: private: $private_key_id, public: $public_key_id"
echo " => OK"
echo
echo "Exporting the master keys..."
res=$($BINARY cc export -i $private_key_id -o /tmp/master_private_key.json)
res=$($BINARY cc export -i $public_key_id -o /tmp/master_public_key.json)
echo " => OK"
echo 
echo "Re-importing the master keys as master_private_key/master_public_key..."
res=$($BINARY cc import -i master_private_key -f /tmp/master_private_key.json -r)
res=$($BINARY cc import -i master_public_key -f /tmp/master_public_key.json -r)
echo " => OK"
echo
echo "Creating user key with access policy 'department::marketing && level::secret'..."
res=$($BINARY cc new -s $private_key_id "department::marketing && level::secret")
marketing_secret_key_id=$(echo "$res" | awk -F 'identifier: ' '{print $2}' | awk 'BEGIN {RS=""} {print $0}')
echo "... $marketing_secret_key_id ... and exporting it..."
res=$($BINARY cc export -i $marketing_secret_key_id -o /tmp/marketing_secret_key.json)
echo " => OK"
echo
echo "Creating user key with access policy '(department::marketing || department::finance) && level::top-secret'..."
res=$($BINARY cc new -s $private_key_id "(department::marketing || department::finance) && level::top-secret")
marketing_fin_top_secret_key_id=$(echo "$res" | awk -F 'identifier: ' '{print $2}' | awk 'BEGIN {RS=""} {print $0}')
echo "... $marketing_fin_top_secret_key_id ... and exporting it..."
res=$($BINARY cc export -i $marketing_fin_top_secret_key_id -o /tmp/marketing_fin_top_secret_key.json)
echo " => OK"
echo
echo "////////////////////////////////////////////////////////////////////////////////////"
echo "//  Encryption / Decryption"
echo "////////////////////////////////////////////////////////////////////////////////////"
echo
echo "Encrypting a message with attributes: department::marketing, level::secret ..."
res=$($BINARY cc encrypt --access-policy "department::marketing && level::secret" -p $public_key_id policy.json -o /tmp/policy_mkg_secret.enc)
echo "... and a message with attributes: department::marketing, level::top-secret."
res=$($BINARY cc encrypt --access-policy "department::marketing && level::top-secret" -p $public_key_id policy.json -o /tmp/policy_mkg_top_secret.enc)
echo " => OK"
echo
echo "Decrypting the message with attributes: department::marketing, level::secret"
echo "   1- with user key with access policy 'department::marketing && level::secret'... $marketing_secret_key_id ..."
res=$($BINARY cc decrypt -u $marketing_secret_key_id /tmp/policy_mkg_secret.enc -o /tmp/policy_mkg_secret.json)
echo "   2- with user key with access policy '(department::marketing || department::finance) && level::top-secret'... $marketing_fin_top_secret_key_id ..."
res=$($BINARY cc decrypt -u $marketing_fin_top_secret_key_id /tmp/policy_mkg_secret.enc -o /tmp/policy_mkg_secret.json)
echo " => OK"
echo
echo "Decrypting the message with attributes: department::marketing, level::top-secret"
echo "   1- with user key with access policy 'department::marketing && level::secret'... SHOULD FAIL !"
#### this should fail, catch the error
set +e
res=$($BINARY cc decrypt -u $marketing_secret_key_id /tmp/policy_mkg_top_secret.enc -o /tmp/policy_mkg_top_secret.json)
if [ $? -eq 0 ]; then
    echo "This decryption should have failed !"
    exit 1
fi
set -e
#### end
echo "   2- with user key with access policy '(department::marketing || department::finance) && level::top-secret'..."
res=$($BINARY cc decrypt  -u $marketing_fin_top_secret_key_id /tmp/policy_mkg_top_secret.enc -o /tmp/policy_mkg_top_secret.json)
echo " => OK"
echo
echo "////////////////////////////////////////////////////////////////////////////////////"
echo "//  Rotate the Marketing Attribute"
echo "////////////////////////////////////////////////////////////////////////////////////"
echo
echo "First export the user key with access policy '(department::marketing || department::finance) && level::top-secret'... $marketing_fin_top_secret_key_id ..."
res=$($BINARY cc export -i $marketing_fin_top_secret_key_id -o /tmp/marketing_fin_top_secret_key_old.json)
echo " => OK"
echo
echo "Rotate the department::marketing attribute..."
res=$($BINARY cc rotate -s $private_key_id -a department::marketing)
echo " => OK"
echo
echo "Encrypting a NEW message with attributes: department::marketing, level::secret ..."
res=$($BINARY cc encrypt --access-policy "department::marketing && level::secret" -p $public_key_id policy.json -o /tmp/policy_mkg_secret_new.enc)
echo " => OK"
echo
echo "Decrypt the NEW message with attributes: department::marketing, level::secret"
echo "   1- with user key with access policy 'department::marketing && level::secret'... $marketing_secret_key_id ..."
res=$($BINARY cc decrypt  -u $marketing_secret_key_id /tmp/policy_mkg_secret_new.enc -o /tmp/policy_mkg_secret.json)
echo "   2- with user key with access policy '(department::marketing || department::finance) && level::top-secret'... $marketing_fin_top_secret_key_id ..."
res=$($BINARY cc decrypt  -u $marketing_fin_top_secret_key_id /tmp/policy_mkg_secret_new.enc -o /tmp/policy_mkg_secret.json)
echo " => OK"
echo 
echo "Re-import the OLD user key with access policy '(department::marketing || department::finance) && level::top-secret'... marketing_fin_top_secret_key_old_id ..."
res=$($BINARY cc import -i marketing_fin_top_secret_key_old_id -f /tmp/marketing_fin_top_secret_key_old.json -r)
echo " => OK"
echo
echo "Decrypting the NEW message the old key marketing_fin_top_secret_key_old_id SHOULD FAIL !"
#### this should fail, catch the error
set +e
res=$($BINARY cc decrypt  -u marketing_fin_top_secret_key_old_id /tmp/policy_mkg_secret_new.enc -o /tmp/policy_mkg_secret_new.json)
if [ $? -eq 0 ]; then
    echo "This decryption should have failed !"
    exit 1
fi
set -e
echo $res

echo "SUCCESS!"