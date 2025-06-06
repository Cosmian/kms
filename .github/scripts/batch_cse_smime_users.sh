#!/bin/bash

CSE_KEY_ID="google_cse"
ISSUER_PRIVATE_KEY_ID="9ef8d4e3-556c-44c4-9377-7fb32ce9c70d"
USER_LIST_FILE="users.txt"
LOG_FILE="provision_log.csv"

# Create or overwrite log file
echo "email,keypair_id,status" > "$LOG_FILE"

# Loop over user emails
while IFS= read -r USER_EMAIL; do
    echo "Processing $USER_EMAIL"

    # Create the DN (Distinguished Name) string
    SUBJECT_NAME="C=FR, ST=IdF, L=Paris, O=Cosmian, OU=R&D, CN=$USER_EMAIL, emailAddress=$USER_EMAIL"

    # Run key-pair creation command and capture output
    CREATE_OUTPUT=$(./target/debug/cosmian kms google key-pairs create \
        --cse-key-id "$CSE_KEY_ID" \
        --subject-name "$SUBJECT_NAME" \
        -i "$ISSUER_PRIVATE_KEY_ID" "$USER_EMAIL" 2>&1)

    # Extract the key-pair ID (assuming it's the last line or in the output)
    KEYPAIR_ID=$(echo "$CREATE_OUTPUT" | grep -Eo 'keypair-[a-zA-Z0-9]+')

    if [[ -n "$KEYPAIR_ID" ]]; then
        # Insert identity
        INSERT_OUTPUT=$(./target/debug/cosmian kms google identities insert \
            --user-id "$USER_EMAIL" "$KEYPAIR_ID" 2>&1)

        if [[ $? -eq 0 ]]; then
            echo "$USER_EMAIL,$KEYPAIR_ID,success" >> "$LOG_FILE"
        else
            echo "$USER_EMAIL,$KEYPAIR_ID,identity-insert-failed: $INSERT_OUTPUT" >> "$LOG_FILE"
        fi
    else
        echo "$USER_EMAIL,,keypair-create-failed: $CREATE_OUTPUT" >> "$LOG_FILE"
    fi

done < "$USER_LIST_FILE"

echo "Done provisioning users. See $LOG_FILE for results."
