#!/bin/bash

# Wait for MongoDB to be ready. This is crucial as mongoimport needs the server to be up.
# The 'docker-entrypoint.sh' script (which runs this init script) usually ensures MongoDB is listening,
# but a small delay or a check can prevent race conditions.
echo "Waiting for MongoDB to start..."
until mongosh --host 127.0.0.1 --port 27017 -u "$MONGO_INITDB_ROOT_USERNAME" -p "$MONGO_INITDB_ROOT_PASSWORD" --authenticationDatabase admin --eval "print(\"MongoDB is ready!\")" > /dev/null 2>&1; do
  printf '.'
  sleep 1
done
echo "MongoDB is up and running. Importing data..."

# Define common mongoimport options for reusability
MONGO_IMPORT_COMMON_OPTS="--db \"$MONGO_INITDB_DATABASE\" --jsonArray --username \"$MONGO_INITDB_ROOT_USERNAME\" --password \"$MONGO_INITDB_ROOT_PASSWORD\" --authenticationDatabase admin"

# --- Import UserAccounts collection ---
echo "Importing UserAccounts collection..."
mongoimport $MONGO_IMPORT_COMMON_OPTS \
            --collection UserAccounts \
            --file "/seed/UserAccounts.json"

# --- Import Folders collection ---
# Assumes 'Folders.json' exists in the /seed directory
echo "Importing Folders collection..."
mongoimport $MONGO_IMPORT_COMMON_OPTS \
            --collection Folders \
            --file "/seed/Folders.json"

# --- Import Items collection ---
# Assumes 'Items.json' exists in the /seed directory
echo "Importing Items collection..."
mongoimport $MONGO_IMPORT_COMMON_OPTS \
            --collection Items \
            --file "/seed/Items.json"

echo "All data imports complete!"