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

# Use the MONGO_INITDB_DATABASE environment variable for the database name.
# The --file path is now relative to the container's root or the working directory, which is '/'.
# Since '/seed' is mounted, '/seed/UserAccounts.json' is the correct path.
mongoimport --db "$MONGO_INITDB_DATABASE" \
            --collection UserAccounts \
            --file "/seed/UserAccounts.json" \
            --jsonArray \
            --username "$MONGO_INITDB_ROOT_USERNAME" \
            --password "$MONGO_INITDB_ROOT_PASSWORD" \
            --authenticationDatabase admin

echo "Data import complete!"