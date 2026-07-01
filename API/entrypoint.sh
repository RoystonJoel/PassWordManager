#!/bin/sh

# Load a single secret file into an env variable
if [ -f /run/secrets/DB_FILE ]; then
    export DB_FILE_PATH=$(cat /run/secrets/DB_FILE)
fi

if [ -f /run/secrets/JWT_SECRET ]; then
    export JWT_SECRET_KEY=$(cat /run/secrets/JWT_SECRET)
fi

if [ -f /run/secrets/JWT_ALGORITHM ]; then
    export JWT_ALGORITHM=$(cat /run/secrets/JWT_ALGORITHM)
fi

if [ -f /run/secrets/TOKEN_EXPIRE ]; then
    export ACCESS_TOKEN_EXPIRE_MINUTES=$(cat /run/secrets/TOKEN_EXPIRE)
fi

if [ -f /run/secrets/SECRET_SERVER_PEPPER ]; then
    export SECRET_SERVER_PEPPER=$(cat /run/secrets/SECRET_SERVER_PEPPER)
fi

# Execute the container's main command
exec "$@"
