#!/bin/bash

./trustd &

APP_PID=$!

while ! curl -s localhost:8080 > /dev/null; do
    echo "Waiting for trustify..."
    sleep 5 # MSP pattern
done

echo "Available on localhost:8080"

HTTP_STATUS=$(curl -o /dev/null -s -w "%{http_code}" localhost:8080)

if [ "$HTTP_STATUS" -eq 200 ]; then
    TEST_OUTPUT="SUCCESS"
else
    TEST_OUTPUT="FAILURE"
fi

echo "Result: $TEST_OUTPUT"

kill $APP_PID
