#!/bin/bash

./trustd &

APP_PID=$!

while ! curl -s localhost:8080 > /dev/null; do
    echo "Waiting for trustify..."
    sleep 5 # MSP pattern
done

echo "Available on localhost:8080"

./e2e

kill $APP_PID
