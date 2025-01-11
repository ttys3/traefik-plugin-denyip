#!/bin/sh

go build -o init-db cmd/init-db/main.go


./init-db -input examples/blocklist.txt -redis-addr localhost:6379 -key-prefix denyip