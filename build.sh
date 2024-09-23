#!/usr/bin/env bash

test -f tinygo/bin/tinygo || (curl -LZO https://github.com/tinygo-org/tinygo/releases/download/v0.33.0/tinygo0.33.0.linux-amd64.tar.gz && tar xvzf tinygo0.33.0.linux-amd64.tar.gz)

tinygo/bin/tinygo build -o plugin.wasm -scheduler=none --no-debug -target=wasi .
