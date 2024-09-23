.PHONY: lint test vendor clean

export GO111MODULE=on

default: lint test build

lint:
	golangci-lint run

test:
	go test -v -cover ./...

build:
	@tinygo build -o plugin.wasm -scheduler=none --no-debug -target=wasi .

clean:
	rm -rf ./vendor