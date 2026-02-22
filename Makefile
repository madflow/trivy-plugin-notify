.PHONY: clean build lint test

clean:
	rm -f notify

build:
	go build -o notify .

test:
	go test -v ./...

lint:
	golangci-lint run

fix:
	go fix ./...
