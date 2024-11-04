.PHONY: clean build test

clean:
	rm -f notify

build:
	go build -o notify .

test:
	go test -v ./...
