BINARY  := nostr-notify
MODULE  := github.com/jubbink/nostr-notify
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build build-linux build-openbsd build-freebsd clean tidy

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

build-linux:
	GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64   .

build-openbsd:
	GOOS=openbsd GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-openbsd-amd64 .

build-freebsd:
	GOOS=freebsd GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-freebsd-amd64 .

dist:
	mkdir -p dist

build-all: dist build-linux build-openbsd build-freebsd

clean:
	rm -f $(BINARY) dist/$(BINARY)-*

tidy:
	go mod tidy
