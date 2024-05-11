#!/bin/make
GOROOT:=$(shell PATH="/pkg/main/dev-lang.go.dev/bin:$$PATH" go env GOROOT)
GOPATH:=$(shell $(GOROOT)/bin/go env GOPATH)

all:
	$(GOPATH)/bin/goimports -w -l .
	$(GOROOT)/bin/go build -v ./...

deps:
	$(GOROOT)/bin/go get -v -t .

########################################
### Protocol Buffers

protob:
	@echo "--> Building Protocol Buffers"
	@for protocol in message signature ecdsa-keygen ecdsa-signing ecdsa-resharing eddsa-keygen eddsa-signing eddsa-resharing; do \
		echo "Generating $$protocol.pb.go" ; \
		protoc --go_out=. ./protob/$$protocol.proto ; \
	done

build: protob
	$(GOROOT)/bin/go fmt ./...

########################################
### Testing

test_unit:
	@echo "--> Running Unit Tests"
	@echo "!!! WARNING: This will take a long time :)"
	$(GOROOT)/bin/go clean -testcache
	$(GOROOT)/bin/go test -timeout 60m ./...

test_unit_race:
	@echo "--> Running Unit Tests (with Race Detection)"
	@echo "!!! WARNING: This will take a long time :)"
	$(GOROOT)/bin/go clean -testcache
	$(GOROOT)/bin/go test -timeout 60m -race ./...

test:
	make test_unit

########################################
### Pre Commit

pre_commit: build test

########################################

# To avoid unintended conflicts with file names, always add to .PHONY
# # unless there is a reason not to.
# # https://www.gnu.org/software/make/manual/html_node/Phony-Targets.html
.PHONY: protob build test_unit test_unit_race test

