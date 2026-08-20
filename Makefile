VERSION ?= 1.1.0

.PHONY: test vet check build

test:
	CGO_ENABLED=0 go test ./...

vet:
	CGO_ENABLED=0 go vet ./...

check: test vet

build: check
	VERSION=$(VERSION) sh scripts/build.sh
