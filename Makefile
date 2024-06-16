SHELL := /bin/bash

ifndef VERBOSE
.SILENT:
endif

# Version info
VERSION := $(shell cat VERSION)
GIT_COMMIT := $(shell git rev-parse --short HEAD)
GIT_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
BUILD_USER := $(USER)@$(shell hostname)
BUILD_DATE := $(shell date +"%FT%T")
BINARY := netgear_cm_exporter
IMAGE := dnesting/$(BINARY)

# Go command flags
export GO111MODULE=on
GOFLAGS := -v

# Linker flags
LDFLAGS := \
	-X main.version=$(VERSION) \
	-X main.revision=$(GIT_COMMIT) \
	-X main.branch=$(GIT_BRANCH) \
	-X main.buildUser=$(BUILD_USER) \
	-X main.buildDate=$(BUILD_DATE)

SRC_PACKAGES := $(shell go list ./...)

.PHONY: all build test vet staticcheck ci prereq clean docker push

all: test build

build:
	echo ">> $@"
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" .

test:
	echo ">> $@"
	go test -race $(GOFLAGS) ./...

vet:
	echo ">> $@"
	go vet $(SRC_PACKAGES)

staticcheck:
	echo ">> $@"
	staticcheck $(SRC_PACKAGES)

ci: vet staticcheck test

prereq:
	go install honnef.co/go/tools/cmd/staticcheck@2023.1.2

clean:
	rm -f $(BINARY)

docker:
	echo ">> $@"
	docker buildx build \
		-t $(IMAGE):$(VERSION) \
		-t $(IMAGE):latest \
		--load \
		--build-arg LDFLAGS="$(LDFLAGS)" \
		.

push:
	echo ">> $@"
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		-t $(IMAGE):$(VERSION) \
		-t $(IMAGE):latest \
		--push \
		--build-arg LDFLAGS="$(LDFLAGS)" \
		.
