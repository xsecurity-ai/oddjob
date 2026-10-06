BINARY  := jaws
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/xsecurity-ai/oddjob/jaws/internal/config.Version=$(VERSION)
DIST    := dist

.PHONY: build release test vet clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/jaws

vet:
	go vet ./...

test:
	go test ./...

# Static binaries for every platform the agent is expected to land on.
# CGO off so there is no libc to match: an agent that will not start on
# the one box you can reach is worth nothing.
release: clean
	@mkdir -p $(DIST)
	@for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do \
		os=$${target%/*}; arch=$${target#*/}; \
		ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
		echo "  $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath \
			-ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY)-$$os-$$arch$$ext ./cmd/jaws || exit 1; \
	done
	@cd $(DIST) && shasum -a 256 * > SHA256SUMS 2>/dev/null || sha256sum * > SHA256SUMS
	@ls -la $(DIST)

clean:
	rm -rf $(DIST) $(BINARY)
