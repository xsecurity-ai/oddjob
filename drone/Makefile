BINARY  := drone

# The version comes out of ../VERSION, through ../scripts/version.sh,
# and from nowhere else.
#
# It used to be `git describe --tags --always --dirty`, which produced
# strings like `v0.1.0-14-gdeadbee-dirty`. That is a useful thing for a
# human to read and a poor thing to put in a column of versions: it is
# not semver, it does not sort, and it says "fourteen commits after
# v0.1.0" where the fleet summary needs "which release is this". The
# tag it described was also chosen by promote.yml rather than by
# anything in the source, so two agents built from the same commit
# before and after a promotion reported different versions.
#
# Unreleased builds get `-dev-<unix time of HEAD>` appended; pass
# ODDJOB_RELEASE=1, or `make release ODDJOB_RELEASE=1`, for the bare
# number. That is the default-is-safe direction: forgetting the flag
# costs a `-dev-` on a local binary, and forgetting it the other way
# round would ship an unreleasable string on a published one. CI sets
# it for the release build and checks the result.
#
# `|| echo dev` covers the agent source being built outside a full
# checkout — a vendored copy, say. Not silently: `dev` is not a
# version, nothing accepts it as one, and scripts/check-version.sh
# rejects it as an artefact version.
VERSION ?= $(shell ../scripts/version.sh 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/xsecurity-ai/oddjob/drone/internal/config.Version=$(VERSION)
DIST    := dist

.PHONY: build release test vet clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/drone

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
			-ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY)-$$os-$$arch$$ext ./cmd/drone || exit 1; \
	done
	@cd $(DIST) && shasum -a 256 * > SHA256SUMS 2>/dev/null || sha256sum * > SHA256SUMS
	@ls -la $(DIST)

clean:
	rm -rf $(DIST) $(BINARY)
