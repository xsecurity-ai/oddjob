# Drone — the enumeration agent, with its tools already in the image.
#
# This container runs somewhere quite unlike the Oddjob one: inside a
# client's network, on a host someone else owns, often behind a proxy
# that logs everything and a firewall that allows very little. Three
# consequences shape the whole file.
#
# The tools are baked in. A Drone can install its own baseline at startup,
# which is right on a box you control and wrong here: it means the first
# thing a new agent does on a client's network is fetch packages from
# the internet. That is noise in their logs, a dependency on egress that
# may not exist, and a window where the agent is enrolled but cannot
# work. Everything in `Baseline` plus gospider is present before the
# container ever starts.
#
# It runs as root inside the container, with almost no capabilities.
# SYN scanning, OS detection and masscan need CAP_NET_RAW. The first
# version of this file put file capabilities on nmap and masscan and
# ran as an unprivileged user, which reads better and does not work:
# the capability is on the file and in the bounding set, but the
# process comes out of exec with CapEff 0 and nmap refuses. Claiming
# that arrangement while shipping something that silently connect-scans
# would be the exact failure this codebase keeps finding.
#
# So: uid 0 in the container, and the compose file drops every
# capability and adds back the two. Container root holding two
# capabilities is a smaller grant than a normal user account on the
# host, and the container is the boundary that matters here.
#
# Identity and spool live on a volume. The enrollment token is one-time:
# lose the identity and the agent cannot re-enroll, it has to be created
# again in Oddjob. Lose the spool and you lose results for scans that
# already ran against the client's estate. Neither belongs in a
# container layer.

# ---------------------------------------------------------------- go
#
# `--platform=$BUILDPLATFORM` pins this stage to the machine doing the
# building, and GOARCH below says what to emit. Without it, buildx runs
# the entire Go toolchain under QEMU to produce an arm64 image — and
# this stage does not just compile the agent, it compiles amass,
# nuclei, httpx and gospider from source. Four large Go programs under
# emulation took this image past forty-five minutes while the amd64
# leg finished in three.
#
# Nothing is lost by cross-compiling. Go's cross-compilation is
# first-class, CGO is off, and the output is decided by GOOS/GOARCH
# rather than by what the compiler happens to be running on.
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS build
WORKDIR /src

# Supplied by buildx. NO DEFAULTS — a default here does not mean
# "when buildx does not say", it means "always", and it silently wins
# over the value buildx provides:
#
#   ARG TARGETARCH=amd64   ->  amd64   even on --platform linux/arm64
#   ARG TARGETARCH         ->  arm64
#
# With the defaults this file shipped x86-64 binaries inside the arm64
# image. The Go-built half came out amd64 while nmap, masscan and
# gobuster — installed by apk in the arm64 runtime stage — came out
# aarch64, so the image ran until the moment anybody tasked a scan.
#
# Empty is correct for a plain `docker build` without buildx: Go reads
# an unset GOOS/GOARCH as "this host", which is what that case wants.
ARG TARGETOS
ARG TARGETARCH
ENV CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH

# ---- the third-party tools, BEFORE any of our own source -----------
#
# Ordering, not neatness. These four were below `COPY . .`, which put
# them downstream of every file in the repository: changing one line of
# the agent rebuilt amass, nuclei, httpx and gospider along with it.
# Measured at 70s for a one-character edit. Up here they depend on this
# Dockerfile and nothing else, so the ordinary case — someone changed
# the agent — reuses them.
#
# Versions are pinned rather than @latest/@master. Three reasons, in
# order of how much they matter: an agent that scans a client's estate
# should be a known build and not whatever upstream published this
# morning; an unpinned ref can change under us between the amd64 and
# arm64 legs and ship a manifest whose two halves hold different
# tools; and a moving ref is a moving cache key.
#
# No GOBIN, deliberately: `go install` refuses outright with "cannot
# install cross-compiled binaries when GOBIN is set". It writes to
# $GOPATH/bin when building for the host and $GOPATH/bin/$GOOS_$GOARCH
# when cross-compiling, so the binaries are collected from wherever
# they landed rather than directed at a fixed path.
ENV GOFLAGS=-buildvcs=false
ARG AMASS_VERSION=v4.2.0
ARG GOSPIDER_VERSION=v1.1.6
ARG NUCLEI_VERSION=v3.11.1
ARG HTTPX_VERSION=v1.12.0
# The module and build caches survive between builds on the same
# builder, so a version bump to one tool does not recompile the shared
# dependency graph of the other three.
#
# `mkdir -p /out` because this is now the first step that writes there.
# It used to be created as a side effect of `go build -o /out/drone`,
# which has moved below.
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/.cache/go-build,sharing=locked \
    mkdir -p /out \
 && go install "github.com/owasp-amass/amass/v4/cmd/amass@${AMASS_VERSION}" \
 && go install "github.com/jaeles-project/gospider@${GOSPIDER_VERSION}" \
 && go install "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION}" \
 && go install "github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION}" \
 && find "$(go env GOPATH)/bin" -type f -perm -u+x -exec mv -t /out {} +

# ---- then the agent itself ------------------------------------------
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/.cache/go-build,sharing=locked \
    go build -trimpath \
      -ldflags "-s -w -X github.com/xsecurity-ai/oddjob/drone/internal/config.Version=$(cat VERSION 2>/dev/null || echo docker)" \
      -o /out/drone ./cmd/drone

# Asserted, not assumed. The failure mode otherwise is an image that
# builds, pushes and ships with no nuclei in it, discovered the first
# time somebody tasks a scan against a client's estate.
RUN set -eu; \
    for b in drone amass gospider nuclei httpx; do \
      [ -x "/out/$b" ] || { echo "missing /out/$b"; ls -lR /out "$(go env GOPATH)/bin"; exit 1; }; \
    done; \
    ls -l /out


# -------------------------------------------------------- masscan
# From source because Wolfi has no masscan package — nmap, gobuster
# and bind-tools are all there, masscan is not. Built in the same
# distribution it will run in, so it links against that libpcap and
# not Debian's.
#
# Pinned to a tag, like the Go tools above: this binary sends packets
# at a client's estate at 11,600 pps, and "whatever main was that
# morning" is not an acceptable answer to which version did that.
FROM cgr.dev/chainguard/wolfi-base:latest@sha256:05d24163df148be377275af8374c16523a1dc7e19bf4f1c689784791553c5e45 AS masscan
ARG MASSCAN_VERSION=1.3.2
RUN apk add --no-cache build-base git libpcap-dev linux-headers \
 && git clone --depth 1 --branch "${MASSCAN_VERSION}" \
      https://github.com/robertdavidgraham/masscan /src \
 && make -C /src -j"$(nproc)" \
 && test -x /src/bin/masscan \
 && (/src/bin/masscan --version || true)
# `|| true` on the version print: masscan exits non-zero from
# --version. The build is proved by `test -x`; the print is for the
# log, so somebody reading a build can see which version went in.


# ----------------------------------------------------------- runtime
# Wolfi rather than Debian. Not distroless — this image cannot be:
# it is a box of scanners that shells out to nmap and masscan, and it
# needs root plus CAP_NET_RAW to do its job. What it does get is a
# 24 MB base that is rebuilt and patched continuously, against a
# bookworm-slim whose CVE list only grows between stable releases.
#
# Pinned by digest for the reason given in the oddjob image: the free
# tier publishes only mutable `latest`, and this repository's rule is
# that a mutable reference gets pinned.
FROM cgr.dev/chainguard/wolfi-base:latest@sha256:05d24163df148be377275af8374c16523a1dc7e19bf4f1c689784791553c5e45 AS runtime

# nmap pulls its NSE library with it, which is the only way scripts get
# here — a Drone cannot fetch individual scripts.
#
# `bind-tools` is Wolfi's name for what Debian calls `dnsutils`: dig,
# host, nslookup. There is no separate nmap-scripts package — Wolfi's
# nmap carries all 605 .nse files and script.db in the one package,
# which is checked below rather than hoped for.
RUN apk add --no-cache nmap gobuster bind-tools ca-certificates libpcap

COPY --from=masscan /src/bin/masscan /usr/local/bin/masscan

COPY --from=build /out/drone /usr/local/bin/drone
COPY --from=build /out/amass /usr/local/bin/amass
COPY --from=build /out/gospider /usr/local/bin/gospider
# In the image rather than installed on first use: an agent should not
# need to reach proxy.golang.org from inside a client's network to run
# the task it was just given, and a nuclei task that fails because the
# box is air-gapped is a worse answer than one that never had to ask.
COPY --from=build /out/nuclei /usr/local/bin/nuclei
COPY --from=build /out/httpx /usr/local/bin/httpx

# WorkDir holds identity.json (0600, the agent's private key) and the
# spool of results not yet delivered. Declared as a volume so a
# `docker run` that forgets `-v` still does not lose them on restart —
# the enrollment token is one-time, so a lost identity means creating
# the agent again in Oddjob, and a lost spool means losing results for
# scans that already ran against someone's estate.
# Every tool the agent shells out to, present and the right
# architecture. This image changed base from Debian to Wolfi, where
# masscan is built from source and nmap's scripts come from a
# different package layout — both are the kind of thing that fails
# silently at the point an operator tasks a scan against a client's
# estate, which is the worst possible place to discover it.
RUN set -eu; \
    for b in drone amass gospider nuclei httpx masscan nmap gobuster dig; do \
      command -v "$b" >/dev/null || { echo "missing: $b"; exit 1; }; \
    done; \
    n=$(find /usr/share/nmap/scripts -name '*.nse' | wc -l); \
    [ "$n" -gt 500 ] || { echo "only $n NSE scripts — nmap -sC would be crippled"; exit 1; }; \
    [ -f /usr/share/nmap/scripts/script.db ] || { echo "no script.db"; exit 1; }; \
    echo "tools present, $n NSE scripts"

# And the right architecture, which the block above only claimed.
#
# This is the check that was missing when `ARG TARGETARCH=amd64`
# shadowed buildx and put x86-64 binaries in the arm64 image. Nothing
# caught it: every tool was present, the image started, and it would
# have failed with "exec format error" the first time an operator
# tasked a scan from an arm64 host.
#
# Bytes 18-19 of an ELF header are e_machine. The expected value is
# read from nmap rather than written down, because nmap comes from
# apk in this stage and is therefore native to the image by
# construction — no table of architectures to get wrong, and it keeps
# working if a third platform is ever added.
RUN set -eu; \
    mach() { od -An -tx1 -j18 -N2 "$(command -v "$1")" | tr -d ' \n'; }; \
    want=$(mach nmap); \
    for b in drone amass gospider nuclei httpx masscan; do \
      got=$(mach "$b"); \
      [ "$got" = "$want" ] || { \
        echo "$b is ELF e_machine $got but this image is $want —"; \
        echo "cross-compilation targeted the wrong architecture."; \
        exit 1; }; \
    done; \
    echo "all binaries are e_machine $want"

RUN mkdir -p /var/lib/drone/work
VOLUME ["/var/lib/drone/work"]

WORKDIR /var/lib/drone
ENV DRONE_WORKDIR=/var/lib/drone/work

# Runs as root, deliberately, and this is the reasoning rather than an
# oversight.
#
# SYN scanning, OS fingerprinting and masscan need CAP_NET_RAW. The
# first version of this file set file capabilities on the binaries with
# setcap and dropped to a non-root user — and it did not work: file
# capabilities are not honoured through a Docker exec, so the process
# started with CapEff 0 and every privileged scan failed at runtime
# instead of at build time.
#
# What actually constrains this container is the RUN invocation, not a
# USER line: `--cap-drop=ALL --cap-add=NET_RAW --cap-add=NET_ADMIN`
# leaves root holding two capabilities out of about forty. See the
# README and docker-compose.yml, which both do this.
#
# nosemgrep: missing-user, missing-user-entrypoint
#
# No default server or key: an agent that starts without being told
# where to report is not useful, and baking either into an image that
# gets copied between engagements is how one client's agent ends up
# talking to another client's Oddjob.
ENTRYPOINT ["/usr/local/bin/drone"]
CMD ["run", "--workdir", "/var/lib/drone/work"]
