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
FROM golang:1.26-bookworm AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/xsecurity-ai/oddjob/drone/internal/config.Version=$(cat VERSION 2>/dev/null || echo docker)" \
      -o /out/drone ./cmd/drone

# The two tools no distribution packages. Built here rather than
# `go install`-ed at runtime for the reason in the header: an agent
# should not need to reach proxy.golang.org from inside a client's
# network to become useful.
ENV GOFLAGS=-buildvcs=false
RUN GOBIN=/out go install github.com/owasp-amass/amass/v4/cmd/amass@master \
 && GOBIN=/out go install github.com/jaeles-project/gospider@latest \
 && GOBIN=/out go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
 && GOBIN=/out go install github.com/projectdiscovery/httpx/cmd/httpx@latest


# ----------------------------------------------------------- runtime
FROM debian:bookworm-slim AS runtime

# nmap pulls its NSE library with it, which is the only way scripts get
# here — a Drone cannot fetch individual scripts.
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap masscan gobuster \
      ca-certificates dnsutils \
 && rm -rf /var/lib/apt/lists/*

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
