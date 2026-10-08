# Oddjob — one image serving the API and the built UI.
#
# The backend serves `frontend/dist` itself, so there is no second
# container and no reverse proxy to configure. The path matters: the
# app resolves the UI as `<repo>/frontend/dist` relative to its own
# module, so the layout inside the image mirrors the repository.

# ---------------------------------------------------------------- UI
# Built on the build machine, not the target. `npm run build` emits
# JavaScript, which is the same bytes whatever the architecture — so
# running node and the whole dependency tree under QEMU to produce an
# arm64 image buys nothing and costs most of the build.
FROM --platform=$BUILDPLATFORM node:22-alpine AS ui
WORKDIR /build/frontend

# Dependencies first: this layer is rebuilt only when the lockfile
# changes, which is what keeps an edit to one .tsx file off the
# critical path.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build


# -------------------------------------------------------- drone agents
# The agent binaries the UI hands out when deploying a Drone. Built here
# so an operator can download one from the Oddjob they are already
# logged into, rather than being sent to find a release elsewhere and
# having to trust whatever they find.
#
# All six targets, because the host an agent is needed on is whatever
# the client has. Static (CGO_ENABLED=0) so they run on the older glibc
# they will meet in the field.
#
# `--platform=$BUILDPLATFORM` for the same reason as the UI stage, and
# more obviously here: this loop already names its own GOOS and GOARCH
# for every target, so the six binaries are byte-identical regardless
# of what the compiler runs on. Emulating the toolchain to produce
# them was pure cost.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS drone
WORKDIR /build/drone

COPY drone/go.mod drone/go.sum ./
RUN go mod download

# The repository-root VERSION file, into the Go build directory, so the
# line below can stamp it. Copied before the source for cache reasons:
# it changes once per release and the agent changes every day, and the
# other order would invalidate six cross-compiles on every edit.
#
# Note what is NOT here: a build argument. These six binaries are
# handed out by the Oddjob UI to be run inside a client's network, and
# the version they report on register is how an operator answers "which
# agent produced this scan". A build argument is something a caller can
# forget, get wrong, or quietly default; the file is the one place the
# version is decided (see scripts/version.sh) and reading it directly
# is the arrangement with no second answer.
#
# No `-dev-` suffix, and that is also deliberate — an image build is a
# release path. scripts/version.sh only adds the suffix when nobody has
# said `--release`, and ci.yml reads these binaries' version back and
# fails if one carries it.
COPY VERSION ./VERSION

COPY drone/ ./
RUN set -eu; \
    ver="$(tr -d '[:space:]' < VERSION)"; \
    [ -n "$ver" ] || { echo "VERSION is empty"; exit 1; }; \
    echo "stamping drone binaries as $ver"; \
    for t in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 \
             windows/amd64 windows/arm64; do \
      os="${t%/*}"; arch="${t#*/}"; \
      out="dist/drone-$os-$arch"; \
      [ "$os" = windows ] && out="$out.exe"; \
      CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
        go build -trimpath \
          -ldflags "-s -w -X github.com/xsecurity-ai/oddjob/drone/internal/config.Version=$ver" \
          -o "$out" ./cmd/drone; \
    done; \
    ls -l dist/


# ------------------------------------------------------- python deps
# A separate stage purely so `uv` (45 MB) and its caches do not ship.
#
# On Chainguard's python rather than python:3.13-slim, and not as a
# hardening measure — this stage is discarded. A virtualenv is bound to
# the interpreter that built it: `/opt/venv/lib/python3.13/site-packages`
# is not on 3.14's path. The runtime below is Chainguard's python, so
# this one has to be the same python or nothing imports. `-dev` is the
# same image with a shell and apk, which uv needs.
FROM cgr.dev/chainguard/python:latest-dev@sha256:630df1be3733f7b38d1b535872904248adfe23fbea4befcb08da47cb7436ddb2 AS deps
# Root because this stage installs: uv puts the virtualenv in /opt/venv and
# its own binary in /usr/local/bin, neither of which Chainguard's default
# uid can write to.
#
# DL3002 ("last USER should not be root") is a claim about the image that
# ships. This stage is discarded — nothing here is in the final image but
# /opt/venv and /empty, both copied with an explicit --chown — and the
# runtime stage below ends on `USER 10001`.
#
# DL3066 wants a numeric id, on the grounds that a name may not resolve on
# the host. `root` is uid 0 on every system there is, and leaving it
# spelled out keeps the contrast with the deliberate `USER 10001` legible.
# hadolint ignore=DL3002,DL3066
USER root

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv

WORKDIR /src
COPY backend/pyproject.toml backend/uv.lock ./
# --no-install-project so this layer depends only on the lockfile.
#
# --python so uv builds the venv against THIS image's interpreter
# rather than downloading one of its own. The runtime stage copies
# this venv and has only the one python; a venv pointing at an
# interpreter that is not there imports nothing.
#
# `mkdir /empty` rides along on the same RUN rather than taking a layer of
# its own (DL3059). It is an empty directory for the runtime to copy in as
# `data`: distroless has no shell, so `RUN mkdir` is not available down
# there, and copying this directory is how the final image gets an empty
# one with the right owner.
RUN uv sync --locked --no-dev --no-install-project --python /usr/bin/python \
 && mkdir -p /empty


# ------------------------------------------------------------ runtime
# Distroless. No shell, no package manager, no apt database, no libc
# utilities — so most of what an attacker reaches for after getting
# execution in a container is simply not present, and the CVE surface
# is the interpreter and the wheels rather than a Debian userland.
#
# Pinned by digest, not `:latest`. Chainguard's free tier publishes
# only `latest` and `latest-dev`, which are mutable — the same reason
# ci.yml pins its actions to SHAs. Dependabot raises a PR when the
# digest moves; merging it is how CVE fixes arrive.
FROM cgr.dev/chainguard/python:latest@sha256:8c6e0d0a587455e8a8d145e20234d5ef5a531a1c052a7b9d76b155ccc7fcded2 AS runtime

# No apt layer at all now. libpq came out because `psycopg[binary]`
# bundles it in the wheel, and curl came out because the healthcheck
# below no longer shells out — see the note there.
#
# No useradd either — there is no shell to run it with, and the image
# is already nonroot. The uid stays 10001 rather than taking
# Chainguard's default of 65532, which is not cosmetic: the `secret`
# volume holds the session-signing key and its files are owned by
# 10001 on every deployment that already exists. A container running
# as 65532 against that volume cannot write to it, so a first boot
# after upgrading fails to generate a key and an existing one cannot
# be rotated. Tested, not reasoned about: PermissionError on
# /app/backend/data. Both uids are equally unprivileged, so there is
# nothing to trade away by keeping the one already on disk.
#
# `--chown` on each COPY rather than a chown afterwards, for the same
# reason as before — chowning after the fact writes a second copy of
# the whole virtualenv into a new layer, 228 MB of it.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

COPY --from=deps --chown=10001:10001 /opt/venv /opt/venv
# The version, as a file, one level above the backend — which is where
# app/version.py walks up to find it. Two properties make this the
# whole mechanism for the Python half:
#
#   * `.git` is in .dockerignore and is therefore not in this image, so
#     version.py takes the release branch and reports a bare `0.0.1`
#     rather than appending a `-dev-` suffix. The image cannot
#     accidentally claim to be a development build, because the thing
#     that marks one is absent by construction.
#   * It is the same file the drone stage above stamped into the agent
#     binaries, from the same build context, so the server and the
#     agents it hands out cannot disagree.
COPY --chown=10001:10001 VERSION /app/VERSION
COPY --chown=10001:10001 backend/ /app/backend/
COPY --from=ui --chown=10001:10001 /build/frontend/dist /app/frontend/dist
COPY --from=drone --chown=10001:10001 /build/drone/dist /app/drone-dist
COPY --chown=10001:10001 docker/entrypoint.py /usr/local/bin/entrypoint.py

# `data` holds the session-signing key, which has to outlive the
# container or every restart logs everyone out — people respond to
# that by keeping a long-lived token lying around instead.
#
# Created by COPY rather than `RUN mkdir`, because there is no shell
# here to run mkdir with. An empty directory with the right owner is
# all it was ever doing.
COPY --from=deps --chown=10001:10001 /empty /app/backend/data

USER 10001
WORKDIR /app/backend

# The path the session-signing key is read from and written to, not the key
# itself: `_secret()` in backend/app/security.py generates one with
# secrets.token_urlsafe on first boot, writes it 0600 to this path, and
# reads it back on every later start. DL3064 matches on the variable name
# containing "SECRET"; there is no secret value here, and the name is the
# one the application looks up.
# hadolint ignore=DL3064
ENV ODDJOB_SECRET_FILE=/app/backend/data/.secret \
    PORT=8000

EXPOSE 8000

# Start-period is generous: the first boot runs migrations, and a
# container killed for being "unhealthy" while migrating is worse than
# one that takes a minute to settle.
#
# Python rather than curl, and in exec form. There is no shell to
# expand `${PORT}` or to interpret `|| exit 1`, and the string form of
# HEALTHCHECK CMD requires one — it would fail every check with "no
# such file or directory", which reads as a broken app rather than a
# broken healthcheck.
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
  CMD ["/opt/venv/bin/python", "-c", "import os,urllib.request,sys; sys.exit(0 if 'setup_required' in urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','8000')+'/api/auth/setup-required', timeout=4).read().decode() else 1)"]

ENTRYPOINT ["/opt/venv/bin/python", "/usr/local/bin/entrypoint.py"]
