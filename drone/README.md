# Drone

**Forward-Deployed Enumeration (FDE) for an engagement.**

A Drone is a single static binary that sits on your attack
infrastructure, takes tasking from Oddjob, runs the scanners, and sends
the results home — where they import themselves into the project. No
database, no dependencies, no inbound port.

It exists because of where scanning has to happen from. The box that can
reach a client's estate is rarely the box your team is looking at. A
Drone is how you put a scanner *there* and still drive it from one place,
with one scope list, one queue and one inventory.

```
   Oddjob ──── tasking ────►  Drone  ────►  nmap · masscan · amass
      ▲                         │           nuclei · gobuster · httpx
      └──────── results ────────┘           gospider
```

**A Drone is tied to one project.** It enrolls against a single
engagement, authenticates to that Oddjob alone, takes tasking only from
that project, and everything it finds imports into that project. It
cannot be borrowed by another engagement, and a second engagement needs
a second Drone.

---

## Where a Drone may be installed

**On attack infrastructure you own or control. Nowhere else.**

Specifically: **never on a host you have compromised.** Not on a target,
not on a pivot, not on a box you have a shell on because it was in
scope. This is not a style preference, and it is worth being plain about
why:

- **It is a persistent, privileged implant with a credential.** It runs
  as root or with `CAP_NET_RAW`, installs packages, executes scanners,
  and holds a key that authenticates to your Oddjob. Leaving that on a
  client's machine is leaving a backdoor with your name on it.
- **It would exfiltrate the client's data to you automatically.** Scan
  output, hostnames, banners — sent out of their network, by a process
  you installed, on a schedule. That is a conversation you do not want to
  have.
- **It is almost certainly outside your authorization.** Permission to
  test a host is not permission to install software on it, and a signed
  scope document very rarely says otherwise.
- **You will not get it back.** Engagements end. Containers do not
  uninstall themselves, and `--restart unless-stopped` survives a reboot.
  The orphaned-agent problem is real and it is yours.

Use a VPS you rent, a VM in your own cloud account, a laptop on the
engagement, or a box the client gave you *for this purpose and in
writing*. If you are unsure whether a host counts, it does not.

### What a Drone does to the host it is on

| | |
|---|---|
| Runs as | root, or unprivileged with `CAP_NET_RAW` for SYN scans |
| Installs | its baseline tools, via the system package manager |
| Listens on | nothing, unless you choose call-in mode |
| Writes to | one working directory: identity, spool, scan output |
| Sends | results to the Oddjob it enrolled with, and nowhere else |

---

## Modes, and how they work

### Connection: how Oddjob and the Drone reach each other

**Callback** (the default). The Drone dials out and polls for work. It
holds no open port, needs no firewall change, and works from inside a
client network that allows outbound HTTPS and nothing else. Use this
unless you cannot.

```
Drone ──── outbound HTTPS ────► Oddjob
```

**Call-in.** Oddjob dials the Drone. For a host that cannot dial out but
can be reached — and only that. The inbound side is deliberately tiny: it
reports status and asks the loop to poll now. It **cannot be used to run
anything**; all tasking still arrives over the outbound channel, where
the Drone authenticated the server rather than the other way round.

```
Oddjob ──── "wake up" ────► Drone :7777 ──── outbound ────► Oddjob
```

Call-in needs `--listen`, `--advertise` and a call-in key.

### Routing: which Drone gets the work

Set per project, in Oddjob under **Drones → Routing**.

| mode | behaviour | when |
|---|---|---|
| **mesh** | Work is spread across every online Drone. | The default, and what you want most of the time. |
| **primary** | One Drone does the work and the rest stand by. The primary is *derived* — the enabled, online Drone with the lowest priority — so if it stops heartbeating the next one takes over on the next poll. No leader record to go stale, and two Drones cannot both believe they are primary. | Attribution matters and all traffic must come from one address. |
| **geo** | A task goes to a Drone that serves its region. | Egress has to come from a particular country or network. |

### Parallelism

Each project sets a ceiling — how many tasks one Drone may run at once,
default 5. Each Drone independently works out what its own host can
stand: cores, memory actually available, and what masscan managed to
emit locally. **The lower of the two wins.** A 32-core server will not be
given more than the project allows, and a Raspberry Pi will not be given
five scans because somebody typed 5 into a form.

---

## Region configuration

Regions are **declared by you on both sides**, never looked up. Resolving
a target's address to a country would mean sending the client's
addresses to a third-party geolocation service, which is not a thing this
tool will do quietly.

On the Drone, when you deploy it:

```bash
drone run --name tokyo-01 --regions jp,apac
```

Or with an existing Drone, in Oddjob: **Drones → ⚙ Edit → Regions**.
Free text and comma-separated — `jp`, `eu`, `us-east`, `client-dmz`.
The useful division is usually the client's network, not a standard
country list.

Then set the project to `geo` routing and give each task a region:

```
Targets → Enumerate → … → Region: jp
```

A pooled task with no region is refused in `geo` mode rather than
guessed at. A Drone with no regions set will never be given geo work —
Oddjob says so on its row rather than leaving you to wonder.

---

## Configuration and deployment

### Docker — do it this way

```bash
# In Oddjob: Drones → Deploy a Drone. Copy the enrollment token.
docker run -d --name drone --restart unless-stopped \
  --cap-drop=ALL --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -e DRONE_SERVER=https://oddjob.internal \
  -e DRONE_ENROLL_TOKEN=drone_... \
  -v drone-state:/var/lib/drone/work \
  drone-agent \
  run --name edge-01 --workdir /var/lib/drone/work
```

The tools are already in the image, so the Drone is useful the moment it
starts and never needs to reach a package mirror from inside someone's
network.

`--cap-drop=ALL` with `NET_RAW` and `NET_ADMIN` added back: enough for
SYN scanning and masscan, and nothing else. `network_mode: host` if you
need the host's own addresses for attribution.

There is a [`docker-compose.yml`](docker-compose.yml) with every option
written out.

### Binary

```bash
drone run --server https://oddjob.internal --enroll-token drone_...
```

| flag | environment | |
|---|---|---|
| `--server` | `DRONE_SERVER` | Oddjob's URL |
| `--enroll-token` | `DRONE_ENROLL_TOKEN` | one-time, exchanged for an identity |
| `--key` | `DRONE_KEY` | callback key, after enrollment |
| `--call-in-key` | `DRONE_CALL_IN_KEY` | for call-in mode |
| `--advertise` | `DRONE_ADVERTISE` | URL Oddjob should use to reach `--listen` |
| `--workdir` | `DRONE_WORKDIR` | identity and spool live here |
| `--public-ip-url` | `DRONE_PUBLIC_IP_URL` | asked once at registration what our public address is; `off` to ask nobody |
| `--name` | | what it is called in the UI |
| `--regions` | | comma-separated, for `geo` routing |
| `--heartbeat` | | default 15s |

Prefer the environment over flags for anything secret: process lists are
readable by every user on the box, which on an engagement host is
precisely the point.

### Enrollment, and what it establishes

The token is **one-time and short-lived**. The Drone exchanges it for a
mutual identity: it generates a keypair locally, sends the public half,
and gets Oddjob's in return. From that moment each side has pinned the
other. A Drone will refuse tasking from anything that is not the Oddjob
it enrolled with, and bodies are sealed under a key only those two hold —
so a TLS-terminating proxy inside a client network, which is ordinary
corporate furniture, sees nothing.

If an enrollment fails after the token was spent, mint a new one. The
token is burned on use by design; that is what stops a second process
registering with a copy of it.

### Checking a host before you commit

```bash
drone check      # what this host can do, as JSON, and exit
```

Reports the platform, whether raw sockets are available, which tools are
present and which are missing — without enrolling or contacting Oddjob.

It does make one request of its own: to `ifconfig.me`, asking what this
host's traffic looks like from outside. That is the only answer that
survives NAT and containers, and the routing table cannot produce it.
Nothing but the bare request is sent, but it *is* a connection to a
third party from the client's network, so it is switchable off:

```bash
DRONE_PUBLIC_IP_URL=off drone check    # or --public-ip-url ''
```

### Which machine is which

Two pairs of fields, because in each pair the two halves answer
different questions and they disagree in exactly the cases that matter.

`platform` is `runtime.GOOS` — what the binary is. `host_platform` is
the machine underneath: a Linux container on WSL2 on a Windows Server
VM reports `platform: linux`, `host_platform: windows`, rendered
`linux (container on windows)`. When the host cannot be determined —
inside Docker Desktop's LinuxKit VM, for instance, which looks the same
on macOS and on Windows — `host_platform` is **empty**, not guessed.
`host_platform_source` carries the evidence so the claim can be checked.

`outbound_ip` is the address, and `outbound_ip_source` is where the
number came from: `public-service` (asked from outside), `host-route`
(this host's routing table), `container-host-netns` (a container
sharing the host's namespace, so still the host's address),
`container-internal` (the container's own address, which means nothing
outside this machine), `interface`, or `unknown`. Read the address
without the source and a `172.17.0.3` looks exactly like a real egress
address.

---

## What it runs

`nmap`, `masscan`, `amass`, `gobuster`, `gospider`, `nuclei`, `httpx`,
plus name and address lookups using the Go resolver directly.

The Drone installs these at startup if they are missing, and tells
Oddjob what it could not get. Oddjob then stops sending it work that
needs them — pooled work waits for a Drone that has the tool, and work
addressed to this one by name fails immediately with the reason, rather
than being retried into the same wall.

A Drone does not download arbitrary binaries and run them. The installable
set is a fixed list, in the agent and again on the server, and the server
refuses anything outside it.

---

## Raw sockets

SYN scanning, OS fingerprinting and masscan need `CAP_NET_RAW`. A Drone
reports honestly whether it has it rather than discovering mid-scan:

- **Linux**: reads its own `CapEff`. File capabilities set with `setcap`
  do not survive into a Docker exec, which is why the compose file grants
  the capability to the container instead.
- **Windows**: needs Npcap. Reported as present or not.
- Without raw sockets, nmap is given `-sT` and masscan refuses outright —
  it does not degrade, so Oddjob will not offer it against an
  unprivileged Drone.

---

## Security

Read [`../SECURITY.md`](../SECURITY.md).

The short version: a Drone is a privileged process holding a credential
to your engagement data. Treat it as attack infrastructure, put it only
where you would put a C2 redirector, and remove it when the engagement
ends.
