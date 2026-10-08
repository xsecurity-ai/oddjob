# Ghost

**Forward-Deployed Enumeration (FDE) for an engagement.**

A Ghost is a single static binary that sits on your attack
infrastructure, takes tasking from Oddjob, runs the scanners, and sends
the results home — where they import themselves into the project. No
database, no dependencies, no inbound port.

It exists because of where scanning has to happen from. The box that can
reach a client's estate is rarely the box your team is looking at. A
Ghost is how you put a scanner *there* and still drive it from one place,
with one scope list, one queue and one inventory.

```
   Oddjob ──── tasking ────►  Ghost  ────►  nmap · masscan · amass
      ▲                         │           nuclei · gobuster · httpx
      └──────── results ────────┘           gospider
```

**A Ghost is tied to one project.** It enrolls against a single
engagement, authenticates to that Oddjob alone, takes tasking only from
that project, and everything it finds imports into that project. It
cannot be borrowed by another engagement, and a second engagement needs
a second Ghost.

---

## Where a Ghost may be installed

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

### What a Ghost does to the host it is on

| | |
|---|---|
| Runs as | root, or unprivileged with `CAP_NET_RAW` for SYN scans |
| Installs | its baseline tools, via the system package manager |
| Listens on | nothing, unless you choose call-in mode |
| Writes to | one working directory: identity, spool, scan output |
| Sends | results to the Oddjob it enrolled with, and nowhere else |

---

## Modes, and how they work

### Connection: how Oddjob and the Ghost reach each other

**Callback** (the default). The Ghost dials out and polls for work. It
holds no open port, needs no firewall change, and works from inside a
client network that allows outbound HTTPS and nothing else. Use this
unless you cannot.

```
Ghost ──── outbound HTTPS ────► Oddjob
```

**Call-in.** Oddjob dials the Ghost. For a host that cannot dial out but
can be reached — and only that. The inbound side is deliberately tiny: it
reports status and asks the loop to poll now. It **cannot be used to run
anything**; all tasking still arrives over the outbound channel, where
the Ghost authenticated the server rather than the other way round.

```
Oddjob ──── "wake up" ────► Ghost :7777 ──── outbound ────► Oddjob
```

Call-in needs `--listen`, `--advertise` and a call-in key.

### Routing: which Ghost gets the work

Set per project, in Oddjob under **Ghosts → Routing**.

| mode | behaviour | when |
|---|---|---|
| **mesh** | Work is spread across every online Ghost. | The default, and what you want most of the time. |
| **primary** | One Ghost does the work and the rest stand by. The primary is *derived* — the enabled, online Ghost with the lowest priority — so if it stops heartbeating the next one takes over on the next poll. No leader record to go stale, and two Ghosts cannot both believe they are primary. | Attribution matters and all traffic must come from one address. |
| **geo** | A task goes to a Ghost that serves its region. | Egress has to come from a particular country or network. |

### Parallelism

Each project sets a ceiling — how many tasks one Ghost may run at once,
default 5. Each Ghost independently works out what its own host can
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

On the Ghost, when you deploy it:

```bash
ghost run --name tokyo-01 --regions jp,apac
```

Or with an existing Ghost, in Oddjob: **Ghosts → ⚙ Edit → Regions**.
Free text and comma-separated — `jp`, `eu`, `us-east`, `client-dmz`.
The useful division is usually the client's network, not a standard
country list.

Then set the project to `geo` routing and give each task a region:

```
Targets → Enumerate → … → Region: jp
```

A pooled task with no region is refused in `geo` mode rather than
guessed at. A Ghost with no regions set will never be given geo work —
Oddjob says so on its row rather than leaving you to wonder.

---

## Configuration and deployment

### Docker — do it this way

```bash
# In Oddjob: Ghosts → Deploy a Ghost. Copy the enrollment token.
docker run -d --name ghost --restart unless-stopped \
  --network host \
  --cap-drop=ALL --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -e GHOST_SERVER=https://oddjob.internal \
  -e GHOST_ENROLL_TOKEN=ghost_... \
  -v ghost-state:/var/lib/ghost/work \
  ghost-agent \
  run --name edge-01 --workdir /var/lib/ghost/work
```

The tools are already in the image, so the Ghost is useful the moment it
starts and never needs to reach a package mirror from inside someone's
network.

`--cap-drop=ALL` with `NET_RAW` and `NET_ADMIN` added back: enough for
SYN scanning and masscan, and nothing else.

### `--network host`, and why the example has it

**Leave it off and the Ghost cannot catch a callback.** On the default
bridge the container has a private address on a private network. Nothing
outside the host can reach it, so a reverse shell, an SSRF callback or a
DNS exfil listener has nowhere to land — the target connects to the host
and the host has nothing listening. If you want the Ghost to *receive*
connections, this flag is not optional.

Two other things it fixes, both visible the moment you look at a Ghost in
the fleet table:

```
            interfaces reported
bridge      172.17.0.2
host        203.0.113.9, 10.100.0.2, 10.13.0.5
```

**Attribution.** On a bridge every packet the client sees comes from the
host's address after NAT, while the agent believes its address is a
private bridge IP that appears in nobody's logs. Both ends of the record
are then wrong, and an incident notification written from that reports an
address the client cannot find.

**Reach.** The agent can only talk to what its namespace can see. On a
bridge that is not the private networks the host sits on — which are
usually the entire reason that host was chosen.

#### What you are giving up

Host networking removes the container's network namespace. Combined with
`NET_ADMIN`, that capability now applies to **the host's** network stack
rather than an isolated one: routing and firewall rules included. On a
dedicated scanning box that is the intent. On a shared machine, decide
deliberately — and prefer a box you are willing to treat as part of the
engagement.

Docker Desktop on macOS and Windows does not implement host networking.
The agent still runs and still reports honestly; it just scans from the
VM, and it cannot catch callbacks there either. Linux is where an agent
belongs.

#### Without it

Everything else works — enumeration, scanning, crawling, reporting. You
lose inbound connections, truthful addresses, and the host's other
networks:

```bash
docker run -d --name ghost --restart unless-stopped \
  --cap-drop=ALL --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -e GHOST_SERVER=https://oddjob.internal \
  -e GHOST_ENROLL_TOKEN=ghost_... \
  -v ghost-state:/var/lib/ghost/work \
  ghost-agent run --name edge-01 --workdir /var/lib/ghost/work
```

There is a [`docker-compose.yml`](docker-compose.yml) with every option
written out, `network_mode: host` included.

### Binary

```bash
ghost run --server https://oddjob.internal --enroll-token ghost_...
```

| flag | environment | |
|---|---|---|
| `--server` | `GHOST_SERVER` | Oddjob's URL |
| `--enroll-token` | `GHOST_ENROLL_TOKEN` | one-time, exchanged for an identity |
| `--key` | `GHOST_KEY` | callback key, after enrollment |
| `--call-in-key` | `GHOST_CALL_IN_KEY` | for call-in mode |
| `--advertise` | `GHOST_ADVERTISE` | URL Oddjob should use to reach `--listen` |
| `--workdir` | `GHOST_WORKDIR` | identity and spool live here |
| `--public-ip-url` | `GHOST_PUBLIC_IP_URL` | asked once at registration what our public address is; `off` to ask nobody |
| `--name` | | what it is called in the UI |
| `--regions` | | comma-separated, for `geo` routing |
| `--heartbeat` | | default 15s |
| `--parallel` | `GHOST_PARALLEL` | tasks at once; `0` (the default) sizes from the host |

Prefer the environment over flags for anything secret: process lists are
readable by every user on the box, which on an engagement host is
precisely the point.

### How many tasks at once

By default the Ghost decides, and re-decides every 60 seconds. Two
inputs: cores times four — the work is network-bound, so a core carries
several processes that are all sitting in a socket read — lowered by
available memory at 128 MB a task with 64 MB held back for the system.
Whichever is smaller wins, floored at 1 and capped at 32.

In a container, "available memory" is the smaller of `/proc/meminfo`
and this container's own cgroup limit. That file belongs to the host: a
Ghost under `--memory=512m` on a 16 GB machine reads 6 GB from it and
368 MB from the cgroup, and the cgroup is the one that will kill it.

The fleet table shows the number and the reason it landed there, which
is worth reading before changing anything: `4 cores x 4 (tasks wait on
the network, not the CPU)` and `300 MB available, less 64 MB reserved,
at 128 MB per task` call for different fixes, and only one of them is
this setting.

```bash
ghost run --parallel 8          # or GHOST_PARALLEL=8
ghost run --parallel 0          # the default: work it out from the host
```

An explicit number **wins over the memory estimate** rather than being
clamped by it. Asking for 8 and getting 2 with no explanation is how
people conclude a setting does nothing. Where the host disagrees it
says so instead: `set to 8 by the operator (the 136 MB available
suggests 1)`.

That wording is a real warning and not decoration. Memory is what
actually binds a small host, and the one thing here that eats it is
amass — measured resident at 438 MB on one of our own ghosts, against a
few tens for nmap. Several amass tasks on a 1 GB box will reach the OOM
killer, and it takes the Ghost with it. The retune is what normally
saves you: capacity is re-read from `MemAvailable` every minute, so a
Ghost that starts something heavy watches its own headroom fall and
stops accepting work. Overriding upward on a host with little free
memory opts out of the margin, not the mechanism.

### Enrollment, and what it establishes

The token is **one-time and short-lived**. The Ghost exchanges it for a
mutual identity: it generates a keypair locally, sends the public half,
and gets Oddjob's in return. From that moment each side has pinned the
other. A Ghost will refuse tasking from anything that is not the Oddjob
it enrolled with, and bodies are sealed under a key only those two hold —
so a TLS-terminating proxy inside a client network, which is ordinary
corporate furniture, sees nothing.

If an enrollment fails after the token was spent, mint a new one. The
token is burned on use by design; that is what stops a second process
registering with a copy of it.

### Checking a host before you commit

```bash
ghost check      # what this host can do, as JSON, and exit
```

Reports the platform, whether raw sockets are available, which tools are
present and which are missing — without enrolling or contacting Oddjob.

It does make one request of its own: to `ifconfig.me`, asking what this
host's traffic looks like from outside. That is the only answer that
survives NAT and containers, and the routing table cannot produce it.
Nothing but the bare request is sent, but it *is* a connection to a
third party from the client's network, so it is switchable off:

```bash
GHOST_PUBLIC_IP_URL=off ghost check    # or --public-ip-url ''
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

`nmap`, `masscan`, `gobuster`, `gospider`, `nuclei`, `httpx`, plus name
and address lookups using the Go resolver directly, and **amass linked
into the agent** rather than executed.

### amass is a library here, not a binary

It used to be whatever `amass` the host had. On one of ours that was
v3.19.2 from a snap with no configuration, and it did not finish a
*passive* enumeration of `example.com` in five minutes — two and a half
of which were system time, so it was not waiting on the network, it was
thrashing. The same zone through the v4 library finishes in under a
minute.

None of the settings that matter are reachable from the v3 command
line. Recursion, how many DNS queries may be in flight, the rate per
resolver and which resolvers to use are library-level, so the way to
make it faster was to stop talking to it through argv.

| task argument | default | |
|---|---|---|
| `recursive` | `true` | follow what the sources turn up rather than stopping at the first level |
| `max_dns_queries` | `20000` | in flight at once; the work is almost all waiting on somebody else's resolver |
| `resolvers_qps` | `100` | per resolver per second |
| `resolvers` | eight public ones | **stated, not inherited** — see below |
| `mode` | `passive` | `active` sends traffic to the target's own infrastructure |
| `timeout_seconds` | `2700` | a cut-off run still reports what it found |

The resolvers are named rather than taken from the host because an
agent inside a corporate network picks up a resolver that answers for
the *internal* view of a zone, and an enumeration that quietly returns
somebody's split-horizon records is a wrong answer that looks like a
right one.

Two things follow from linking it in. A Ghost no longer needs an amass
binary, so it is not in the image and not in the required-tool list —
an agent missing it still runs amass tasks. And a run that hits its
timeout still reports the names it found, where shelling out discarded
them.

The Ghost installs these at startup if they are missing, and tells
Oddjob what it could not get. Oddjob then stops sending it work that
needs them — pooled work waits for a Ghost that has the tool, and work
addressed to this one by name fails immediately with the reason, rather
than being retried into the same wall.

A Ghost does not download arbitrary binaries and run them. The installable
set is a fixed list, in the agent and again on the server, and the server
refuses anything outside it.

---

## Raw sockets

SYN scanning, OS fingerprinting and masscan need `CAP_NET_RAW`. A Ghost
reports honestly whether it has it rather than discovering mid-scan:

- **Linux**: reads its own `CapEff`. File capabilities set with `setcap`
  do not survive into a Docker exec, which is why the compose file grants
  the capability to the container instead.
- **Windows**: needs Npcap. Reported as present or not.
- Without raw sockets, nmap is given `-sT` and masscan refuses outright —
  it does not degrade, so Oddjob will not offer it against an
  unprivileged Ghost.

---

## Security

Read [`../SECURITY.md`](../SECURITY.md).

The short version: a Ghost is a privileged process holding a credential
to your engagement data. Treat it as attack infrastructure, put it only
where you would put a C2 redirector, and remove it when the engagement
ends.
