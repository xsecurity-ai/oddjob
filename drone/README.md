# Drone

A grey-zone enumeration agent for [Oddjob](../README.md). One static
binary for Linux, macOS and Windows.

```bash
drone run --server https://oddjob.internal --key drone_...
```

A Drone **dials out** and holds the connection open, so it works from
inside a client network with nothing exposed and no inbound firewall
rule. The server can also reach back in — `--listen` opens a small
authenticated API for that — but the system does not depend on it.

## What it does

- Installs and keeps `amass`, `nmap`, `masscan` and `gobuster`; the
  server can authorise more from a fixed list.
- Runs tasking and sends results home in the tool's **native format**,
  so Oddjob imports them with the parsers it already has.
- Resolves names and does reverse-IP lookups to turn an address back
  into the domains hosted on it.

## Tasking

Queue work against an enrolled agent:

```
POST /api/agents/{id}/tasks?project=CODE
{"kind": "nmap", "args": {"targets": ["host.example"], "ports": "22,80,443"}}
```

Kinds: `nmap` `masscan` `amass` `gobuster` `nuclei` `httpx` `nslookup`
`reverse_ip` `install` `shell`. Every kind takes **`targets`** for the
thing it acts on, and also accepts its own tool's word for it —
`query`, `ip`, `domain`, `url`. `amass` and `gobuster` take exactly one
subject per task and say so rather than quietly scanning the first.

A result comes back with no operator attached, so it imports in
**strict mode**: any host the project has not seen before is surveyed
and *nothing is written*. The reply carries `needs_decision` and the
list. Answer it and the findings land:

```
POST /api/agents/{id}/tasks/{task_id}/import?project=CODE
{"decisions": {"host.example": {"action": "add"}}}
```

`add`, `map` (attach to an existing target) or `reject`. The task's
output is kept, so a decision that mapped a host to the wrong target
can be redone. Hosts the project already knows import straight
through with no decision needed.

A task whose tool exited non-zero is recorded as **failed**, carrying
the tool's own stderr. It is never imported — nmap can be refused at
the command line and still write an XML file describing a finished run
over zero hosts, and "we never looked" must not read as "we looked and
found nothing".

## Privilege

SYN scanning, OS fingerprinting and masscan need raw sockets. A Drone
reports whether it has them, and the server records it — a scan that
silently fell back to a connect scan is a *different scan*, and a
report that does not say so is wrong.

```bash
sudo drone run ...                      # Linux/macOS
setcap cap_net_raw,cap_net_admin+eip $(which nmap)   # or grant per-tool
```

## Building

```bash
make build          # host
make release        # linux/darwin/windows, amd64 + arm64
```
