# Jaws

A grey-zone enumeration agent for [Oddjob](../README.md). One static
binary for Linux, macOS and Windows.

```bash
jaws run --server https://oddjob.internal --key jaws_...
```

Jaws **dials out** and holds the connection open, so it works from
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

## Privilege

SYN scanning, OS fingerprinting and masscan need raw sockets. Jaws
reports whether it has them, and the server records it — a scan that
silently fell back to a connect scan is a *different scan*, and a
report that does not say so is wrong.

```bash
sudo jaws run ...                      # Linux/macOS
setcap cap_net_raw,cap_net_admin+eip $(which nmap)   # or grant per-tool
```

## Building

```bash
make build          # host
make release        # linux/darwin/windows, amd64 + arm64
```
