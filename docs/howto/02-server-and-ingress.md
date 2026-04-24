<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# 02 Server And Ingress

Previous: [01 Simple Client Proxy](01-simple-client-proxy.md)  
Next: [03 Wrapper Interception](03-wrapper-interception.md)

At the data-plane level, `uwgsocks` exposes local services with
`reverse_forwards`. At the internet edge, the companion project
`simple-wireguard-server` publishes those services through protected HTTPS
subdomains.

## Local Reverse-Forward Demo

Start a local web app:

```bash
python3 -m http.server 8080 --bind 127.0.0.1
```

In another terminal, start the client with a tunnel-side listener:

```bash
./uwgsocks --config ./examples/ingress-client.yaml
```

That file creates this reverse forward:

```yaml
reverse_forwards:
  - proto: tcp
    listen: 100.64.90.99:8080
    target: 127.0.0.1:8080
```

Now hit the tunnel-side listener through the local proxy:

```bash
curl --proxy http://127.0.0.1:8082 http://100.64.90.99:8080
```

You are reaching a local web server through a userspace WireGuard address,
without opening a host port on the app machine.

## Public HTTPS Subdomains

For public internet ingress, run the companion control plane on a public host:

```bash
./uwgsocks-ui -listen 0.0.0.0:8080
```

That project manages `uwgsocks` as a child daemon and publishes protected
services through login-gated subdomains. The underlying tunnel hop is still
`reverse_forwards`; the UI adds:

- HTTPS edge termination
- subdomain routing
- access control
- share links and auth flows
- managed daemon config generation

## Secure Control Channel

Protect the daemon API with a bearer token:

```yaml
api:
  listen: 127.0.0.1:9090
  token: demo-api-token-change-me
```

Then query it:

```bash
curl -H 'Authorization: Bearer demo-api-token-change-me' \
  http://127.0.0.1:9090/v1/status
```

That token protects runtime management. The public ingress auth layer lives in
`simple-wireguard-server`.

## Mental Model

- `uwgsocks`: the rootless WireGuard router and reverse-forward engine
- `simple-wireguard-server`: the browser-managed HTTPS ingress and control plane

Use them together when you want local services to appear on the public internet
without opening inbound ports on the origin machine.
