<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# 09 Unix Socket Forwards

Previous: [08 Reference Map](08-reference-map.md)  
Next: [How-To Index](README.md)

Unix socket forwards let you keep services off loopback and still move them
through WireGuard. That matters on shared systems, containers, CI runners, and
HPC nodes where `127.0.0.1` is too broad or just the wrong integration point.

With this feature you can:

- expose a local Unix socket service such as `/var/run/docker.sock` to selected peers
- bind client-side forwards on `unix://` so only processes with filesystem access can reach them
- carry UDP through Unix sockets too, including `dgram`, `seqpacket`, and framed `stream`

## Validate The Example

The repo now includes a Unix socket example config:

```bash
./uwgsocks --config ./examples/unix-forwarding.yaml --check
```

That validates:

- TCP forward on `unix:///tmp/uwg-postgres.sock`
- UDP forward on `unix+dgram:///tmp/uwg-dns.sock`
- UDP forward on `unix+stream:///tmp/uwg-udp-stream.sock`
- TCP reverse forward to `/var/run/docker.sock`
- TCP reverse forward to a local Unix-socket HTTP server

## Scheme Cheatsheet

- `unix://path.sock`
  - default Unix mode
  - TCP: stream
  - UDP: datagram
- `unix+stream://path.sock`
  - stream socket
  - plain byte stream for TCP
  - framed datagrams for UDP
- `unix+dgram://path.sock`
  - datagram socket
  - raw datagrams for UDP
  - framed messages for TCP
- `unix+seqpacket://path.sock`
  - sequenced-packet socket
  - raw packets for UDP
  - framed messages for TCP

`frame_bytes: 2` or `frame_bytes: 4` controls the big-endian length prefix when
framing is needed. The default is 4 bytes.

## Forward To A Remote TCP Service Without Loopback

This creates a local Unix socket instead of `127.0.0.1:15432`:

```yaml
forwards:
  - proto: tcp
    listen: unix:///tmp/uwg-postgres.sock
    target: 100.64.90.1:5432
```

Start it:

```bash
./uwgsocks --config ./examples/unix-forwarding.yaml
```

Then point a local client at the socket:

```bash
psql "host=/tmp dbname=app user=app"
```

Only processes that can open `/tmp/uwg-postgres.sock` can use the forward.

## Publish Docker Over WireGuard

This is the high-value reverse-forward pattern:

```yaml
reverse_forwards:
  - proto: tcp
    listen: 100.64.90.99:2375
    target: unix:///var/run/docker.sock
```

Now another peer can talk to Docker through the tunnel:

```bash
docker -H tcp://100.64.90.99:2375 ps
```

That keeps Docker off the LAN and off loopback. Pair it with ACLs so only the
exact peers you trust can reach `100.64.90.99:2375`.

## Bind A Node.js HTTP Server To A Unix Socket

Instead of listening on `127.0.0.1:8080`, bind the app to a Unix socket:

```js
import http from "node:http";
import fs from "node:fs";

const socketPath = "/tmp/node-http.sock";
try { fs.unlinkSync(socketPath); } catch {}

http.createServer((req, res) => {
  res.end("hello over unix socket");
}).listen(socketPath);
```

Then publish it into the tunnel:

```yaml
reverse_forwards:
  - proto: tcp
    listen: 100.64.90.99:8080
    target: unix:///tmp/node-http.sock
```

From another peer:

```bash
curl http://100.64.90.99:8080
```

## UDP Over Unix Sockets

UDP can use:

- `unix://` or `unix+dgram://`
- `unix+seqpacket://`
- `unix+stream://` with `frame_bytes`

Example framed UDP over Unix stream:

```yaml
forwards:
  - proto: udp
    listen: unix+stream:///tmp/uwg-udp-stream.sock
    target: 100.64.90.1:123
    frame_bytes: 2
```

That maps one Unix stream connection to one UDP flow. Each framed message is
one UDP datagram.

## Platform Note

Not every platform supports every Unix socket family. `uwgsocks` probes the
requested Unix socket type at startup and fails clearly if the runtime does not
support it. In practice:

- `unix://` stream sockets are the safest cross-platform Unix choice
- `unix+dgram://` is widely available on Unix-like systems
- `unix+seqpacket://` is more platform-dependent

If you need the broadest portability, prefer `unix://` for TCP and
`unix+dgram://` for UDP.
