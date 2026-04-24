<!-- Copyright (c) 2026 Reindert Pelsma -->
<!-- SPDX-License-Identifier: ISC -->

# 04 Firewall And ACLs

Previous: [03 Wrapper Interception](03-wrapper-interception.md)  
Next: [05 Pluggable Transports](05-pluggable-transports.md)

`uwgsocks` does not just relay packets. It applies outbound ACLs, inbound ACLs,
and relay ACLs with a userspace conntrack engine so replies can flow without
opening lateral movement across the mesh.

## Start From The Shipped Relay Example

```bash
./uwgsocks --config ./examples/relay-acls.yaml --check
```

The important part is:

```yaml
relay:
  enabled: true
  conntrack: true

acl:
  relay_default: deny
  relay:
    - action: allow
      source: 10.10.10.0/24
      destination: 10.20.20.0/24
      protocol: tcp
      destination_port: 443
```

## Lock A Peer To One Service

If you want one peer to reach exactly one internal service and nothing else:

```yaml
acl:
  relay_default: deny
  relay:
    - action: allow
      source: 100.64.82.2/32
      destination: 10.20.20.53/32
      protocol: tcp
      destination_port: 443
```

That means:

- peer `100.64.82.2` can reach `10.20.20.53:443`
- everything else is denied
- reply traffic is allowed through conntrack

## Why Conntrack Matters

Without conntrack, “allow one destination port” is not enough for a practical
relay because return packets would not match the original forward rule cleanly.
The relay state table gives you tight policy without breaking real traffic.

## Runtime Updates

You can replace ACLs live through the API:

```bash
curl -X PUT \
  -H 'Content-Type: application/json' \
  --unix-socket uwgsocks.sock \
  http://localhost/v1/acls
```

For the full ACL schema and policy planes, jump to
[08 Reference Map](08-reference-map.md).

