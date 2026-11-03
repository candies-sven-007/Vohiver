# UK egress via a VLESS Reality node (Xray bridge)

This document is a template only. It contains NO node credentials.
Fill the placeholders locally on the stick, from your own proxy
library, and never paste the filled file into chat.

Why Xray, not sing-box, for this node type (checked against MDD,
branch slim-reader-vowifi, 2026-11-03):
- MDD's egress code routes Reality/XHTTP nodes through Xray-core,
  because testing them through sing-box would measure sing-box's
  compatibility with the server's Xray build, not whether the node
  works.
- The bridge is: Xray inbound SOCKS (127.0.0.1, UDP enabled) ->
  Xray outbound VLESS Reality -> UK server. Vohiver's
  internal/egress SOCKS5 UDP transport then dials the ePDG through
  that loopback SOCKS, for IKE UDP 500 and NAT-T UDP 4500.
- Do NOT use ssh -D for this: ssh SOCKS does not carry UDP, so
  IKE over it will never work.

## Xray config skeleton (fill locally)

```json
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "listen": "127.0.0.1", "port": 1080,
    "protocol": "socks", "tag": "bridge-in",
    "settings": {"auth": "noauth", "udp": true, "ip": "127.0.0.1"}
  }],
  "outbounds": [{
    "protocol": "vless", "tag": "uk-node",
    "settings": {"vnext": [{
      "address": "<node server, from your own library>",
      "port": "<node port>",
      "users": [{"id": "<node uuid>", "flow": "xtls-rprx-vision"}]
    }]},
    "streamSettings": {
      "network": "tcp", "security": "reality",
      "realitySettings": {
        "serverName": "<node sni>",
        "fingerprint": "chrome",
        "publicKey": "<node public key>",
        "shortId": "<node short id>"
      }
    }
  }],
  "routing": {"domainStrategy": "AsIs", "rules": [{
    "type": "field", "inboundTag": ["bridge-in"],
    "outboundTag": "uk-node"
  }]}
}
```

## Test order (on the stick, after the bridge is up)

1. `curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me` style
   TCP check is NOT enough for VoWiFi; it only proves the bridge
   is up.
2. Run Vohiver's egress probe / IKE client with
   `-proxy socks5://127.0.0.1:1080 -target <ePDG IP> -port 500`.
   A successful IKEv2 SA_INIT response through the bridge proves
   the UK path; a direct ike-scan from the stick is expected to
   fail from mainland China and proves nothing about the bridge.
3. Only then proceed to EAP-AKA: the IKE client must keep using
   the same bridge for UDP 500 and UDP 4500, with no direct
   fallback, exactly like MDD's outer_transport.
