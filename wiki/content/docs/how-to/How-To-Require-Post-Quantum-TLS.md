---
title: How To Require Post-Quantum TLS
weight: 3
---

By default the handshake offers X25519MLKEM768 first and settles on what the server supports, reporting it in `KeyExchange`. `-RequirePostQuantum` offers TLS 1.3 and X25519MLKEM768 and nothing else, so a server without them fails the handshake. Source: `src/lib.rs` (`client_config`, `refused_post_quantum`, `open`).

```powershell
(Invoke-SecureFetch https://www.debian.org/).KeyExchange
Invoke-SecureFetch https://www.debian.org/ -RequirePostQuantum -ErrorAction SilentlyContinue -ErrorVariable failed
$failed[0].FullyQualifiedErrorId
$failed[0].Exception.Message
(Invoke-SecureFetch https://pq.cloudflareresearch.com/cdn-cgi/trace -RequirePostQuantum).KeyExchange
```

```text
X25519
SecureFetchNotPostQuantum,Pwrs.Modules.SecureFetch.InvokeSecureFetchCommand
www.debian.org did not complete a TLS 1.3 handshake with X25519MLKEM768, the only key exchange -RequirePostQuantum offers: received fatal alert: HandshakeFailure
X25519MLKEM768
```

## What the refusal means

- The handshake always finishes before the request is written, so a server refused this way has been sent nothing but the handshake: no path, no header field, no body.
- `SecureFetchNotPostQuantum` (SecurityError) covers every way a server turns the offer down: an alert saying it shares no group or version, rustls finding it chose TLS 1.2 or no shared group, a retry asking for a group that was not offered, or the connection closed mid-handshake, which some servers do instead of sending an alert. A wait that runs out is a timeout, not a refusal.
- Every new connection makes a full handshake of its own (session resumption is off), so each response's `KeyExchange` is the group its own connection agreed.

## Without the switch

Without `-RequirePostQuantum`, TLS 1.2 is accepted and the key exchange falls back to X25519, secp256r1 or secp384r1 when the server does not offer X25519MLKEM768. The response still says what was agreed, so a script can check `KeyExchange` itself.
