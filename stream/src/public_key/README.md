# Public Key Authentication Protocol

## Quick Summary

This module implements a custom encrypted communication protocol using pre-shared cryptographic identities. It provides mutual authentication and encrypted channels, but **does NOT provide identity hiding**.

## Key Characteristics

- ✅ **Mutual authentication** with pre-shared identities
- ✅ **Encrypted communication** using ChaCha20-Poly1305
- ✅ **Forward secrecy** via ephemeral keys
- ✅ **Replay protection** with timestamps and nonces
- ❌ **No identity hiding** - peer identities visible to network observers
- ❌ **No multiplexing** - one connection per peer
- ❌ **No automatic reconnection** - handle at application layer

## When to Use

### Good Fit ✅
- Private peer-to-peer networks with known participants
- Microservices within a secure perimeter
- IoT devices with embedded identities
- Systems where connection metadata is not sensitive

### Poor Fit ❌
- Anonymous communication systems
- Public web services (use TLS instead)
- Consensus protocols (encryption often unnecessary)
- Ultra-low latency systems (adds 20-50μs per message)

## Consensus Protocol Consideration

For consensus protocols that only need authenticated channels:
- Messages (blocks, votes) are often public anyway
- Encryption adds CPU overhead without security benefit
- Consider using signed messages over plain TCP instead:

```rust
// Simple authentication-only approach
struct SignedMessage<T> {
    payload: T,
    sender: PublicKey,
    signature: Signature,
}
```

## Identity Exposure Warning

During handshake, both peers send their public keys **in plaintext**:
- Network observers can see who is communicating
- Connections from the same peer are linkable
- No protection against traffic analysis

If identity privacy is required, this protocol is **not suitable**.

## Performance Impact

- **Bandwidth**: 16-byte authentication tag per message
- **Latency**: ~20-50μs encryption/decryption overhead
- **CPU**: ChaCha20-Poly1305 for every message
- **Handshake**: 3 round trips before data exchange

## Configuration

All peers must use identical configuration:
- `namespace`: Application-specific message prefix
- `max_message_size`: DoS protection limit
- `synchrony_bound`: Maximum clock skew tolerance
- `max_handshake_age`: Replay protection window
- `handshake_timeout`: DoS protection timeout