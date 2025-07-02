//! Communicate with an authenticated peer over an encrypted connection.
//!
//! Provides encrypted communication with peers identified by developer-specified
//! cryptographic identities (e.g., BLS, ed25519, etc.).
//! Implements its own encrypted transport layer (no TLS, no X.509 certificates,
//! no protocol negotiation) that exclusively uses these cryptographic identities
//! to authenticate incoming connections. Uses ChaCha20-Poly1305 for message encryption.
//!
//! # Purpose and Domain
//!
//! This protocol is designed for authenticated and encrypted communication between
//! peers in distributed systems where:
//!
//! - **Known peer identities**: All participants have pre-established cryptographic identities
//! - **Mutual authentication is required**: Both parties must prove their identity
//! - **Message confidentiality is needed**: Communications should be protected from eavesdropping
//! - **Message integrity is critical**: Messages must be protected from tampering
//! - **Low protocol overhead is desired**: No certificate chains or protocol negotiation
//!
//! ## Suitable Use Cases
//!
//! - **Peer-to-peer networks**: Where nodes maintain long-lived connections with known peers
//! - **Private distributed systems**: Where all participants are pre-authorized
//! - **Microservice communication**: Within a trusted network boundary
//! - **IoT device networks**: Where devices have embedded cryptographic identities
//!
//! ## Unsuitable Use Cases
//!
//! - **Anonymous communication**: This protocol provides NO identity hiding
//! - **Public web services**: Use TLS/HTTPS instead
//! - **Consensus protocols**: May have unnecessary encryption overhead (see below)
//! - **High-frequency trading**: Encryption adds ~20-50μs latency per message
//!
//! # Protocol Assumptions and Limitations
//!
//! ## Security Assumptions
//!
//! - **No identity hiding**: Peer identities are transmitted in plaintext during handshake.
//!   An eavesdropper can determine which peers are communicating.
//! - **Pre-shared namespace**: The namespace parameter must be agreed upon out-of-band
//! - **Time synchronization**: Peers must have reasonably synchronized clocks (within `synchrony_bound`)
//! - **Trusted first connection**: No protection against active MITM on first connection
//!   (unlike TLS with certificate authorities)
//!
//! ## Performance Considerations
//!
//! - **Encryption overhead**: Each message has 16-byte authentication tag overhead
//! - **CPU cost**: ChaCha20-Poly1305 encryption/decryption for every message
//! - **Handshake latency**: 3-RTT handshake before data can be exchanged
//! - **No multiplexing**: One connection per peer pair (no stream multiplexing)
//!
//! ## Design Trade-offs
//!
//! ### Why Not Just Authentication?
//!
//! Some use cases (e.g., consensus protocols) only need authenticated channels since:
//! - Messages are often public anyway (e.g., blocks, votes)
//! - Encryption adds unnecessary CPU overhead
//! - Lower latency is more important than confidentiality
//!
//! However, this protocol always encrypts because:
//! - Prevents selective message dropping by intermediaries
//! - Protects against traffic analysis
//! - Simplifies the protocol (no negotiation of encryption on/off)
//! - Future-proofs against evolving privacy requirements
//!
//! For authentication-only use cases, consider using signed messages over plain TCP instead.
//!
//! ### Identity Exposure
//!
//! During handshake, both peers send their public keys in plaintext. This means:
//! - Network observers can build a connection graph
//! - Peer identities are linkable across connections
//! - No protection against targeted traffic analysis
//!
//! This is acceptable when:
//! - The network topology is public anyway
//! - Peers have static, long-lived identities
//! - Regulatory compliance requires identity visibility
//!
//! This is NOT acceptable when:
//! - Anonymous communication is required
//! - Peer identities should be unlinkable
//! - Protection against metadata analysis is needed
//!
//! # Design
//!
//! ## Handshake
//!
//! A 3-message handshake provides mutual authentication and establishes a shared secret
//! between peers. Custom implementation supports arbitrary cryptographic schemes without
//! protocol negotiation overhead.
//!
//! The **dialer** initiates the connection to a known peer identity, while the **listener**
//! accepts incoming connections. Much like a SYN / SYN-ACK / ACK handshake, the dialer and listener
//! exchange messages in three rounds.
//!
//! The SYN-equivalent is a [handshake::Hello] message that contains:
//! - The recipient's expected public key (prevents wrong-target attacks)
//! - The sender's ephemeral public key (for Diffie-Hellman key exchange)
//! - The current timestamp (prevents replay attacks)
//! - The sender's static public key and signature
//!
//! The ACK-equivalent is a [handshake::Confirmation] message that proves that each party can derive
//! the correct shared secret.
//!
//! Thus:
//! - Message 1 is a `Hello` message from the dialer to the listener
//! - Message 2 is a `Hello` and `Confirmation` message from the listener to the dialer
//! - Message 3 is a `Confirmation` message from the dialer to the listener
//!
//! ### Security Properties
//!
//! This protocol provides:
//!
//! - **Mutual Authentication**: Both parties prove existence of their static private keys through
//!   signatures.
//! - **Replay Protection**: Confirmations are bound to the handshake transcript to prevent replay
//!   attacks by confirming that the peer that sent the `Hello` message (with the cryptographic
//!   signature) also had possession of the ephemeral key.
//! - **Forward Secrecy**: Ephemeral keys ensure that any compromise of long-term static keys
//!   doesn't affect other sessions.
//! - **DoS Protection**: A configurable deadline is enforced for handshake completion to protect
//!   against DoS attacks by malicious peers that create connections but abandon handshakes.
//!
//! ## Encryption
//!
//! During the handshake, a shared X25519 secret is established using Diffie-Hellman key exchange.
//! This secret is combined with the handshake transcript to derive four separate ChaCha20-Poly1305
//! ciphers:
//!
//! - **Confirmation Ciphers**: One cipher per direction for key confirmation during the handshake
//! - **Traffic Ciphers**: One cipher per direction for encrypting post-handshake traffic
//!
//! Using the handshake transcript in key derivation ensures that derived keys
//! are bound to the specific handshake exchange, providing additional security against
//! man-in-the-middle and transcript substitution attacks.
//!
//! Each direction of communication uses a 12-byte nonce derived from a counter that is
//! incremented for each message sent. This provides a maximum of 2^96 messages per sender,
//! which would be sufficient for over 2.5 trillion years of continuous communication at a rate of
//! 1 billion messages per second—sufficient for all practical use cases. This approach ensures that
//! well-behaving peers can remain connected indefinitely as long as they both stay online
//! (maximizing p2p network stability). In the unlikely case of counter overflow, the connection
//! will be terminated and a new connection should be established.
//!
//! This prevents nonce reuse (which would compromise message confidentiality)
//! and saves bandwidth (as there is no need to transmit nonces alongside encrypted messages).
//!
//! # Alternative Approaches
//!
//! Depending on your specific requirements, consider these alternatives:
//!
//! ## For Consensus Protocols
//!
//! If you only need authenticated channels (common in consensus protocols):
//! ```ignore
//! // Option 1: Sign each message individually
//! let signed_msg = crypto.sign(&msg);
//! tcp_stream.send(&signed_msg);
//!
//! // Option 2: Use HMAC with a shared key derived from DH
//! let mac = hmac_sha256(&shared_key, &msg);
//! tcp_stream.send(&(msg, mac));
//! ```
//!
//! ## For Anonymous Communication
//!
//! If identity hiding is required:
//! - Use Tor or I2P for network-layer anonymity
//! - Implement a protocol with ephemeral identities
//! - Consider noise protocol framework with XX or IK patterns
//!
//! ## For Public Services
//!
//! If you need:
//! - Web browser compatibility
//! - Certificate authority trust model  
//! - Protocol negotiation (ALPN)
//! - Standard compliance
//!
//! Use TLS 1.3 with QUIC or HTTP/3 instead.
//!
//! # Implementation Notes
//!
//! - **Thread Safety**: Connection splitting allows concurrent send/receive
//! - **Backpressure**: Implemented at the stream level, not in this protocol
//! - **Keep-alive**: Not implemented; use application-level heartbeats if needed
//! - **Reconnection**: Not automatic; implement at application layer if required
//! - **Connection Pooling**: One connection per peer; no built-in pooling

use chacha20poly1305::{
    aead::{generic_array::typenum::Unsigned, AeadCore},
    ChaCha20Poly1305,
};
use std::time::Duration;

mod cipher;
mod connection;
use commonware_cryptography::Signer;
pub use connection::{Connection, IncomingConnection, Receiver, Sender};
pub mod handshake;
mod nonce;
pub mod x25519;

// When encrypting data, an authentication tag is appended to the ciphertext.
// This constant represents the size of the authentication tag in bytes.
const AUTHENTICATION_TAG_LENGTH: usize = <ChaCha20Poly1305 as AeadCore>::TagSize::USIZE;

/// Configuration for a connection.
///
/// # Warning
///
/// Synchronize this configuration across all peers.
/// Mismatched configurations may cause dropped connections or parsing errors.
#[derive(Clone)]
pub struct Config<C: Signer> {
    /// Cryptographic primitives for signing and verification.
    pub crypto: C,

    /// Unique prefix for all signed messages. Should be application-specific.
    /// Prevents replay attacks across different applications using the same keys.
    pub namespace: Vec<u8>,

    /// Maximum message size (in bytes). Prevents memory exhaustion DoS attacks.
    pub max_message_size: usize,

    /// Maximum time drift allowed for future timestamps. Handles clock skew.
    pub synchrony_bound: Duration,

    /// Maximum age of handshake messages before rejection.
    pub max_handshake_age: Duration,

    /// Maximum time allowed for completing the handshake.
    pub handshake_timeout: Duration,
}
