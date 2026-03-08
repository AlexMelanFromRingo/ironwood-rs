//! Transport helpers for connecting `PacketConn` over TLS or plain TCP.
//!
//! `PacketConn::handle_conn` accepts any `AsyncRead + AsyncWrite` stream, so TLS
//! and QUIC are supported by wrapping the underlying stream before passing it in.
//!
//! # TLS (self-signed, skip-verify — same as yggdrasil-go)
//!
//! Yggdrasil uses TLS with self-signed certificates and skips certificate
//! verification — authentication is done at the Ironwood layer via ed25519 key
//! exchange, not X.509. This matches the behaviour of `yggdrasil-go`.
//!
//! ## Example: dial a TLS peer
//!
//! ```rust,no_run
//! use ironwood_rs::{PacketConn, transport};
//! use ed25519_dalek::SigningKey;
//! use rand::rngs::OsRng;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let key = SigningKey::generate(&mut OsRng);
//!     let conn = PacketConn::new(key).await?;
//!
//!     // Dial a TLS peer (certificate not verified — auth happens at Ironwood layer)
//!     let stream = transport::dial_tls("tls://peer.example.com:443").await?;
//!     tokio::spawn(async move { conn.handle_conn(stream).await });
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Example: listen for TLS peers
//!
//! ```rust,no_run
//! use ironwood_rs::{PacketConn, transport};
//! use ed25519_dalek::SigningKey;
//! use rand::rngs::OsRng;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let key = SigningKey::generate(&mut OsRng);
//!     let conn = PacketConn::new(key).await?;
//!
//!     let listener = transport::listen_tls("0.0.0.0:9001").await?;
//!     loop {
//!         let (stream, _addr) = listener.accept().await?;
//!         let c = conn.clone();
//!         tokio::spawn(async move { c.handle_conn(stream).await });
//!     }
//! }
//! ```

use anyhow::{anyhow, Result};
use blake2::Blake2b512;
use ed25519_dalek::{Signature, SigningKey, Signer, Verifier, VerifyingKey};
use quinn::crypto::rustls::QuicClientConfig;
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::{PacketConn, PublicKeyBytes};

// ---------------------------------------------------------------------------
// High-level: connect a raw stream to a PacketConn
// ---------------------------------------------------------------------------

/// Connect a raw async stream to a `PacketConn`.
///
/// Performs a minimal key-exchange handshake (each side sends its 32-byte
/// ed25519 public key, then reads the remote key) and calls
/// [`PacketConn::handle_conn`].  This is all that is needed for two
/// `ironwood-rs` nodes to talk to each other.
///
/// For connecting to a `yggdrasil-go` node, use the yggdrasil version-metadata
/// handshake instead (see `yggdrasil-rs/src/core/handshake.rs`).
///
/// Returns when the peer disconnects or an error occurs.
pub async fn handle_stream<S>(conn: &PacketConn, stream: S, priority: u8) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);

    // Exchange 32-byte ed25519 public keys
    let our_key = conn.public_key();
    writer.write_all(&our_key).await
        .map_err(|e| anyhow!("key exchange write: {e}"))?;

    let mut peer_key = [0u8; 32];
    reader.read_exact(&mut peer_key).await
        .map_err(|e| anyhow!("key exchange read: {e}"))?;

    conn.handle_conn(
        peer_key,
        Box::new(reader),
        Box::new(writer),
        priority,
    ).await
}

// ---------------------------------------------------------------------------
// Acceptor (listen side)
// ---------------------------------------------------------------------------

/// A TLS listener wrapping a `TcpListener`.
pub struct TlsListener {
    inner: TcpListener,
    acceptor: TlsAcceptor,
}

impl TlsListener {
    /// Accept the next inbound TLS connection.
    ///
    /// Returns a stream that implements `AsyncRead + AsyncWrite` and can be
    /// passed directly to `PacketConn::handle_conn`.
    pub async fn accept(&self) -> Result<(tokio_rustls::server::TlsStream<TcpStream>, SocketAddr)> {
        let (tcp, addr) = self.inner.accept().await?;
        let tls = self.acceptor.accept(tcp).await
            .map_err(|e| anyhow!("TLS accept failed: {e}"))?;
        Ok((tls, addr))
    }
}

/// Create a TLS listener on `addr` using a freshly generated self-signed certificate.
///
/// Yggdrasil-go uses self-signed certs and skips peer cert verification — all
/// authentication is handled by the Ironwood ed25519 handshake.
pub async fn listen_tls(addr: &str) -> Result<TlsListener> {
    let tcp = TcpListener::bind(addr).await
        .map_err(|e| anyhow!("bind {addr}: {e}"))?;

    let cert_key = rcgen::generate_simple_self_signed(vec!["yggdrasil".to_string()])
        .map_err(|e| anyhow!("cert gen: {e}"))?;
    let cert_der = rustls_pki_types::CertificateDer::from(cert_key.cert.der().to_vec());
    let key_der = rustls_pki_types::PrivateKeyDer::try_from(cert_key.key_pair.serialize_der())
        .map_err(|e| anyhow!("key der: {e}"))?;

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| anyhow!("TLS server config: {e}"))?;

    Ok(TlsListener {
        inner: tcp,
        acceptor: TlsAcceptor::from(Arc::new(server_config)),
    })
}

// ---------------------------------------------------------------------------
// Connector (dial side)
// ---------------------------------------------------------------------------

/// Dial a TLS peer, skipping certificate verification.
///
/// `addr` can be:
/// - `"host:port"` — plain host:port
/// - `"tls://host:port"` — with scheme prefix (stripped automatically)
///
/// Certificate verification is intentionally skipped to match yggdrasil-go
/// behaviour: the Ironwood ed25519 handshake provides the actual authentication.
pub async fn dial_tls(addr: &str) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let addr = addr.strip_prefix("tls://").unwrap_or(addr);

    let tcp = TcpStream::connect(addr).await
        .map_err(|e| anyhow!("TCP connect {addr}: {e}"))?;

    let client_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(client_config));

    // SNI name: use a fixed placeholder since we don't verify certs anyway.
    let server_name = ServerName::try_from("yggdrasil")
        .map_err(|e| anyhow!("server name: {e}"))?;

    let tls = connector.connect(server_name, tcp).await
        .map_err(|e| anyhow!("TLS handshake {addr}: {e}"))?;

    Ok(tls)
}

/// Dial a plain TCP peer.
///
/// `addr` can be:
/// - `"host:port"` — plain host:port
/// - `"tcp://host:port"` — with scheme prefix (stripped automatically)
pub async fn dial_tcp(addr: &str) -> Result<TcpStream> {
    let addr = addr.strip_prefix("tcp://").unwrap_or(addr);
    TcpStream::connect(addr).await
        .map_err(|e| anyhow!("TCP connect {addr}: {e}"))
}

// ---------------------------------------------------------------------------
// QUIC transport
// ---------------------------------------------------------------------------

/// A QUIC listener wrapping a `quinn::Endpoint`.
pub struct QuicListener {
    endpoint: quinn::Endpoint,
}

impl QuicListener {
    /// Accept the next inbound QUIC connection.
    ///
    /// Returns the first bidirectional stream, which can be passed to
    /// `handle_stream` or `handle_yggdrasil_stream`.
    pub async fn accept(&self) -> Result<(quinn::SendStream, quinn::RecvStream)> {
        let conn = self.endpoint.accept().await
            .ok_or_else(|| anyhow!("QUIC endpoint closed"))?
            .await
            .map_err(|e| anyhow!("QUIC accept: {e}"))?;

        let (send, recv) = conn.accept_bi().await
            .map_err(|e| anyhow!("QUIC accept_bi: {e}"))?;
        Ok((send, recv))
    }
}

/// Create a QUIC listener on `addr` using a freshly generated self-signed certificate.
///
/// Like TLS, certificate verification is skipped — Ironwood ed25519 handshake
/// provides authentication.
pub async fn listen_quic(addr: &str) -> Result<QuicListener> {
    let addr: SocketAddr = addr.parse()
        .map_err(|e| anyhow!("parse addr {addr}: {e}"))?;

    let cert_key = rcgen::generate_simple_self_signed(vec!["yggdrasil".to_string()])
        .map_err(|e| anyhow!("cert gen: {e}"))?;
    let cert_der = rustls_pki_types::CertificateDer::from(cert_key.cert.der().to_vec());
    let key_der = rustls_pki_types::PrivateKeyDer::try_from(cert_key.key_pair.serialize_der())
        .map_err(|e| anyhow!("key der: {e}"))?;

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| anyhow!("TLS server config: {e}"))?;

    let quic_server = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_config)
            .map_err(|e| anyhow!("QUIC server config: {e}"))?,
    ));

    let endpoint = quinn::Endpoint::server(quic_server, addr)
        .map_err(|e| anyhow!("QUIC bind {addr}: {e}"))?;

    Ok(QuicListener { endpoint })
}

/// Dial a QUIC peer.
///
/// `addr` can be:
/// - `"host:port"` — plain host:port
/// - `"quic://host:port"` — with scheme prefix (stripped automatically)
///
/// Certificate verification is skipped (auth happens at Ironwood layer).
/// Returns `(send, recv)` for the first bidirectional stream.
pub async fn dial_quic(addr: &str) -> Result<(quinn::SendStream, quinn::RecvStream)> {
    let addr = addr.strip_prefix("quic://").unwrap_or(addr);

    let client_config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();

    let quic_client = QuicClientConfig::try_from(client_config)
        .map_err(|e| anyhow!("QUIC client config: {e}"))?;

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
        .map_err(|e| anyhow!("QUIC client endpoint: {e}"))?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_client)));

    let remote: SocketAddr = addr.parse()
        .map_err(|e| anyhow!("parse addr {addr}: {e}"))?;

    let conn = endpoint.connect(remote, "yggdrasil")
        .map_err(|e| anyhow!("QUIC connect {addr}: {e}"))?
        .await
        .map_err(|e| anyhow!("QUIC handshake {addr}: {e}"))?;

    let (send, recv) = conn.open_bi().await
        .map_err(|e| anyhow!("QUIC open_bi: {e}"))?;
    Ok((send, recv))
}

// ---------------------------------------------------------------------------
// Yggdrasil-go-compatible handshake
// ---------------------------------------------------------------------------

/// Connect a stream using the **yggdrasil-go version-metadata handshake**.
///
/// This is the handshake used by yggdrasil-go nodes. Use this instead of
/// [`handle_stream`] when connecting to a live yggdrasil-go node.
///
/// Wire format:
/// ```text
/// [magic "meta" 4B] [remaining-len u16 BE] [TLVs...] [ed25519 sig 64B]
/// TLVs: (type u16, len u16, value):
///   0 = major_ver (u16)  1 = minor_ver (u16)
///   2 = public_key (32B) 3 = priority  (u8)
/// Signature: ed25519(signing_key).sign(BLAKE2b-512(public_key))
/// ```
///
/// ## Example
///
/// ```rust,no_run
/// use ironwood_rs::{PacketConn, transport};
/// use ed25519_dalek::SigningKey;
/// use rand::rngs::OsRng;
///
/// #[tokio::main]
/// async fn main() -> anyhow::Result<()> {
///     let signing_key = SigningKey::generate(&mut OsRng);
///     let conn = PacketConn::new(signing_key.clone());
///
///     let stream = transport::dial_tls("tls://ygg.mkg20001.io:443").await?;
///     tokio::spawn(async move {
///         transport::handle_yggdrasil_stream(&conn, stream, &signing_key, b"", 0)
///             .await
///             .unwrap_or(());
///     });
///     Ok(())
/// }
/// ```
pub async fn handle_yggdrasil_stream<S>(
    conn: &PacketConn,
    stream: S,
    signing_key: &SigningKey,
    password: &[u8],
    priority: u8,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);

    let our_pub: [u8; 32] = signing_key.verifying_key().to_bytes();

    // --- Send our metadata ---
    let encoded = encode_version_metadata(&our_pub, signing_key, password, priority)?;
    writer.write_all(&encoded).await
        .map_err(|e| anyhow!("handshake write: {e}"))?;

    // --- Receive peer metadata ---
    let peer_meta = decode_version_metadata(&mut reader, password).await?;
    if !is_compatible_version(peer_meta.major_ver, peer_meta.minor_ver) {
        return Err(anyhow!(
            "incompatible protocol version {}.{} (we speak 0.5)",
            peer_meta.major_ver, peer_meta.minor_ver
        ));
    }

    conn.handle_conn(
        peer_meta.public_key,
        Box::new(reader),
        Box::new(writer),
        priority,
    ).await
}

// Protocol version we implement (same as yggdrasil-go v0.5.x)
const VERSION_MAJOR: u16 = 0;
const VERSION_MINOR: u16 = 5;

fn is_compatible_version(major: u16, minor: u16) -> bool {
    major == VERSION_MAJOR && minor == VERSION_MINOR
}

fn encode_version_metadata(
    pub_key: &[u8; 32],
    signing_key: &SigningKey,
    password: &[u8],
    priority: u8,
) -> Result<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::with_capacity(128);
    buf.extend_from_slice(b"meta");
    buf.extend_from_slice(&[0u8, 0u8]); // remaining-length placeholder

    // TLV: major version (type=0, len=2)
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&2u16.to_be_bytes());
    buf.extend_from_slice(&VERSION_MAJOR.to_be_bytes());

    // TLV: minor version (type=1, len=2)
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.extend_from_slice(&2u16.to_be_bytes());
    buf.extend_from_slice(&VERSION_MINOR.to_be_bytes());

    // TLV: public key (type=2, len=32)
    buf.extend_from_slice(&2u16.to_be_bytes());
    buf.extend_from_slice(&32u16.to_be_bytes());
    buf.extend_from_slice(pub_key);

    // TLV: priority (type=3, len=1)
    buf.extend_from_slice(&3u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    buf.push(priority);

    // Signature: ed25519(BLAKE2b-512(password)(pub_key))
    let hash = blake2b_hash(pub_key, password)?;
    let sig: ed25519_dalek::Signature = signing_key.sign(&hash);
    buf.extend_from_slice(&sig.to_bytes());

    // Fill remaining-length
    let remaining = (buf.len() - 6) as u16;
    buf[4] = (remaining >> 8) as u8;
    buf[5] = remaining as u8;

    Ok(buf)
}

struct PeerMeta {
    major_ver: u16,
    minor_ver: u16,
    public_key: [u8; 32],
}

async fn decode_version_metadata<R: AsyncRead + Unpin>(
    reader: &mut R,
    password: &[u8],
) -> Result<PeerMeta> {
    let mut header = [0u8; 6];
    reader.read_exact(&mut header).await
        .map_err(|e| anyhow!("handshake read header: {e}"))?;

    if &header[..4] != b"meta" {
        return Err(anyhow!("invalid handshake magic — peer is not yggdrasil"));
    }

    let remaining_len = u16::from_be_bytes([header[4], header[5]]) as usize;
    if remaining_len < 64 {
        return Err(anyhow!("handshake frame too short ({remaining_len}B)"));
    }

    let mut body = vec![0u8; remaining_len];
    reader.read_exact(&mut body).await
        .map_err(|e| anyhow!("handshake read body: {e}"))?;

    let sig_bytes = &body[body.len() - 64..];
    let tlvs = &body[..body.len() - 64];

    let mut meta = PeerMeta { major_ver: 0, minor_ver: 0, public_key: [0u8; 32] };
    let mut rest = tlvs;
    while rest.len() >= 4 {
        let op = u16::from_be_bytes([rest[0], rest[1]]);
        let oplen = u16::from_be_bytes([rest[2], rest[3]]) as usize;
        rest = &rest[4..];
        if rest.len() < oplen { break; }
        match op {
            0 if oplen >= 2 => meta.major_ver = u16::from_be_bytes([rest[0], rest[1]]),
            1 if oplen >= 2 => meta.minor_ver = u16::from_be_bytes([rest[0], rest[1]]),
            2 if oplen == 32 => meta.public_key.copy_from_slice(&rest[..32]),
            _ => {}
        }
        rest = &rest[oplen..];
    }

    // Verify signature
    let hash = blake2b_hash(&meta.public_key, password)?;
    let vk = VerifyingKey::from_bytes(&meta.public_key)
        .map_err(|e| anyhow!("peer has invalid public key: {e}"))?;
    let sig_arr: [u8; 64] = sig_bytes.try_into()
        .map_err(|_| anyhow!("signature length mismatch"))?;
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(&hash, &sig)
        .map_err(|_| anyhow!("handshake signature verification failed"))?;

    Ok(meta)
}

fn blake2b_hash(data: &[u8], password: &[u8]) -> Result<Vec<u8>> {
    if password.is_empty() {
        use blake2::Digest;
        let mut h = Blake2b512::new();
        Digest::update(&mut h, data);
        return Ok(Digest::finalize(h).to_vec());
    }
    use blake2::{Blake2bMac512, digest::{KeyInit, Mac}};
    let mut h = <Blake2bMac512 as KeyInit>::new_from_slice(password)
        .map_err(|e| anyhow!("BLAKE2b key error: {e}"))?;
    Mac::update(&mut h, data);
    Ok(Mac::finalize(h).into_bytes().to_vec())
}

// ---------------------------------------------------------------------------
// Certificate verifier: skip-verify (matches yggdrasil-go)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer,
        _intermediates: &[rustls_pki_types::CertificateDer],
        _server_name: &rustls_pki_types::ServerName,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
