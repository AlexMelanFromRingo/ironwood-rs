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
