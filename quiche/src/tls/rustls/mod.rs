// Copyright (C) 2025, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

mod verifiers;

use crate::crypto::crypto_provider;
use crate::crypto::key_material_from_keys;
use crate::crypto::Algorithm;
use crate::crypto::Level;
use crate::crypto::Open;
use crate::crypto::Seal;
use crate::packet;
use crate::tls::rustls::verifiers::DisabledServerCertVerifier;
use crate::tls::rustls::verifiers::RejectedClientCertAllowedAnonymousVerifier;
use crate::ConnectionError;
use crate::Error;
use crate::Result;
use rustls::client::ClientSessionMemoryCache;
use rustls::client::Resumption;
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::ServerName;
use rustls::quic::ClientConnection;
use rustls::quic::Connection;
use rustls::quic::KeyChange;
use rustls::quic::Keys;
use rustls::quic::Secrets;
use rustls::quic::ServerConnection;
use rustls::quic::Version;
use rustls::server::WebPkiClientVerifier;
use rustls::version::TLS13;
use rustls::CipherSuite;
use rustls::ClientConfig;
use rustls::HandshakeKind;
use rustls::KeyLogFile;
use rustls::RootCertStore;
use rustls::ServerConfig;
use rustls::Side;
use std::fs::DirEntry;
use std::sync::Arc;

const INTERNAL_ERROR: u64 = 0x01;
const TLS_ALERT_ERROR: u64 = 0x100;

/// Connection state the TLS callbacks-equivalent code paths mutate during
/// `do_handshake`. Mirrors the boringssl backend's `ExData`, minus the fields
/// only its C callbacks need (ALPN, keylog and trace id live in the rustls
/// configs instead).
pub struct ExData<'a> {
    pub crypto_ctx: &'a mut [packet::CryptoContext; packet::Epoch::count()],

    pub session: &'a mut Option<Vec<u8>>,

    pub local_error: &'a mut Option<ConnectionError>,

    pub local_transport_params: crate::TransportParams,

    pub recovery_config: crate::recovery::RecoveryConfig,

    pub tx_cap_factor: f64,

    /// PMTUD configuration: (enable, max_probes)
    pub pmtud: Option<(bool, u8)>,
}

pub struct Context {
    client_config: Option<Arc<ClientConfig>>,
    server_config: Option<Arc<ServerConfig>>,
    // required to build the above configs
    // are consumed during configs building
    private_key: Option<PrivateKeyDer<'static>>,
    ca_certificates: Option<Vec<CertificateDer<'static>>>,
    verify_ca_certificates_store: Option<RootCertStore>,
    system_default_cert_store: Option<RootCertStore>,
    alpns: Vec<Vec<u8>>,
    enable_verify_ca_certificates: bool,
    enable_keylog: bool,
    enable_early_data: bool,
    quic_version: Version,
    client_resumption_store: Arc<ClientSessionMemoryCache>,
}

impl Context {
    pub fn new() -> Result<Self> {
        let _ = crypto_provider();

        Ok(Self {
            client_config: None,
            server_config: None,
            private_key: None,
            ca_certificates: None,
            enable_verify_ca_certificates: false,
            verify_ca_certificates_store: None,
            system_default_cert_store: None,
            enable_keylog: false,
            enable_early_data: false,
            quic_version: Default::default(),
            alpns: vec![],
            client_resumption_store: Arc::new(ClientSessionMemoryCache::new(256)),
        })
    }

    pub fn new_handshake(&mut self) -> Result<Handshake> {
        // user supplied verification store when enabled and available
        // used for server mTLS validation on server or
        // used for server certificate validation on client
        let verify_store = if self.enable_verify_ca_certificates {
            self.verify_ca_certificates_store.clone()
        } else {
            None
        };

        if self.server_config.is_none() &&
            self.private_key.is_some() &&
            self.ca_certificates.is_some()
        {
            let builder =
                ServerConfig::builder_with_provider(crypto_provider().clone())
                    .with_protocol_versions(&[&TLS13])
                    .map_err(|e| {
                        error!("failed to set protocol version for server config builder: {}", e);
                        Error::TlsFail
                    })?;
            // setup user supplied and enabled CA certificates for mTLS auth
            let builder = if let Some(verify_store) = verify_store.clone() {
                let client_verifier =
                    WebPkiClientVerifier::builder(verify_store.into())
                        .allow_unauthenticated()
                        .build()
                        .map_err(|e| {
                            error!("client_verifier: failed to build {}", e);
                            Error::TlsFail
                        })?;

                builder.with_client_cert_verifier(client_verifier)
            } else {
                if self.enable_verify_ca_certificates {
                    // in case no store is present fail on mTLS authentication
                    // user warning is issued during Handshake.do_handshake()
                    builder.with_client_cert_verifier(Arc::new(
                        RejectedClientCertAllowedAnonymousVerifier::new()?,
                    ))
                } else {
                    builder.with_no_client_auth()
                }
            };

            let (Some(certs), Some(key)) = (
                self.ca_certificates.clone(),
                self.private_key.as_ref().map(|k| k.clone_key()),
            ) else {
                error!(
                    "server without certificate and key config is not supported"
                );
                return Err(Error::TlsFail);
            };

            let mut config =
                builder.with_single_cert(certs, key).map_err(|e| {
                    error!("loading certificate or key failed: {}", e);
                    Error::TlsFail
                })?;

            if self.enable_keylog {
                config.key_log = Arc::new(KeyLogFile::new());
            }

            if self.enable_early_data {
                // rustls currently only allows 0 or 2^32-1 for max early data
                // size
                config.max_early_data_size = u32::MAX;
            }

            if !self.alpns.is_empty() {
                config.alpn_protocols = self.alpns.clone();
            }

            self.server_config = Some(Arc::new(config));
        };

        if self.client_config.is_none() {
            let builder =
                ClientConfig::builder_with_provider(crypto_provider().clone())
                    .with_protocol_versions(&[&TLS13])
                    .map_err(|e| {
                        error!("failed to set protocol version for client config builder: {}", e);
                        Error::TlsFail
                    })?;

            // setup user supplied and enabled CA certificates for server
            // certificate validation
            let builder = if let Some(verify_store) = verify_store.clone() {
                let server_verifier =
                    WebPkiServerVerifier::builder(verify_store.into())
                        .build()
                        .map_err(|e| {
                            error!("failed to build server verifier: {}", e);
                            Error::TlsFail
                        })?;

                builder.with_webpki_verifier(server_verifier)
            } else {
                // in case enabled but no CA certificates provided use system
                // default CAs
                if self.enable_verify_ca_certificates {
                    // default to env variables or system store
                    let store = self.load_system_default_certificate_store();
                    builder.with_root_certificates(store)
                } else {
                    // completely deactivate validation
                    let builder = builder.dangerous();
                    let disabled_server_verification =
                        Arc::new(DisabledServerCertVerifier::new()?);
                    builder.with_custom_certificate_verifier(
                        disabled_server_verification,
                    )
                }
            };

            let mut config = if let (Some(certs), Some(key)) = (
                self.ca_certificates.clone(),
                self.private_key.as_ref().map(|k| k.clone_key()),
            ) {
                builder.with_client_auth_cert(certs, key).map_err(|e| {
                    error!("failed to set client auth: {}", e);
                    Error::TlsFail
                })?
            } else {
                builder.with_no_client_auth()
            };

            if self.enable_keylog {
                config.key_log = Arc::new(KeyLogFile::new());
            }

            if self.enable_early_data {
                config.enable_early_data = true;
            }

            if !self.alpns.is_empty() {
                config.alpn_protocols = self.alpns.clone();
            }

            // required for 0-rtt, the resumption store is persisted within the
            // Context and propagated to all connections on the
            // ClientConfig
            config.resumption =
                Resumption::store(self.client_resumption_store.clone());

            self.client_config = Some(Arc::new(config))
        }

        Ok(Handshake {
            client_config: self.client_config.clone().ok_or_else(|| {
                error!("no client config available");
                Error::TlsFail
            })?,
            server_config: self.server_config.clone(),
            quic_version: self.quic_version,
            connection: None,
            side: Side::Client, // dummy value, correctly set during init()
            enable_verify_ca_certificates: self.enable_verify_ca_certificates,
            quic_transport_params: None,
            provided_data: None,
            highest_level: Level::Initial,
            hostname: None,
            one_rtt_keys_secrets: None,
            pending_tls_error: None,
        })
    }

    fn load_system_default_certificate_store(&mut self) -> RootCertStore {
        // loading the files is an expensive operation, ensure it's only done once
        // system default cert store is used in some areas
        if let Some(store) = &self.system_default_cert_store {
            return store.clone();
        };

        let mut system_default_certificate_store = RootCertStore::empty();
        let certificates_result = rustls_native_certs::load_native_certs();
        system_default_certificate_store
            .add_parsable_certificates(certificates_result.certs);

        self.system_default_cert_store = Some(system_default_certificate_store);
        self.system_default_cert_store.clone().unwrap()
    }

    pub fn load_verify_locations_from_file(&mut self, file: &str) -> Result<()> {
        let verify_certificates = Self::load_ca_certificates_from_file(file)?;
        self.extend_verify_ca_certificates(verify_certificates);
        self.invalidate_configs();
        Ok(())
    }

    pub fn load_verify_locations_from_directory(
        &mut self, path: &str,
    ) -> Result<()> {
        let files: Result<Vec<DirEntry>> = std::fs::read_dir(path)
            .map_err(|e| {
                error!("failed to load verify locations from directory: {:?}", e);
                Error::TlsFail
            })?
            .map(|rd| {
                rd.map_err(|e| {
                    error!(
                        "failed to load verify locations from directory: {:?}",
                        e
                    );
                    Error::TlsFail
                })
            })
            .collect();

        let verify_certificates: Vec<CertificateDer> = files?
            .into_iter()
            .map(|f| Self::load_ca_certificates_from_file(f.path()))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect();

        self.extend_verify_ca_certificates(verify_certificates);
        self.invalidate_configs();
        Ok(())
    }

    pub fn use_certificate_chain_file(&mut self, file: &str) -> Result<()> {
        self.ca_certificates = Some(Self::load_ca_certificates_from_file(file)?);
        self.invalidate_configs();
        Ok(())
    }

    fn load_ca_certificates_from_file(
        file: impl AsRef<std::path::Path>,
    ) -> Result<Vec<CertificateDer<'static>>> {
        let certificates: Result<Vec<CertificateDer>> =
            CertificateDer::pem_file_iter(file)
                .map_err(|e| {
                    error!("failed to load ca certificates from pem file: {}", e);
                    Error::TlsFail
                })?
                .map(|r| {
                    r.map_err(|e| {
                        error!("failed to load pem certificate: {}", e);
                        Error::TlsFail
                    })
                })
                .collect();
        certificates
    }

    fn extend_verify_ca_certificates(
        &mut self, verify_certificates: Vec<CertificateDer<'static>>,
    ) {
        if let Some(cert_store) = &mut self.verify_ca_certificates_store {
            cert_store.add_parsable_certificates(verify_certificates);
        } else {
            let mut store = RootCertStore::empty();
            store.add_parsable_certificates(verify_certificates);
            self.verify_ca_certificates_store = Some(store);
        }
    }

    pub fn use_privkey_file(&mut self, file: &str) -> Result<()> {
        let private_key = PrivateKeyDer::from_pem_file(file).map_err(|e| {
            error!("failed to load private key from pem: {}", e);
            Error::TlsFail
        })?;

        self.private_key = Some(private_key);
        self.invalidate_configs();
        Ok(())
    }

    /// Built configs snapshot the settings at `new_handshake()` time; any
    /// change afterwards (certificate rotation, ALPN, verification, keylog,
    /// early data) must rebuild them or later connections silently keep the
    /// old configuration.
    fn invalidate_configs(&mut self) {
        self.client_config = None;
        self.server_config = None;
    }

    pub fn set_verify(&mut self, verify: bool) {
        self.enable_verify_ca_certificates = verify;
        self.invalidate_configs();
    }

    /// Keys are logged to the file named by the `SSLKEYLOGFILE` environment
    /// variable, rustls's standard mechanism. A per-connection writer passed
    /// to `Connection::set_keylog()` is NOT supported by this backend: rustls
    /// key logging is configured per config, not per connection.
    pub fn enable_keylog(&mut self) {
        self.enable_keylog = true;
        self.invalidate_configs();
    }

    pub fn set_alpn(&mut self, v: &[&[u8]]) -> Result<()> {
        let alpns: Vec<Vec<u8>> = v.iter().map(|a| a.to_vec()).collect();
        self.alpns = alpns;
        self.invalidate_configs();
        Ok(())
    }

    // not supported in rustls
    // pub fn set_ticket_key(&mut self, _key: &[u8]) -> Result<()> {}

    pub fn set_early_data_enabled(&mut self, enabled: bool) {
        self.enable_early_data = enabled;
        self.invalidate_configs();
    }
}

pub struct Handshake {
    client_config: Arc<ClientConfig>,
    server_config: Option<Arc<ServerConfig>>,
    quic_version: Version,

    side: Side,
    enable_verify_ca_certificates: bool,
    quic_transport_params: Option<Vec<u8>>,
    hostname: Option<ServerName<'static>>,
    connection: Option<Connection>,

    highest_level: Level,
    provided_data: Option<Vec<u8>>,
    one_rtt_keys_secrets: Option<(Keys, Secrets)>,

    /// A fatal TLS alert from `read_hs`, surfaced on the next
    /// `do_handshake()` call, which owns the `ExData` needed to record the
    /// QUIC-level CRYPTO_ERROR close.
    pending_tls_error: Option<ConnectionError>,
}

impl Handshake {
    pub fn init(&mut self, is_server: bool) -> Result<()> {
        self.side = match is_server {
            true => Side::Server,
            false => Side::Client,
        };

        Ok(())
    }

    pub fn use_legacy_codepoint(&mut self, _use_legacy: bool) {
        // noop for rustls
    }

    pub fn set_host_name(&mut self, name: &str) -> Result<()> {
        let hostname = ServerName::try_from(name)
            .map_err(|e| {
                error!("failed to convert hostname: {}", e);
                Error::TlsFail
            })?
            .to_owned();

        self.hostname = Some(hostname);
        Ok(())
    }

    pub fn set_quic_transport_params(
        &mut self, params: &crate::TransportParams, is_server: bool,
    ) -> Result<()> {
        let mut raw_params = [0; 128];

        let raw_params =
            crate::TransportParams::encode(params, is_server, &mut raw_params)?;

        self.quic_transport_params = Some(raw_params.to_vec());
        Ok(())
    }

    pub fn quic_transport_params(&self) -> &[u8] {
        // peer/remote transport parameters
        if let Some(conn) = &self.connection {
            // when resuming a tls session returning the transport parameters
            // leads to errors as during decoding they are checked
            // against the new connection ids which are not yet
            // fully established and the previous connection ids would be present
            if self.is_in_early_data() {
                return &[];
            };

            return if let Some(params) = conn.quic_transport_parameters() {
                params
            } else {
                &[]
            };
        }

        debug_assert!(false, "connection not available {:?}", self.side);
        &[]
    }

    pub fn alpn_protocol(&self) -> &[u8] {
        if let Some(conn) = &self.connection {
            if let Some(alpns) = conn.alpn_protocol() {
                return alpns;
            }
        }

        &[]
    }

    pub fn server_name(&self) -> Option<&str> {
        self.connection.as_ref().and_then(|c| match c {
            Connection::Client(_) => None,
            Connection::Server(sc) => sc.server_name(),
        })
    }

    // peer/receive Crypto frame data
    pub fn provide_data(&mut self, _level: Level, buf: &[u8]) -> Result<()> {
        debug!(
            "provide_data side={:?} level={:?}",
            self.side, self.highest_level
        );

        let Some(conn) = &mut self.connection else {
            trace!("storing data as no connection present side={:?}", self.side);
            // A large ClientHello arrives as multiple ordered chunks; append
            // so the eventual `read_hs` sees the whole flight.
            match &mut self.provided_data {
                Some(data) => data.extend_from_slice(buf),
                None => self.provided_data = Some(buf.to_vec()),
            }
            return Ok(());
        };

        if let Err(e) = conn.read_hs(buf) {
            error!("failed to read handshake data: {:?} {:?}", self.side, e);

            // Defer the failure to the next `do_handshake()`, which owns the
            // ExData and records the TLS alert as the QUIC connection close
            // (0x0100 + alert), instead of letting the peer time out.
            self.pending_tls_error = Some(Self::connection_error(
                conn.alert(),
                e.to_string().as_bytes().to_vec(),
            ));
        }

        Ok(())
    }

    fn connection_error(
        alert: Option<rustls::AlertDescription>, reason: Vec<u8>,
    ) -> ConnectionError {
        let error_code = match alert {
            Some(alert) => TLS_ALERT_ERROR + u64::from(u8::from(alert)),
            None => INTERNAL_ERROR,
        };

        ConnectionError {
            is_app: false,
            error_code,
            reason,
        }
    }

    // local/send Crypto frame data
    pub fn do_handshake(&mut self, ex_data: &mut ExData) -> Result<()> {
        if let Some(tls_error) = self.pending_tls_error.take() {
            if ex_data.local_error.is_none() {
                *ex_data.local_error = Some(tls_error);
            }
            return Err(Error::TlsFail);
        }

        if self.connection.is_none() {
            debug!("no connection present side={:?}", self.side);

            let Some(params) = self.quic_transport_params.clone() else {
                error!("missing transport parameters {:?}", self.side);
                return Err(Error::TlsFail);
            };

            match self.side {
                Side::Client => {
                    let hostname = match (
                        self.hostname.clone(),
                        self.enable_verify_ca_certificates,
                    ) {
                        (Some(hostname), _) => hostname,
                        // No SNI with verification disabled matches the
                        // BoringSSL backend's connect(None) behavior; rustls
                        // requires SOME ServerName, so use a placeholder.
                        (None, false) => ServerName::try_from("no.sni.invalid")
                            .expect("static placeholder name parses")
                            .to_owned(),
                        (None, true) => {
                            error!(
                                "a verifying client connection needs a server \
                                 name; pass one to connect()"
                            );
                            return Err(Error::TlsFail);
                        },
                    };

                    // NOTE: generates ClientHello
                    let client_conn = ClientConnection::new(
                        self.client_config.clone(),
                        self.quic_version,
                        hostname.to_owned(),
                        params,
                    )
                    .map_err(|e| {
                        error!("failed to create client config {}", e);
                        Error::TlsFail
                    })?;

                    self.connection = Some(client_conn.into())
                },
                Side::Server => {
                    let Some(server_config) = self.server_config.clone() else {
                        error!("server config not present for server side");
                        return Err(Error::TlsFail);
                    };

                    if self.enable_verify_ca_certificates {
                        warn!("verify_peer: enabled but no CA store for mTLS verification configured.");
                    }

                    let mut server_conn = ServerConnection::new(
                        server_config,
                        self.quic_version,
                        params.clone(),
                    )
                    .map_err(|e| {
                        error!("failed to create server connection {}", e);
                        Error::TlsFail
                    })?;

                    if let Some(crypto_data) = self.provided_data.take() {
                        match server_conn.read_hs(&crypto_data) {
                            Ok(()) => { /* continue */ },
                            Err(e) => {
                                if ex_data.local_error.is_none() {
                                    *ex_data.local_error =
                                        Some(Self::connection_error(
                                            server_conn.alert(),
                                            e.to_string().as_bytes().to_vec(),
                                        ));
                                };
                                error!("failed to read handshake data: {:?}", e);
                                return Err(Error::TlsFail);
                            },
                        }
                    }

                    self.connection = Some(server_conn.into());
                },
            }
        };

        loop {
            let current_level = self.highest_level;

            let mut buf = Vec::new();
            let mut key_change =
                self.connection.as_mut().unwrap().write_hs(&mut buf);

            let mut level_upgraded = false;
            if let Some(key_change) = key_change.take() {
                level_upgraded = self.process_key_change(ex_data, key_change)?;
            }

            if !level_upgraded && self.one_rtt_keys_secrets.is_some() {
                let keys_secrets = self.one_rtt_keys_secrets.take().unwrap();
                self.handle_application_keys(ex_data, keys_secrets)?;
            }

            if buf.is_empty() {
                break;
            } else {
                self.write_crypto_stream(current_level, ex_data, buf.as_slice())?;
            }
        }

        let Some(conn) = self.connection.as_mut() else {
            return Err(Error::TlsFail);
        };

        if let Some(zero_rtt_keys) = conn.zero_rtt_keys() {
            // rustls keeps reporting the 0-RTT keys while they remain valid,
            // so install them only once, and never move the level BACKWARDS:
            // a server sits past Initial by the time it sees them, and a
            // resumed client moves on to Handshake while they are still
            // reported.
            let space = &mut ex_data.crypto_ctx[packet::Epoch::Application];
            match self.side {
                Side::Client =>
                    if space.crypto_seal.is_none() {
                        space.crypto_seal = Some(Seal::from(zero_rtt_keys));
                    },
                Side::Server =>
                    if space.crypto_0rtt_open.is_none() {
                        space.crypto_0rtt_open = Some(Open::from(zero_rtt_keys));
                    },
            }

            if self.highest_level == Level::Initial {
                self.highest_level = Level::ZeroRTT;
            }
        }

        trace!(
            "handshake status side={:?}, kind={:?}, ongoing={:?}, alpn={:?}",
            self.side,
            conn.handshake_kind(),
            conn.is_handshaking(),
            match conn.alpn_protocol() {
                None => "",
                Some(alpn) => {
                    str::from_utf8(alpn).unwrap()
                },
            }
        );

        // setting a session value to allow for tls resumption / zero-rtt
        if matches!(self.side, Side::Client) &&
            !conn.is_handshaking() &&
            ex_data.session.is_none()
        {
            // The blob is [len | backend session | len | peer params]: lib.rs
            // decodes the second element itself and hands the first back to
            // set_session() opaquely. rustls keeps the actual resumption
            // state in the Context's in-memory store, so the backend element
            // is empty.
            let mut session = Vec::new();

            session.extend_from_slice(&0u64.to_be_bytes());

            let peer_params = self.quic_transport_params();
            let peer_params_len: [u8; 8] =
                (peer_params.len() as u64).to_be_bytes();
            session.extend_from_slice(&peer_params_len);
            session.extend_from_slice(peer_params);

            *ex_data.session = Some(session);
        }

        Ok(())
    }

    fn process_key_change(
        &mut self, ex_data: &mut ExData, key_change: KeyChange,
    ) -> Result<bool> {
        match key_change {
            KeyChange::Handshake { keys } => match self.highest_level {
                // A client that sent 0-RTT data sits at ZeroRTT when the
                // ServerHello arrives; everyone else at Initial.
                Level::Initial | Level::ZeroRTT => {
                    let next_space =
                        &mut ex_data.crypto_ctx[packet::Epoch::Handshake];

                    if next_space.crypto_seal.is_some() ||
                        next_space.crypto_open.is_some()
                    {
                        debug_assert!(
                            false,
                            "keys are already present for Handshake"
                        );
                    };

                    let (open, seal) = key_material_from_keys(keys, None)?;
                    next_space.crypto_open = Some(open);
                    next_space.crypto_seal = Some(seal);

                    self.highest_level = Level::Handshake;
                    Ok(true)
                },
                Level::Handshake | Level::OneRTT => {
                    error!(
                        "unexpected handshake key change at level {:?}",
                        self.highest_level
                    );
                    Err(Error::TlsFail)
                },
            },

            KeyChange::OneRtt { keys, next } =>
                self.handle_application_keys(ex_data, (keys, next)),
        }
    }

    fn handle_application_keys(
        &mut self, ex_data: &mut ExData, keys_secrets: (Keys, Secrets),
    ) -> Result<bool> {
        self.highest_level = Level::OneRTT;

        if !self.is_completed() {
            // avoid accepts of 1 RTT data before handshake is finished
            // temporarily storing keys/secrets in handshake
            // populate in space once handshake is compeleted
            self.one_rtt_keys_secrets = Some((keys_secrets.0, keys_secrets.1));

            Ok(false)
        } else {
            let next_space = &mut ex_data.crypto_ctx[packet::Epoch::Application];

            let (open, seal) =
                key_material_from_keys(keys_secrets.0, Some(keys_secrets.1))?;
            next_space.crypto_open = Some(open);
            next_space.crypto_seal = Some(seal);

            Ok(true)
        }
    }

    fn write_crypto_stream(
        &self, level: Level, ex_data: &mut ExData, data: &[u8],
    ) -> Result<()> {
        let pkt_num_space = match level {
            Level::Initial => &mut ex_data.crypto_ctx[packet::Epoch::Initial],
            Level::ZeroRTT => {
                error!("TLS wrote crypto data at the 0-RTT level");
                return Err(Error::TlsFail);
            },
            Level::Handshake => &mut ex_data.crypto_ctx[packet::Epoch::Handshake],
            Level::OneRTT => &mut ex_data.crypto_ctx[packet::Epoch::Application],
        };

        pkt_num_space.crypto_stream.send.write(data, false)?;

        debug!(
            "handshake crypto data written side={:?}, level={:?}, sent={}",
            self.side,
            self.highest_level,
            data.len()
        );
        Ok(())
    }

    pub fn process_post_handshake(
        &mut self, _ex_data: &mut ExData,
    ) -> Result<()> {
        // no-op
        Ok(())
    }

    pub fn write_level(&self) -> Level {
        // lib.rs expects the BoringSSL write levels, which never report
        // ZeroRTT: a client holding 0-RTT keys still writes its CRYPTO data
        // at the Initial level.
        match self.highest_level {
            Level::ZeroRTT => Level::Initial,
            level => level,
        }
    }

    pub fn cipher(&self) -> Option<Algorithm> {
        let suite = self
            .connection
            .as_ref()
            .and_then(|c| c.negotiated_cipher_suite());
        let suite = suite?;

        match suite.suite() {
            CipherSuite::TLS13_AES_128_GCM_SHA256 => Some(Algorithm::AES128_GCM),
            CipherSuite::TLS13_AES_256_GCM_SHA384 => Some(Algorithm::AES256_GCM),
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 =>
                Some(Algorithm::ChaCha20_Poly1305),
            _ => None,
        }
    }

    pub fn is_completed(&self) -> bool {
        if let Some(conn) = &self.connection {
            return !conn.is_handshaking();
        }

        false
    }

    pub fn is_resumed(&self) -> bool {
        if let Some(conn) = &self.connection {
            if let Some(kind) = conn.handshake_kind() {
                return matches!(kind, HandshakeKind::Resumed);
            }
        }

        false
    }

    pub fn clear(&mut self) -> Result<()> {
        self.connection = None;
        Ok(())
    }

    pub fn set_session(&mut self, _session: &[u8]) -> Result<()> {
        match self.side {
            // The TLS resumption state lives in the Context's in-memory
            // store, so there is nothing to restore into rustls here (which
            // also means a session cannot resume in a new process, unlike
            // BoringSSL's serialized SSL_SESSION). lib.rs restores the peer
            // transport parameters from the blob itself. The freshly encoded
            // LOCAL parameters are deliberately untouched: replacing them
            // with a previous connection's would resurrect its
            // initial_source_connection_id and the server would reject the
            // resumed handshake.
            Side::Client => Ok(()),
            Side::Server => {
                error!("set session is a client only operation");
                Err(Error::TlsFail)
            },
        }
    }

    pub fn curve(&self) -> Option<String> {
        let Some(conn) = &self.connection else {
            return None;
        };

        let kx_group = conn.negotiated_key_exchange_group()?;

        Some(format!("{:?}", kx_group.name()))
    }

    pub fn sigalg(&self) -> Option<String> {
        // this information is not available through the connection
        // only handled internally within rustls during handshake
        // loggable with level trace
        None
    }

    pub fn peer_cert_chain(&self) -> Option<Vec<&[u8]>> {
        let Some(conn) = &self.connection else {
            return None;
        };

        if let Some(certs) = conn.peer_certificates() {
            let out: Vec<&[u8]> = certs.iter().map(|c| c.as_ref()).collect();
            if !out.is_empty() {
                Some(out)
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn peer_cert(&self) -> Option<&[u8]> {
        let Some(conn) = &self.connection else {
            return None;
        };

        if let Some(certs) = conn.peer_certificates() {
            certs.first().map(|c| c.as_ref())
        } else {
            None
        }
    }

    pub fn early_data_reason(&self) -> u32 {
        // rustls does not expose an equivalent of BoringSSL's
        // ssl_early_data_reason_t; 0 is ssl_early_data_unknown.
        0
    }

    pub fn is_in_early_data(&self) -> bool {
        let Some(conn) = &self.connection else {
            return false;
        };
        conn.zero_rtt_keys().is_some()
    }
}
