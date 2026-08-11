//! Host-side support for DNS-anchored identity keys: fetching a DNSSEC proof that a human-readable
//! name publishes an identity key, and attaching it to a PSBT.
//!
//! See `docs/dns-identity.md` for the specification.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};

use bitcoin::Psbt;
use common::dns_identity::{
    hrn_to_dns_name, parse_idkey_param, select_bitcoin_uri, verify_dnssec_identity_key,
    MAX_DNSSEC_CHAIN_LEN,
};
use common::psbt::{DnssecIdentityKey, PsbtIdAuthGlobalWrite};
use dnssec_prover::query::{ProofBuilder, QueryBuf};
use dnssec_prover::rr::{Name, TXT_TYPE, RR};
use dnssec_prover::ser::parse_rr_stream;
use dnssec_prover::validation::verify_rr_stream;

#[derive(Debug)]
pub enum DnsIdentityError {
    /// The name is not a valid ASCII `user@domain`.
    InvalidName,
    /// The resolver could not be reached, or returned an unusable answer.
    QueryFailed,
    /// The proof does not validate, or the record does not publish an identity key.
    ProofInvalid,
    /// The chain is larger than the device is willing to validate.
    ProofTooLarge(usize),
}

impl std::fmt::Display for DnsIdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsIdentityError::InvalidName => {
                write!(f, "name is not a valid ASCII user@domain")
            }
            DnsIdentityError::QueryFailed => write!(f, "failed to build a DNSSEC proof"),
            DnsIdentityError::ProofInvalid => {
                write!(f, "the DNSSEC proof does not validate, or the record publishes no idkey")
            }
            DnsIdentityError::ProofTooLarge(len) => write!(
                f,
                "the DNSSEC proof is {} bytes, more than the {} the device accepts",
                len, MAX_DNSSEC_CHAIN_LEN
            ),
        }
    }
}

impl std::error::Error for DnsIdentityError {}

/// A DNSSEC proof that `hrn` publishes `pubkey`.
pub struct DnsIdentityProof {
    /// The human-readable name, without any `₿` prefix.
    pub hrn: String,
    /// The identity public key the name publishes.
    pub pubkey: [u8; 33],
    /// The RFC 9102 authentication chain.
    pub chain: Vec<u8>,
    /// The lowest TTL in the chain: the proof should not be cached for longer than this.
    pub ttl: u32,
}

/// Builds an RFC 9102 proof for the TXT records at `name`.
///
/// `dnssec_prover::query::build_txt_proof` does this too, but pipelines every query over a single
/// TCP connection. RFC 7766 requires resolvers to support that, yet transparent DNS proxies
/// commonly answer the first query on a connection and then close it, which makes the pipelined
/// version fail outright on such networks. Driving `ProofBuilder` with one connection per query
/// costs a few more round trips and works either way.
pub fn build_txt_proof_sequentially(
    resolver: SocketAddr,
    name: &Name,
) -> Result<(Vec<u8>, u32), DnsIdentityError> {
    fn query_once(resolver: SocketAddr, query: &QueryBuf) -> Result<QueryBuf, DnsIdentityError> {
        let mut stream =
            TcpStream::connect(resolver).map_err(|_| DnsIdentityError::QueryFailed)?;
        stream
            .write_all(&(query.len() as u16).to_be_bytes())
            .and_then(|()| stream.write_all(query))
            .map_err(|_| DnsIdentityError::QueryFailed)?;

        let mut len_bytes = [0u8; 2];
        stream
            .read_exact(&mut len_bytes)
            .map_err(|_| DnsIdentityError::QueryFailed)?;
        let mut resp = QueryBuf::new_zeroed(u16::from_be_bytes(len_bytes));
        stream
            .read_exact(&mut resp)
            .map_err(|_| DnsIdentityError::QueryFailed)?;
        Ok(resp)
    }

    let (mut builder, initial_query) = ProofBuilder::new(name, TXT_TYPE);
    let mut pending = vec![initial_query];
    while builder.awaiting_responses() {
        let Some(query) = pending.pop() else {
            // The builder still expects responses but we have nothing left to ask.
            return Err(DnsIdentityError::QueryFailed);
        };
        let resp = query_once(resolver, &query)?;
        let new_queries = builder
            .process_response(&resp)
            .map_err(|_| DnsIdentityError::QueryFailed)?;
        pending.extend(new_queries);
    }
    builder.finish_proof().map_err(|()| DnsIdentityError::QueryFailed)
}

/// Builds a proof that `hrn` publishes an identity key, by querying a recursive resolver.
///
/// The proof is validated locally before being returned, so that a host never hands the device a
/// chain it could have known was broken. Note that the resolver is *not* trusted: the proof is
/// self-contained and the device validates it again for itself.
pub fn fetch_identity_proof(
    resolver: SocketAddr,
    hrn: &str,
) -> Result<DnsIdentityProof, DnsIdentityError> {
    let dns_name = hrn_to_dns_name(hrn).map_err(|_| DnsIdentityError::InvalidName)?;

    let (chain, ttl) = build_txt_proof_sequentially(resolver, &dns_name)?;

    if chain.len() > MAX_DNSSEC_CHAIN_LEN {
        return Err(DnsIdentityError::ProofTooLarge(chain.len()));
    }

    // Read the key out of the proof, then check the whole thing the same way the device will.
    let rrs = parse_rr_stream(&chain).map_err(|_| DnsIdentityError::ProofInvalid)?;
    let verified = verify_rr_stream(&rrs).map_err(|_| DnsIdentityError::ProofInvalid)?;
    let uri = select_bitcoin_uri(
        verified
            .resolve_name(&dns_name)
            .into_iter()
            .filter_map(|rr| match rr {
                RR::Txt(txt) => Some(txt),
                _ => None,
            }),
    )
    .map_err(|_| DnsIdentityError::ProofInvalid)?;
    let pubkey = parse_idkey_param(&uri).map_err(|_| DnsIdentityError::ProofInvalid)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    verify_dnssec_identity_key(hrn, &chain, &pubkey, now)
        .map_err(|_| DnsIdentityError::ProofInvalid)?;

    Ok(DnsIdentityProof {
        hrn: hrn.to_string(),
        pubkey,
        chain,
        ttl,
    })
}

/// Attaches a proof to a PSBT, so that the device can label outputs authenticated by that key.
///
/// The per-output identity signatures are a separate matter: they come from the payee, over
/// whichever channel delivered the address.
pub fn add_identity_proof_to_psbt(
    psbt: &mut Psbt,
    proof: &DnsIdentityProof,
) -> Result<(), DnsIdentityError> {
    psbt.add_dnssec_identity_key(&DnssecIdentityKey {
        pubkey: proof.pubkey,
        name: &proof.hrn,
        chain: &proof.chain,
    })
    .map_err(|_| DnsIdentityError::ProofInvalid)
}
