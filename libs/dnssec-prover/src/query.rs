//! This module exposes utilities for building DNSSEC proofs by directly querying a recursive
//! resolver.

use core::{cmp, ops};
use alloc::vec;
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::net::{SocketAddr, TcpStream};
#[cfg(feature = "std")]
use std::io::{Read, Write, Error, ErrorKind};

#[cfg(feature = "tokio")]
use tokio_crate::net::TcpStream as TokioTcpStream;
#[cfg(feature = "tokio")]
use tokio_crate::io::{AsyncReadExt, AsyncWriteExt};

use crate::rr::*;
use crate::ser::*;
use crate::MAX_PROOF_STEPS;

// In testing use a rather small buffer to ensure we hit the allocation paths sometimes. In
// production, we should generally never actually need to go to heap as DNS messages are rarely
// larger than a KiB or two.
#[cfg(any(test, fuzzing))]
const STACK_BUF_LIMIT: u16 = 32;
#[cfg(not(any(test, fuzzing)))]
const STACK_BUF_LIMIT: u16 = 2048;

/// A buffer for storing queries and responses.
#[derive(Clone, PartialEq, Eq)]
pub struct QueryBuf {
	buf: [u8; STACK_BUF_LIMIT as usize],
	heap_buf: Vec<u8>,
	len: u16,
}
impl QueryBuf {
	/// Generates a new buffer of the given length, consisting of all zeros.
	pub fn new_zeroed(len: u16) -> Self {
		let heap_buf = if len > STACK_BUF_LIMIT { vec![0; len as usize] } else { Vec::new() };
		Self {
			buf: [0; STACK_BUF_LIMIT as usize],
			heap_buf,
			len
		}
	}
	/// Extends the size of this buffer by appending the given slice.
	///
	/// If the total length of this buffer exceeds [`u16::MAX`] after appending, the buffer's state
	/// is undefined, however pushing data beyond [`u16::MAX`] will not panic.
	pub fn extend_from_slice(&mut self, sl: &[u8]) {
		let new_len = self.len.saturating_add(sl.len() as u16);
		let was_heap = self.len > STACK_BUF_LIMIT;
		let is_heap = new_len > STACK_BUF_LIMIT;
		if was_heap != is_heap {
			self.heap_buf = vec![0; new_len as usize];
			self.heap_buf[..self.len as usize].copy_from_slice(&self.buf[..self.len as usize]);
		}
		let target = if is_heap {
			self.heap_buf.resize(new_len as usize, 0);
			&mut self.heap_buf[self.len as usize..]
		} else {
			&mut self.buf[self.len as usize..new_len as usize]
		};
		target.copy_from_slice(sl);
		self.len = new_len;
	}
	/// Converts this query into its bytes on the heap
	pub fn into_vec(self) -> Vec<u8> {
		if self.len > STACK_BUF_LIMIT {
			self.heap_buf
		} else {
			self.buf[..self.len as usize].to_vec()
		}
	}
}
impl ops::Deref for QueryBuf {
	type Target = [u8];
	fn deref(&self) -> &[u8] {
		if self.len > STACK_BUF_LIMIT {
			&self.heap_buf
		} else {
			&self.buf[..self.len as usize]
		}
	}
}
impl ops::DerefMut for QueryBuf {
	fn deref_mut(&mut self) -> &mut [u8] {
		if self.len > STACK_BUF_LIMIT {
			&mut self.heap_buf
		} else {
			&mut self.buf[..self.len as usize]
		}
	}
}

// We don't care about transaction IDs as we're only going to accept signed data.
// Further, if we're querying over DoH, the RFC says we SHOULD use a transaction ID of 0 here.
const TXID: u16 = 0;

fn build_query(domain: &Name, ty: u16) -> QueryBuf {
	let mut query = QueryBuf::new_zeroed(0);
	query.extend_from_slice(&TXID.to_be_bytes());
	query.extend_from_slice(&[0x01, 0x20]); // Flags: Recursive, Authenticated Data
	query.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 1]); // One question, One additional
	write_name(&mut query, domain);
	query.extend_from_slice(&ty.to_be_bytes());
	query.extend_from_slice(&1u16.to_be_bytes()); // INternet class
	query.extend_from_slice(&[0, 0, 0x29]); // . OPT
	query.extend_from_slice(&0u16.to_be_bytes()); // 0 UDP payload size
	query.extend_from_slice(&[0, 0]); // EDNS version 0
	query.extend_from_slice(&0x8000u16.to_be_bytes()); // Accept DNSSEC RRs
	query.extend_from_slice(&0u16.to_be_bytes()); // No additional data
	query
}

/// Possible errors when building queries. Note that there are many possible errors, but only a
/// handful of common ones are captured in the variants here.
// Note that this is also duplicated in uniffi in the udl
#[derive(PartialEq, Eq)]
pub enum ProofBuildingError {
	/// The server provided an invalid response.
	///
	/// We failed to parse the server's response or it contained nonsense that we couldn't
	/// understand.
	InvalidResponse,
	/// The server we are querying gave us a response code of SERVFAIL or FORMERR.
	///
	/// This generally indicates it failed to connect to some DNS server required to resolve our
	/// queries or it couldn't understand the response it got back from such a server.
	ServerFailure,
	/// The server we are querying gave us a response code of NXDOMAIN on our very first query.
	///
	/// This indicates the name being queried for does not exist.
	NoSuchName,
	/// The server we are querying gave us a response code of NXDOMAIN.
	///
	/// This indicates the server couldn't find an answer to one of our queries.
	MissingRecord,
	/// The server responded indicating it could not authenticate the response using DNSSEC.
	///
	/// This generally indicates that the data we are querying for was not DNSSEC-signed.
	/// It could also indicate that the server we are trying to query using does not validate
	/// DNSSEC.
	Unauthenticated,
	/// A query was provided when no query was expected.
	///
	/// This indicates a bug in the code driving the proof builder, rather than an issue with the
	/// DNS.
	NoResponseExpected,
}

impl core::fmt::Display for ProofBuildingError {
	fn fmt(&self, fmt: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
		match self {
			ProofBuildingError::InvalidResponse =>
				fmt.write_str("The server provided a response we could not understand"),
			ProofBuildingError::ServerFailure =>
				fmt.write_str("The server indicated it failed to talk to a required authorative DNS server"),
			ProofBuildingError::NoSuchName =>
				fmt.write_str("The server indicated the requested hostname does not exist"),
			ProofBuildingError::MissingRecord =>
				fmt.write_str("The server indicated one of the records we needed to build our proof did not exist"),
			ProofBuildingError::Unauthenticated =>
				fmt.write_str("The server indicated the records we needed were not DNSSEC-authenticated"),
			ProofBuildingError::NoResponseExpected =>
				fmt.write_str("Internal error in the proof building software"),
		}
	}
}

impl core::fmt::Debug for ProofBuildingError {
	fn fmt(&self, fmt: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
		core::fmt::Display::fmt(self, fmt)
	}
}

#[cfg(feature = "std")]
impl std::error::Error for ProofBuildingError {

}

#[cfg(dnssec_prover_fuzzing)]
/// Read some input and parse it as if it came from a server, for fuzzing.
pub fn fuzz_response(response: &[u8]) {
	let (mut proof, mut names) = (Vec::new(), Vec::new());
	let _ = handle_response(response, &mut proof, &mut names);
}

/// Handle a response, returning the minimum TTL of any answer.
///
/// Note that the caller must map errors of [`ProofBuildingError::MissingRecord`] to
/// [`ProofBuildingError::NoSuchName`] if this was the first query!
fn handle_response(resp: &[u8], proof: &mut Vec<u8>, rrsig_key_names: &mut Vec<Name>) -> Result<u32, ProofBuildingError> {
	let mut read: &[u8] = resp;
	let resp_txid = read_u16(&mut read).map_err(|()| ProofBuildingError::InvalidResponse)?;
	if resp_txid != TXID { return Err(ProofBuildingError::InvalidResponse); }
	// 2 byte transaction ID
	let flags = read_u16(&mut read).map_err(|()| ProofBuildingError::InvalidResponse)?;
	if flags & 0b1000_0000_0000_0000 == 0 {
		// This message is tagged as a query, not a response?
		return Err(ProofBuildingError::InvalidResponse);
	}
	if flags & 0b1111 == 2 || flags & 0b1111 == 1 {
		return Err(ProofBuildingError::ServerFailure);
	}
	if flags & 0b1111 == 3 {
		// NXDOMAIN, note that the caller should map this to NoSuchName if applicable.
		return Err(ProofBuildingError::MissingRecord);
	}
	// Check that OPCODE, Truncation, and RCODE are all 0s
	if flags & 0b0111_1010_0000_1111 != 0 {
		return Err(ProofBuildingError::InvalidResponse);
	}
	if flags & 0b10_0000 == 0 {
		// The AD bit was unset
		return Err(ProofBuildingError::Unauthenticated);
	}
	let questions = read_u16(&mut read).map_err(|()| ProofBuildingError::InvalidResponse)?;
	if questions != 1 { return Err(ProofBuildingError::InvalidResponse); }
	let answers = read_u16(&mut read).map_err(|()| ProofBuildingError::InvalidResponse)?;
	if answers == 0 { return Err(ProofBuildingError::InvalidResponse); }
	let authorities = read_u16(&mut read).map_err(|()| ProofBuildingError::InvalidResponse)?;
	let _additional = read_u16(&mut read).map_err(|()| ProofBuildingError::InvalidResponse)?;

	for _ in 0..questions {
		read_wire_packet_name(&mut read, resp).map_err(|()| ProofBuildingError::InvalidResponse)?;
		read_u16(&mut read).map_err(|()| ProofBuildingError::InvalidResponse)?; // type
		read_u16(&mut read).map_err(|()| ProofBuildingError::InvalidResponse)?; // class
	}

	// Only read the answers and NSEC records in authorities, skipping additional entirely.
	let mut min_ttl = u32::MAX;
	for _ in 0..answers {
		let (rr, ttl) = parse_wire_packet_rr(&mut read, resp)
			.map_err(|()| ProofBuildingError::InvalidResponse)?;
		write_rr(&rr, ttl, proof);
		min_ttl = cmp::min(min_ttl, ttl);
		if let RR::RRSig(rrsig) = rr { rrsig_key_names.push(rrsig.key_name); }
	}

	for _ in 0..authorities {
		// Only include records from the authority section if they are NSEC/3 (or signatures
		// thereover). We don't care about NS records here.
		let (rr, ttl) = parse_wire_packet_rr(&mut read, resp)
			.map_err(|()| ProofBuildingError::InvalidResponse)?;
		match &rr {
			RR::RRSig(rrsig) => {
				if rrsig.ty != NSec::TYPE && rrsig.ty != NSec3::TYPE {
					continue;
				}
			},
			RR::NSec(_)|RR::NSec3(_) => {},
			_ => continue,
		}
		write_rr(&rr, ttl, proof);
		min_ttl = cmp::min(min_ttl, ttl);
		if let RR::RRSig(rrsig) = rr { rrsig_key_names.push(rrsig.key_name); }
	}

	Ok(min_ttl)
}

#[cfg(dnssec_prover_fuzzing)]
/// Read a stream of responses and handle them it as if they came from a server, for fuzzing.
pub fn fuzz_proof_builder(mut response_stream: &[u8]) {
	let (mut builder, _) = ProofBuilder::new(&"example.com.".try_into().unwrap(), Txt::TYPE);
	while builder.awaiting_responses() {
		let len = if let Ok(len) = read_u16(&mut response_stream) { len } else { return };
		let mut buf = QueryBuf::new_zeroed(len);
		if response_stream.len() < len as usize { return; }
		buf.copy_from_slice(&response_stream[..len as usize]);
		response_stream = &response_stream[len as usize..];
		let _ = builder.process_response(&buf);
	}
	let _ = builder.finish_proof();
}

/// A simple state machine which will generate a series of queries and process the responses until
/// it has built a DNSSEC proof.
///
/// A [`ProofBuilder`] driver starts with [`ProofBuilder::new`], fetching the state machine and
/// initial query. As long as [`ProofBuilder::awaiting_responses`] returns true, responses should
/// be read from the resolver. For each query response read from the DNS resolver,
/// [`ProofBuilder::process_response`] should be called, and each fresh query returned should be
/// sent to the resolver. Once [`ProofBuilder::awaiting_responses`] returns false,
/// [`ProofBuilder::finish_proof`] should be called to fetch the resulting proof.
///
/// To build a DNSSEC proof using a DoH server, take each [`QueryBuf`], encode it as base64url, and
/// make a query to `https://doh-server/endpoint?dns=base64url_encoded_query` with an `Accept`
/// header of `application/dns-message`. Each response, in raw binary, can be fed directly into
/// [`ProofBuilder::process_response`].
#[derive(Clone)]
pub struct ProofBuilder {
	proof: Vec<u8>,
	min_ttl: u32,
	dnskeys_requested: Vec<Name>,
	pending_queries: usize,
	queries_made: usize,
}

impl ProofBuilder {
	/// Constructs a new [`ProofBuilder`] and an initial query to send to the recursive resolver to
	/// begin the proof building process.
	///
	/// Given a correctly-functioning resolver the proof will ultimately be able to prove the
	/// contents of any records with the given `ty`pe at the given `name` (as long as the given
	/// `ty`pe is supported by this library).
	///
	/// You can find constants for supported standard types in the [`crate::rr`] module.
	pub fn new(name: &Name, ty: u16) -> (ProofBuilder, QueryBuf) {
		let initial_query = build_query(name, ty);
		(ProofBuilder {
			proof: Vec::new(),
			min_ttl: u32::MAX,
			dnskeys_requested: Vec::with_capacity(MAX_PROOF_STEPS),
			pending_queries: 1,
			queries_made: 1,
		}, initial_query)
	}

	/// Returns true as long as further responses are expected from the resolver.
	///
	/// As long as this returns true, responses should be read from the resolver and passed to
	/// [`Self::process_response`]. Once this returns false, [`Self::finish_proof`] should be used
	/// to (possibly) get the final proof.
	pub fn awaiting_responses(&self) -> bool {
		self.pending_queries > 0 && self.queries_made <= MAX_PROOF_STEPS
	}

	/// Processes a query response from the recursive resolver, returning a list of new queries to
	/// send to the resolver.
	pub fn process_response(&mut self, resp: &QueryBuf) -> Result<Vec<QueryBuf>, ProofBuildingError> {
		if self.pending_queries == 0 { return Err(ProofBuildingError::NoResponseExpected); }

		let mut rrsig_key_names = Vec::new();
		let min_ttl = match handle_response(resp, &mut self.proof, &mut rrsig_key_names) {
			Ok(min_ttl) => min_ttl,
			Err(err) => {
				if self.proof.is_empty() && err == ProofBuildingError::MissingRecord {
					return Err(ProofBuildingError::NoSuchName);
				} else {
					return Err(err);
				}
			},
		};
		self.min_ttl = cmp::min(self.min_ttl, min_ttl);
		self.pending_queries -= 1;

		rrsig_key_names.sort_unstable();
		rrsig_key_names.dedup();

		let mut new_queries = Vec::with_capacity(2);
		for key_name in rrsig_key_names.drain(..) {
			if !self.dnskeys_requested.contains(&key_name) {
				new_queries.push(build_query(&key_name, DnsKey::TYPE));
				self.pending_queries += 1;
				self.queries_made += 1;
				self.dnskeys_requested.push(key_name.clone());

				if key_name.as_str() != "." {
					new_queries.push(build_query(&key_name, DS::TYPE));
					self.pending_queries += 1;
					self.queries_made += 1;
				}
			}
		}
		if self.queries_made <= MAX_PROOF_STEPS {
			Ok(new_queries)
		} else {
			Ok(Vec::new())
		}
	}

	/// Finalizes the proof, if one is available, and returns it as well as the TTL that should be
	/// used to cache the proof (i.e. the lowest TTL of all records which were used to build the
	/// proof).
	///
	/// Only fails if too many queries have been made or there are still some pending queries.
	pub fn finish_proof(self) -> Result<(Vec<u8>, u32), ()> {
		if self.pending_queries > 0 || self.queries_made > MAX_PROOF_STEPS {
			Err(())
		} else {
			Ok((self.proof, self.min_ttl))
		}
	}
}

#[cfg(feature = "std")]
fn send_query(stream: &mut TcpStream, query: &[u8]) -> Result<(), Error> {
	stream.write_all(&(query.len() as u16).to_be_bytes())?;
	stream.write_all(&query)?;
	Ok(())
}

#[cfg(feature = "tokio")]
async fn send_query_async(stream: &mut TokioTcpStream, query: &[u8]) -> Result<(), Error> {
	stream.write_all(&(query.len() as u16).to_be_bytes()).await?;
	stream.write_all(&query).await?;
	Ok(())
}

#[cfg(feature = "std")]
fn read_response(stream: &mut TcpStream) -> Result<QueryBuf, Error> {
	let mut len_bytes = [0; 2];
	stream.read_exact(&mut len_bytes)?;
	let mut buf = QueryBuf::new_zeroed(u16::from_be_bytes(len_bytes));
	stream.read_exact(&mut buf)?;
	Ok(buf)
}

#[cfg(feature = "tokio")]
async fn read_response_async(stream: &mut TokioTcpStream) -> Result<QueryBuf, Error> {
	let mut len_bytes = [0; 2];
	stream.read_exact(&mut len_bytes).await?;
	let mut buf = QueryBuf::new_zeroed(u16::from_be_bytes(len_bytes));
	stream.read_exact(&mut buf).await?;
	Ok(buf)
}

#[cfg(feature = "std")]
macro_rules! build_proof_impl {
	($stream: ident, $send_query: ident, $read_response: ident, $domain: expr, $ty: expr $(, $async_ok: tt)?) => { {
		// We require the initial query to have already gone out, and assume our resolver will
		// return any CNAMEs all the way to the final record in the response. From there, we just
		// have to take any RRSIGs in the response and walk them up to the root. We do so
		// iteratively, sending DNSKEY and DS lookups after every response, deduplicating requests
		// using `dnskeys_requested`.
		let (mut builder, initial_query) = ProofBuilder::new($domain, $ty);
		$send_query(&mut $stream, &initial_query)
			$(.await?; $async_ok)??; // Either await?; Ok(())?, or just ?
		while builder.awaiting_responses() {
			let response = $read_response(&mut $stream)
				$(.await?; $async_ok)??; // Either await?; Ok(())?, or just ?
			let new_queries = builder.process_response(&response)
				.map_err(|err| Error::new(ErrorKind::Other, err))?;
			for query in new_queries {
				$send_query(&mut $stream, &query)
					$(.await?; $async_ok)??; // Either await?; Ok(())?, or just ?
			}
		}

		builder.finish_proof()
			.map_err(|()| Error::new(ErrorKind::Other, "Too many requests required"))
	} }
}

#[cfg(feature = "std")]
fn build_proof(resolver: SocketAddr, domain: &Name, ty: u16) -> Result<(Vec<u8>, u32), Error> {
	let mut stream = TcpStream::connect(resolver)?;
	build_proof_impl!(stream, send_query, read_response, domain, ty)
}

#[cfg(feature = "tokio")]
async fn build_proof_async(resolver: SocketAddr, domain: &Name, ty: u16) -> Result<(Vec<u8>, u32), Error> {
	let mut stream = TokioTcpStream::connect(resolver).await?;
	build_proof_impl!(stream, send_query_async, read_response_async, domain, ty, { Ok::<(), Error>(()) })
}

/// Builds a DNSSEC proof for an A record by querying a recursive resolver, returning the proof as
/// well as the TTL for the proof provided by the recursive resolver.
///
/// Note that this proof is NOT verified in any way, you need to use the [`crate::validation`]
/// module to validate the records contained.
#[cfg(feature = "std")]
pub fn build_a_proof(resolver: SocketAddr, domain: &Name) -> Result<(Vec<u8>, u32), Error> {
	build_proof(resolver, domain, A::TYPE)
}

/// Builds a DNSSEC proof for an AAAA record by querying a recursive resolver, returning the proof
/// as well as the TTL for the proof provided by the recursive resolver.
///
/// Note that this proof is NOT verified in any way, you need to use the [`crate::validation`]
/// module to validate the records contained.
#[cfg(feature = "std")]
pub fn build_aaaa_proof(resolver: SocketAddr, domain: &Name) -> Result<(Vec<u8>, u32), Error> {
	build_proof(resolver, domain, AAAA::TYPE)
}

/// Builds a DNSSEC proof for an TXT record by querying a recursive resolver, returning the proof
/// as well as the TTL for the proof provided by the recursive resolver.
///
/// Note that this proof is NOT verified in any way, you need to use the [`crate::validation`]
/// module to validate the records contained.
#[cfg(feature = "std")]
pub fn build_txt_proof(resolver: SocketAddr, domain: &Name) -> Result<(Vec<u8>, u32), Error> {
	build_proof(resolver, domain, Txt::TYPE)
}

/// Builds a DNSSEC proof for an TLSA record by querying a recursive resolver, returning the proof
/// as well as the TTL for the proof provided by the recursive resolver.
///
/// Note that this proof is NOT verified in any way, you need to use the [`crate::validation`]
/// module to validate the records contained.
#[cfg(feature = "std")]
pub fn build_tlsa_proof(resolver: SocketAddr, domain: &Name) -> Result<(Vec<u8>, u32), Error> {
	build_proof(resolver, domain, TLSA::TYPE)
}


/// Builds a DNSSEC proof for an A record by querying a recursive resolver, returning the proof as
/// well as the TTL for the proof provided by the recursive resolver.
///
/// Note that this proof is NOT verified in any way, you need to use the [`crate::validation`]
/// module to validate the records contained.
#[cfg(feature = "tokio")]
pub async fn build_a_proof_async(resolver: SocketAddr, domain: &Name) -> Result<(Vec<u8>, u32), Error> {
	build_proof_async(resolver, domain, A::TYPE).await
}

/// Builds a DNSSEC proof for an AAAA record by querying a recursive resolver, returning the proof
/// as well as the TTL for the proof provided by the recursive resolver.
///
/// Note that this proof is NOT verified in any way, you need to use the [`crate::validation`]
/// module to validate the records contained.
#[cfg(feature = "tokio")]
pub async fn build_aaaa_proof_async(resolver: SocketAddr, domain: &Name) -> Result<(Vec<u8>, u32), Error> {
	build_proof_async(resolver, domain, AAAA::TYPE).await
}

/// Builds a DNSSEC proof for an TXT record by querying a recursive resolver, returning the proof
/// as well as the TTL for the proof provided by the recursive resolver.
///
/// Note that this proof is NOT verified in any way, you need to use the [`crate::validation`]
/// module to validate the records contained.
#[cfg(feature = "tokio")]
pub async fn build_txt_proof_async(resolver: SocketAddr, domain: &Name) -> Result<(Vec<u8>, u32), Error> {
	build_proof_async(resolver, domain, Txt::TYPE).await
}

/// Builds a DNSSEC proof for an TLSA record by querying a recursive resolver, returning the proof
/// as well as the TTL for the proof provided by the recursive resolver.
///
/// Note that this proof is NOT verified in any way, you need to use the [`crate::validation`]
/// module to validate the records contained.
#[cfg(feature = "tokio")]
pub async fn build_tlsa_proof_async(resolver: SocketAddr, domain: &Name) -> Result<(Vec<u8>, u32), Error> {
	build_proof_async(resolver, domain, TLSA::TYPE).await
}

#[cfg(all(feature = "validation", feature = "std", test))]
mod tests {
	use super::*;
	use crate::validation::*;

	use rand::seq::SliceRandom;

	use std::net::ToSocketAddrs;
	use std::time::SystemTime;

	#[test]
	fn test_cloudflare_txt_query() {
		let sockaddr = "8.8.8.8:53".to_socket_addrs().unwrap().next().unwrap();
		let query_name = "cloudflare.com.".try_into().unwrap();
		let (proof, _) = build_txt_proof(sockaddr, &query_name).unwrap();

		let mut rrs = parse_rr_stream(&proof).unwrap();
		rrs.shuffle(&mut rand::rngs::OsRng);
		let verified_rrs = verify_rr_stream(&rrs).unwrap();
		assert!(verified_rrs.verified_rrs.len() > 1);

		let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
		assert!(verified_rrs.valid_from < now);
		assert!(verified_rrs.expires > now);
	}

	#[test]
	fn test_sha1_query() {
		let sockaddr = "8.8.8.8:53".to_socket_addrs().unwrap().next().unwrap();
		let query_name = "benthecarman.com.".try_into().unwrap();
		let (proof, _) = build_a_proof(sockaddr, &query_name).unwrap();

		let mut rrs = parse_rr_stream(&proof).unwrap();
		rrs.shuffle(&mut rand::rngs::OsRng);
		let verified_rrs = verify_rr_stream(&rrs).unwrap();
		assert!(verified_rrs.verified_rrs.len() >= 1);

		let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
		assert!(verified_rrs.valid_from < now);
		assert!(verified_rrs.expires > now);
	}

	#[test]
	fn test_txt_query() {
		let sockaddr = "8.8.8.8:53".to_socket_addrs().unwrap().next().unwrap();
		let query_name = "matt.user._bitcoin-payment.mattcorallo.com.".try_into().unwrap();
		let (proof, _) = build_txt_proof(sockaddr, &query_name).unwrap();

		let mut rrs = parse_rr_stream(&proof).unwrap();
		rrs.shuffle(&mut rand::rngs::OsRng);
		let verified_rrs = verify_rr_stream(&rrs).unwrap();
		assert_eq!(verified_rrs.verified_rrs.len(), 2);
		assert_eq!(verified_rrs.verified_rrs.iter().filter(|rr| {
			const PFX: &'static str = "bitcoin:";
			if let RR::Txt(txt) = &rr {
				txt.data.iter()
					.take(PFX.len())
					.filter_map(|b| char::from_u32(b.into()))
					.map(|c| c.to_ascii_lowercase())
					.eq(PFX.chars())
			} else { false }
		}).count(), 1);

		let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
		assert!(verified_rrs.valid_from < now);
		assert!(verified_rrs.expires > now);
	}

	#[test]
	fn test_cname_query() {
		for resolver in ["1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"] {
			let sockaddr = resolver.to_socket_addrs().unwrap().next().unwrap();
			let query_name = "cname_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap();
			let (proof, _) = build_txt_proof(sockaddr, &query_name).unwrap();

			let mut rrs = parse_rr_stream(&proof).unwrap();
			rrs.shuffle(&mut rand::rngs::OsRng);
			let verified_rrs = verify_rr_stream(&rrs).unwrap();
			assert_eq!(verified_rrs.verified_rrs.len(), 2);

			let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
			assert!(verified_rrs.valid_from < now);
			assert!(verified_rrs.expires > now);

			let resolved_rrs = verified_rrs.resolve_name(&query_name);
			assert_eq!(resolved_rrs.len(), 1);
			if let RR::Txt(txt) = &resolved_rrs[0] {
				assert_eq!(txt.name.as_str(), "txt_test.dnssec_proof_tests.bitcoin.ninja.");
				assert_eq!(txt.data.as_vec(), b"dnssec_prover_test");
			} else { panic!(); }
		}
	}

	#[cfg(feature = "tokio")]
	use tokio_crate as tokio;

	#[cfg(feature = "tokio")]
	#[tokio::test]
	async fn test_txt_query_async() {
		let sockaddr = "8.8.8.8:53".to_socket_addrs().unwrap().next().unwrap();
		let query_name = "matt.user._bitcoin-payment.mattcorallo.com.".try_into().unwrap();
		let (proof, _) = build_txt_proof_async(sockaddr, &query_name).await.unwrap();

		let mut rrs = parse_rr_stream(&proof).unwrap();
		rrs.shuffle(&mut rand::rngs::OsRng);
		let verified_rrs = verify_rr_stream(&rrs).unwrap();
		assert_eq!(verified_rrs.verified_rrs.len(), 2);
		assert_eq!(verified_rrs.verified_rrs.iter().filter(|rr| {
			const PFX: &'static str = "bitcoin:";
			if let RR::Txt(txt) = &rr {
				txt.data.iter()
					.take(PFX.len())
					.filter_map(|b| char::from_u32(b.into()))
					.map(|c| c.to_ascii_lowercase())
					.eq(PFX.chars())
			} else { false }
		}).count(), 1);

		let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
		assert!(verified_rrs.valid_from < now);
		assert!(verified_rrs.expires > now);
	}

	#[cfg(feature = "tokio")]
	#[tokio::test]
	async fn test_cross_domain_cname_query_async() {
		for resolver in ["1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"] {
			let sockaddr = resolver.to_socket_addrs().unwrap().next().unwrap();
			let query_name = "wildcard.x_domain_cname_wild.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap();
			let (proof, _) = build_txt_proof_async(sockaddr, &query_name).await.unwrap();

			let mut rrs = parse_rr_stream(&proof).unwrap();
			rrs.shuffle(&mut rand::rngs::OsRng);
			let verified_rrs = verify_rr_stream(&rrs).unwrap();
			// The CName plus both TXT records at its target.
			assert_eq!(verified_rrs.verified_rrs.len(), 3);

			let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
			assert!(verified_rrs.valid_from < now);
			assert!(verified_rrs.expires > now);

			let resolved_rrs = verified_rrs.resolve_name(&query_name);
			assert_eq!(resolved_rrs.len(), 2);
			assert_eq!(resolved_rrs.iter().filter(|rr| {
				const PFX: &'static str = "bitcoin:";
				if let RR::Txt(txt) = &rr {
					assert_eq!(txt.name.as_str(), "matt.user._bitcoin-payment.mattcorallo.com.");
					txt.data.iter()
						.take(PFX.len())
						.filter_map(|b| char::from_u32(b.into()))
						.map(|c| c.to_ascii_lowercase())
						.eq(PFX.chars())
				} else { false }
			}).count(), 1);
		}
	}

	#[cfg(feature = "tokio")]
	#[tokio::test]
	async fn test_dname_wildcard_query_async() {
		for resolver in ["1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"] {
			let sockaddr = resolver.to_socket_addrs().unwrap().next().unwrap();
			let query_name = "wildcard_a.wildcard_b.dname_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap();
			let (proof, _) = build_txt_proof_async(sockaddr, &query_name).await.unwrap();

			let mut rrs = parse_rr_stream(&proof).unwrap();
			rrs.shuffle(&mut rand::rngs::OsRng);
			let verified_rrs = verify_rr_stream(&rrs).unwrap();
			assert_eq!(verified_rrs.verified_rrs.len(), 3);

			let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
			assert!(verified_rrs.valid_from < now);
			assert!(verified_rrs.expires > now);

			let resolved_rrs = verified_rrs.resolve_name(&query_name);
			assert_eq!(resolved_rrs.len(), 1);
			if let RR::Txt(txt) = &resolved_rrs[0] {
				assert_eq!(txt.name.as_str(), "cname.wildcard_test.dnssec_proof_tests.bitcoin.ninja.");
				assert_eq!(txt.data.as_vec(), b"wildcard_test");
			} else { panic!(); }
		}
	}

	#[cfg(feature = "tokio")]
	#[tokio::test]
	async fn test_tbast_ovh_hosted() {
		// OVH's DNS servers do all kinds of weird inefficient things, making for a good test.
		for resolver in ["1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"] {
			let sockaddr = resolver.to_socket_addrs().unwrap().next().unwrap();
			let query_name = "me.user._bitcoin-payment.t-bast.xyz.".try_into().unwrap();
			let (proof, _) = build_txt_proof_async(sockaddr, &query_name).await.unwrap();

			let mut rrs = parse_rr_stream(&proof).unwrap();
			rrs.shuffle(&mut rand::rngs::OsRng);
			let verified_rrs = verify_rr_stream(&rrs).unwrap();
			assert_eq!(verified_rrs.verified_rrs.len(), 1);

			let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
			assert!(verified_rrs.valid_from < now);
			assert!(verified_rrs.expires > now);

			let resolved_rrs = verified_rrs.resolve_name(&query_name);
			assert_eq!(resolved_rrs.len(), 1);
			if let RR::Txt(txt) = &resolved_rrs[0] {
				assert_eq!(txt.name.as_str(), "me.user._bitcoin-payment.t-bast.xyz.");
				assert!(txt.data.as_vec().starts_with(b"bitcoin:"));
			} else { panic!(); }
		}
	}

	#[cfg(feature = "tokio")]
	#[tokio::test]
	async fn test_no_dnssec() {
		// Google believes DNSSEC is a bad idea due to 10 year old information and a cargo cult
		// within Mountain View. Thus we assume they'll never bother to use the security it
		// provides.
		for resolver in ["1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"] {
			let sockaddr = resolver.to_socket_addrs().unwrap().next().unwrap();
			let query_name = "google.com.".try_into().unwrap();
			let err = build_a_proof_async(sockaddr, &query_name).await.unwrap_err();
			assert_eq!(err.into_inner().unwrap().downcast().unwrap(), Box::new(ProofBuildingError::Unauthenticated));
		}
	}
}
