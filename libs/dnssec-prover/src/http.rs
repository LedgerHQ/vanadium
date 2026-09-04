//! A simple tokio-based HTTP server which serves DNSSEC proofs in RFC 9102 format.

#![deny(missing_docs)]

#![allow(clippy::new_without_default)] // why is this even a lint
#![allow(clippy::result_unit_err)] // Why in the hell is this a lint?
#![allow(clippy::get_first)] // Sometimes this improves readability
#![allow(clippy::needless_lifetimes)] // lifetimes improve readability
#![allow(clippy::needless_borrow)] // borrows indicate read-only/non-move
#![allow(clippy::too_many_arguments)] // sometimes we don't have an option
#![allow(clippy::identity_op)] // sometimes identities improve readability for repeated actions
#![allow(clippy::erasing_op)] // sometimes identities improve readability for repeated actions

extern crate alloc;

/// The maximum number of requests we will make when building a proof or the maximum number of
/// [`rr::RRSig`] sets we'll validate records from when validating proofs.
// Note that this is duplicated exactly in src/lib.rs
pub const MAX_PROOF_STEPS: usize = 20;

pub mod rr;
pub mod ser;
pub mod query;

#[cfg(feature = "validation")]
mod base32;
#[cfg(feature = "validation")]
mod crypto;
#[cfg(feature = "validation")]
pub mod validation;
#[cfg(feature = "validation")]
pub(crate) mod unhex;

#[cfg(any(feature = "build_server", all(feature = "tokio", feature = "validation")))]
use tokio_crate as tokio;

#[cfg(feature = "build_server")]
#[tokio::main]
async fn main() {
	let resolver_sockaddr = std::env::var("RESOLVER")
		.expect("Please set the RESOLVER env variable to the TCP socket of a recursive DNS resolver")
		.parse().expect("RESOLVER was not a valid socket address");
	let bind_addr = std::env::var("BIND")
		.expect("Please set the BIND env variable to a socket address to listen on");

	let listener = tokio::net::TcpListener::bind(bind_addr).await
		.expect("Failed to bind to socket");
	imp::run_server(listener, resolver_sockaddr).await;
}

#[cfg(not(feature = "build_server"))]
fn main() { panic!("You need to enable the `build_server` feature to use the built-in server"); }

#[cfg(any(feature = "build_server", all(feature = "tokio", feature = "validation")))]
mod imp {
	use super::*;

	use rr::Name;
	use query::*;

	use std::net::SocketAddr;

	use tokio::net::TcpListener;
	use tokio::io::{AsyncReadExt, AsyncWriteExt};

	pub(super) async fn run_server(listener: TcpListener, resolver_sockaddr: SocketAddr) {
		loop {
			let (mut socket, _) = listener.accept().await.expect("Failed to accept new TCP connection");
			tokio::spawn(async move {
				let mut response = ("400 Bad Request", "Bad Request");
				'ret_err: loop { // goto label
					let mut buf = [0; 4096];
					let mut buf_pos = 0;
					'read_req: loop {
						if buf_pos == buf.len() { response.1 = "Request Too Large"; break 'ret_err; }
						let read_res = { socket.read(&mut buf[buf_pos..]).await };
						match read_res {
							Ok(0) => return,
							Ok(len) => {
								buf_pos += len;
								for window in buf[..buf_pos].windows(2) {
									if window == b"\r\n" { break 'read_req; }
								}
							}
							Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {},
							Err(_) => return,
						}
					}
					let request;
					if let Ok(s) = std::str::from_utf8(&buf[..buf_pos]) {
						if let Some((r, _)) = s.split_once("\r\n") {
							request = r;
						} else {
							debug_assert!(false);
							break 'ret_err;
						}
					} else {
						break 'ret_err;
					}

					let mut parts = request.split(" ");
					let (verb, path, http_vers);
					if let Some(v) = parts.next() { verb = v; } else { break 'ret_err; }
					if let Some(p) = parts.next() { path = p; } else { break 'ret_err; }
					if let Some(v) = parts.next() { http_vers = v; } else { break 'ret_err; }
					if parts.next().is_some() { break; }
					if verb != "GET" { break; }
					if http_vers != "HTTP/1.1" && http_vers != "HTTP/1.0" { break 'ret_err; }

					const PATH_PFX: &'static str = "/dnssecproof?";
					if !path.starts_with(PATH_PFX) {
						response = ("404 Not Found", "Not Found");
						break 'ret_err;
					}

					let (mut d, mut t) = ("", "");
					for arg in path[PATH_PFX.len()..].split("&") {
						if let Some((k, v)) = arg.split_once("=") {
							if k == "d" {
								d = v;
							} else if k == "t" {
								t = v;
							}
						} else { break 'ret_err; }
					}

					if d == "" || t == "" {
						response.1 = "Missing d or t URI parameters";
						break 'ret_err;
					}
					let query_name = if let Ok(domain) = Name::try_from(d) { domain } else {
						response.1 = "Failed to parse domain, make sure it ends with .";
						break 'ret_err;
					};
					let proof_res = match t.to_ascii_uppercase().as_str() {
						"TXT" => build_txt_proof_async(resolver_sockaddr, &query_name).await,
						"TLSA" => build_tlsa_proof_async(resolver_sockaddr, &query_name).await,
						"A" => build_a_proof_async(resolver_sockaddr, &query_name).await,
						"AAAA" => build_aaaa_proof_async(resolver_sockaddr, &query_name).await,
						_ => break 'ret_err,
					};
					let (proof, cache_ttl) = if let Ok(proof) = proof_res { proof } else {
						response = ("404 Not Found", "Failed to generate proof for given domain");
						break 'ret_err;
					};

					let _ = socket.write_all(
						format!(
							"HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nCache-Control: public, max-age={}, s-maxage={}\r\nAccess-Control-Allow-Origin: *\r\n\r\n",
							proof.len(), cache_ttl, cache_ttl
						).as_bytes()
					).await;
					let _ = socket.write_all(&proof).await;
					return;
				}
				let _ = socket.write_all(format!(
					"HTTP/1.1 {}\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nAccess-Control-Allow-Origin: *\r\n\r\n{}",
					response.0, response.1.len(), response.1,
				).as_bytes()).await;
			});
		}
	}
}

#[cfg(all(feature = "tokio", feature = "validation", test))]
mod test {
	use super::*;

	use crate::rr::RR;
	use crate::ser::parse_rr_stream;
	use crate::validation::verify_rr_stream;

	use minreq;

	#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
	async fn test_lookup() {
		let ns = "8.8.8.8:53".parse().unwrap();
		let listener = tokio::net::TcpListener::bind("127.0.0.1:17492").await
			.expect("Failed to bind to socket");
		tokio::spawn(imp::run_server(listener, ns));
		let resp = minreq::get(
			"http://127.0.0.1:17492/dnssecproof?d=matt.user._bitcoin-payment.mattcorallo.com.&t=tXt"
		).send().unwrap();

		assert_eq!(resp.status_code, 200);
		let rrs = parse_rr_stream(resp.as_bytes()).unwrap();
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
	}

	#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
	async fn test_lookup_a() {
		let ns = "9.9.9.9:53".parse().unwrap();
		let listener = tokio::net::TcpListener::bind("127.0.0.1:17493").await
			.expect("Failed to bind to socket");
		tokio::spawn(imp::run_server(listener, ns));
		let resp = minreq::get(
			"http://127.0.0.1:17493/dnssecproof?d=cloudflare.com.&t=a"
		).send().unwrap();

		assert_eq!(resp.status_code, 200);
		let rrs = parse_rr_stream(resp.as_bytes()).unwrap();
		let verified_rrs = verify_rr_stream(&rrs).unwrap();
		assert!(verified_rrs.verified_rrs.len() >= 1);
	}

	#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
	async fn test_lookup_tlsa() {
		let ns = "1.1.1.1:53".parse().unwrap();
		let listener = tokio::net::TcpListener::bind("127.0.0.1:17494").await
			.expect("Failed to bind to socket");
		tokio::spawn(imp::run_server(listener, ns));
		let resp = minreq::get(
			"http://127.0.0.1:17494/dnssecproof?d=_25._tcp.mail.as397444.net.&t=TLSA"
		).send().unwrap();

		assert_eq!(resp.status_code, 200);
		let rrs = parse_rr_stream(resp.as_bytes()).unwrap();
		let verified_rrs = verify_rr_stream(&rrs).unwrap();
		assert_eq!(verified_rrs.verified_rrs.len(), 1);
	}
}
