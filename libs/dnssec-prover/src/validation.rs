//! Utilities to deserialize and validate RFC 9102 proofs

use alloc::borrow::ToOwned;
use alloc::vec::Vec;
use alloc::vec;
use core::cmp::{self, Ordering};

use crate::base32;
use crate::crypto;
use crate::rr::*;
use crate::ser::write_name;
use crate::sort::{insertion_sort, insertion_sort_by};
use crate::unhex::unhex;
use crate::MAX_PROOF_STEPS;

/// Gets the trusted root anchors
///
/// These are available at <https://data.iana.org/root-anchors/root-anchors.xml>
pub fn root_hints() -> Vec<DS> {
	#[allow(unused_mut)]
	let mut res = vec![
	// The 2010 key was only valid until 2019, predating this software substantially. We don't
	// bother to implement checking that it is only used on old proofs so simply do not use it.
	/*DS {
		name: ".".try_into().unwrap(), key_tag: 19036, alg: 8, digest_type: 2,
		digest: unhex:<32>("49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5").to_vec(),
	},*/
	DS {
		name: ".".try_into().unwrap(), key_tag: 20326, alg: 8, digest_type: 2,
		digest: unhex::<32>("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D").to_vec(),
	}, DS {
		name: ".".try_into().unwrap(), key_tag: 38696, alg: 8, digest_type: 2,
		digest: unhex::<32>("683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16").to_vec(),
	}];
	// In tests, add the trust anchor from RFC 9102
	#[cfg(test)]
	res.push(DS {
		name: ".".try_into().unwrap(), key_tag: 47005, alg: 13, digest_type: 2,
		digest: unhex::<32>("2eb6e9f2480126691594d649a5a613de3052e37861634641bb568746f2ffc4d4").to_vec(),
	});
	res
}

#[derive(Debug, PartialEq)]
/// An error when validating DNSSEC signatures or other data
pub enum ValidationError {
	/// An algorithm used in signing was not supported.
	///
	/// While data was provided, it couldn't be authenticated and may be forged.
	///
	/// In cases where signing is mandatory, this can be treated as an error.
	UnsupportedAlgorithm,
	/// The provided data was invalid or signatures did not validate.
	Invalid,
	/// We would need to validate more than [`MAX_PROOF_STEPS`] sets of [`RRSig`]s to validate the
	/// proof we were given.
	ValidationCountLimited,
}

fn verify_rrsig<'a, RR: WriteableRecord, Keys>(sig: &RRSig, dnskeys: Keys, mut records: Vec<&RR>)
-> Result<(), ValidationError>
where Keys: IntoIterator<Item = &'a DnsKey> {
	for record in records.iter() {
		if sig.ty != record.ty() { return Err(ValidationError::Invalid); }
	}
	for dnskey in dnskeys.into_iter() {
		if dnskey.key_tag() == sig.key_tag {
			// Protocol must be 3, otherwise its not DNSSEC
			if dnskey.protocol != 3 { continue; }
			// The ZONE flag must be set if we're going to validate RRs with this key.
			if dnskey.flags & 0b1_0000_0000 == 0 { continue; }
			// the REVOKE flag must not be set.
			if dnskey.flags & 0b0_1000_0000 != 0 { continue; }
			if dnskey.alg != sig.alg { continue; }

			let mut hash_ctx = match sig.alg {
				8 => crypto::hash::Hasher::sha256(),
				10 => crypto::hash::Hasher::sha512(),
				13 => crypto::hash::Hasher::sha256(),
				14 => crypto::hash::Hasher::sha384(),
				15 => crypto::hash::Hasher::sha512(),
				_ => return Err(ValidationError::UnsupportedAlgorithm),
			};

			hash_ctx.update(&sig.ty.to_be_bytes());
			hash_ctx.update(&sig.alg.to_be_bytes());
			hash_ctx.update(&sig.labels.to_be_bytes());
			hash_ctx.update(&sig.orig_ttl.to_be_bytes());
			hash_ctx.update(&sig.expiration.to_be_bytes());
			hash_ctx.update(&sig.inception.to_be_bytes());
			hash_ctx.update(&sig.key_tag.to_be_bytes());
			write_name(&mut hash_ctx, &sig.key_name);

			insertion_sort(&mut records);

			// Some recursive resolvers (at least 9.9.9.9) give us a few too many records, and the
			// proof builder is too naive to filter them out. Instead, we filter them out here, as
			// there's no security harm to just removing identical records here.
			records.dedup();

			for record in records.iter() {
				let record_labels = record.name().labels() as usize;
				let labels = sig.labels.into();
				// For NSec types, the name should already match the wildcard, so we don't do any
				// filtering here. This is relied upon in `verify_rr_stream` to check whether an
				// NSec record is matching via wildcard (as otherwise we'd allow a resolver to
				// change the name out from under us and change the wildcard to something else).
				if record.ty() != NSec::TYPE && record_labels != labels {
					if record_labels < labels { return Err(ValidationError::Invalid); }
					let signed_name = record.name().trailing_n_labels(sig.labels);
					debug_assert!(signed_name.is_some());
					if let Some(name) = signed_name {
						hash_ctx.update(b"\x01*");
						write_name(&mut hash_ctx, name);
					} else { return Err(ValidationError::Invalid); }
				} else {
					write_name(&mut hash_ctx, record.name());
				}
				hash_ctx.update(&record.ty().to_be_bytes());
				hash_ctx.update(&1u16.to_be_bytes()); // The INternet class
				hash_ctx.update(&sig.orig_ttl.to_be_bytes());
				record.serialize_u16_len_prefixed(&mut hash_ctx);
			}

			let hash = hash_ctx.finish();
			let sig_validation = match sig.alg {
				8|10 => crypto::rsa::validate_rsa(&dnskey.pubkey, &sig.signature, hash.as_ref())
					.map_err(|_| ValidationError::Invalid),
				13 => crypto::secp256r1::validate_ecdsa(&dnskey.pubkey, &sig.signature, hash.as_ref())
					.map_err(|_| ValidationError::Invalid),
				14 => crypto::secp384r1::validate_ecdsa(&dnskey.pubkey, &sig.signature, hash.as_ref())
					.map_err(|_| ValidationError::Invalid),
				// TODO: 15 => ED25519
				_ => return Err(ValidationError::UnsupportedAlgorithm),
			};
			#[cfg(fuzzing)] {
				// When fuzzing, treat any signature starting with a 1 as valid, but only after
				// parsing and checking signatures to give that code a chance to panic.
				if sig.signature.get(0) == Some(&1) {
					return Ok(());
				}
			}

			// Note that technically there could be a key tag collision here, causing spurious
			// verification failure. In most zones, there's only 2-4 DNSKEY entries, meaning a
			// spurious collision shouldn't be much more often than one every billion zones. Much
			// more likely in such a case, someone is just trying to do a KeyTrap attack, so we
			// simply hard-fail and return an error immediately.
			sig_validation?;

			return Ok(());
		}
	}
	Err(ValidationError::Invalid)
}

/// Verify [`RRSig`]s over [`DnsKey`], returning a reference to the [`RRSig`] that matched, if any.
fn verify_dnskeys<'r, 'd, RI, R, DI, D>(sigs: RI, dses: DI, records: Vec<&DnsKey>)
-> Result<&'r RRSig, ValidationError>
where RI: IntoIterator<IntoIter = R>, R: Iterator<Item = &'r RRSig>,
      DI: IntoIterator<IntoIter = D>, D: Iterator<Item = &'d DS> + Clone {
	let mut validated_dnskeys = Vec::with_capacity(records.len());
	let dses = dses.into_iter();

	let mut had_known_digest_type = false;
	let mut had_ds = false;
	for ds in dses.clone() {
		had_ds = true;
		if ds.digest_type == 1 || ds.digest_type == 2 || ds.digest_type == 4 {
			had_known_digest_type = true;
			break;
		}
	}
	if !had_ds { return Err(ValidationError::Invalid); }
	if !had_known_digest_type { return Err(ValidationError::UnsupportedAlgorithm); }

	for dnskey in records.iter() {
		// Only use SHA1 DS records if we don't have any SHA256/SHA384 DS RRs.
		let trust_sha1 = dses.clone().all(|ds| ds.digest_type != 2 && ds.digest_type != 4);
		for ds in dses.clone() {
			if ds.alg != dnskey.alg { continue; }
			if dnskey.key_tag() == ds.key_tag {
				let mut ctx = match ds.digest_type {
					1 if trust_sha1 => crypto::hash::Hasher::sha1(),
					2 => crypto::hash::Hasher::sha256(),
					4 => crypto::hash::Hasher::sha384(),
					_ => continue,
				};
				write_name(&mut ctx, &dnskey.name);
				ctx.update(&dnskey.flags.to_be_bytes());
				ctx.update(&dnskey.protocol.to_be_bytes());
				ctx.update(&dnskey.alg.to_be_bytes());
				ctx.update(&dnskey.pubkey);
				let hash = ctx.finish();
				if hash.as_ref() == ds.digest {
					validated_dnskeys.push(*dnskey);
					break;
				}
			}
		}
	}

	let mut found_unsupported_alg = false;
	for sig in sigs {
		if !validated_dnskeys.iter().any(|key| key.key_tag() == sig.key_tag) {
			// Some DNS servers include spurious RRSig records signed by the ZSK covering the
			// DNSKEY set (looking at you OVH). This is harmless (but wasteful) and we should
			// ignore such signatures rather than immediately failing.
			continue;
		}
		match verify_rrsig(sig, validated_dnskeys.iter().copied(), records.clone()) {
			Ok(()) => return Ok(sig),
			Err(ValidationError::UnsupportedAlgorithm) => {
				// There may be redundant signatures by different keys, where one we don't
				// supprt and another we do. Ignore ones we don't support, but if there are
				// no more, return UnsupportedAlgorithm
				found_unsupported_alg = true;
			},
			Err(ValidationError::ValidationCountLimited) => {
				debug_assert!(false, "verify_rrsig doesn't internally limit");
				return Err(ValidationError::ValidationCountLimited);
			},
			Err(ValidationError::Invalid) => {
				// If a signature is invalid, just immediately fail, avoiding KeyTrap issues.
				return Err(ValidationError::Invalid);
			},
		}
	}

	if found_unsupported_alg {
		Err(ValidationError::UnsupportedAlgorithm)
	} else {
		Err(ValidationError::Invalid)
	}
}

/// Given a set of [`RR`]s, [`verify_rr_stream`] checks what it can and returns the set of
/// non-[`RRSig`]/[`DnsKey`]/[`DS`] records which it was able to verify using this struct.
///
/// It also contains signing and expiry times, which must be validated before considering the
/// contained records verified.
#[derive(Debug, Clone)]
pub struct VerifiedRRStream<'a> {
	/// The set of verified [`RR`]s, not including [`DnsKey`], [`RRSig`], [`NSec`], and [`NSec3`]
	/// records.
	///
	/// These are not valid unless the current UNIX time is between [`Self::valid_from`] and
	/// [`Self::expires`].
	pub verified_rrs: Vec<&'a RR>,
	/// The latest [`RRSig::inception`] of all the [`RRSig`]s validated to verify
	/// [`Self::verified_rrs`].
	///
	/// Any records in [`Self::verified_rrs`] should not be considered valid unless this is before
	/// the current UNIX time.
	///
	/// While the field here is a u64, the algorithm used to identify rollovers will fail in 2133.
	pub valid_from: u64,
	/// The earliest [`RRSig::expiration`] of all the [`RRSig`]s validated to verify
	/// [`Self::verified_rrs`].
	///
	/// Any records in [`Self::verified_rrs`] should not be considered valid unless this is after
	/// the current UNIX time.
	///
	/// While the field here is a u64, the algorithm used to identify rollovers will fail in 2133.
	pub expires: u64,
	/// The minimum [`RRSig::orig_ttl`] of all the [`RRSig`]s validated to verify
	/// [`Self::verified_rrs`].
	///
	/// Any caching of [`Self::verified_rrs`] must not last longer than this value, in seconds.
	pub max_cache_ttl: u32,
}

fn resolve_time(time: u32) -> u64 {
	// RFC 2065 was published in January 1997, so we arbitrarily use that as a cutoff and assume
	// any timestamps before then are actually past 2106 instead.
	// We ignore leap years for simplicity.
	if time < 60*60*24*365*27 {
		(time as u64) + (u32::MAX as u64)
	} else {
		time.into()
	}
}

fn nsec_ord(a: &[u8], b: &[u8]) -> Ordering {
	let mut a_label_iter = a.rsplit(|c| *c == b'.');
	let mut b_label_iter = b.rsplit(|c| *c == b'.');
	loop {
		match (a_label_iter.next(), b_label_iter.next()) {
			(Some(_), None) => return Ordering::Greater,
			(None, Some(_)) => return Ordering::Less,
			(Some(a_label), Some(b_label)) => {
				let mut a_bytes = a_label.iter().copied();
				let mut b_bytes = b_label.iter().copied();
				loop {
					match (a_bytes.next(), b_bytes.next()) {
						(Some(_), None) => return Ordering::Greater,
						(None, Some(_)) => return Ordering::Less,
						(Some(mut a), Some(mut b)) => {
							if a.is_ascii_uppercase() {
								a += b'a' - b'A';
							}
							if b.is_ascii_uppercase() {
								b += b'a' - b'A';
							}
							if a != b { return a.cmp(&b); }
						},
						(None, None) => break,
					}
				}
			},
			(None, None) => return Ordering::Equal,
		}
	}
}
fn nsec_ord_extra<T>(a: &(&str, T), b: &(&str, T)) -> Ordering {
	nsec_ord(a.0.as_bytes(), b.0.as_bytes())
}

#[cfg(test)]
#[test]
fn rfc4034_sort_test() {
	// Test nsec_ord based on RFC 4034 section 6.1's example
	let v = vec![&b"example."[..], &b"a.example."[..], &b"yljkjljk.a.example."[..],
		&b"Z.a.example."[..], &b"zABC.a.EXAMPLE."[..], &b"z.example."[..],
		&b"\001.z.example."[..], &b"*.z.example."[..], &b"\xc8.z.example."[..]];
	let mut sorted = v.clone();
	sorted.sort_unstable_by(|a, b| nsec_ord(a, b));
	assert_eq!(sorted, v);
}

/// Verifies the given set of resource records.
///
/// Given a set of arbitrary records, this attempts to validate DNSSEC data from the [`root_hints`]
/// through to any supported non-DNSSEC record types.
///
/// All records which could be validated are returned, though if an error is found validating any
/// contained record, only `Err` will be returned.
///
/// You MUST check that the current UNIX time is between [`VerifiedRRStream::valid_from`] and
/// [`VerifiedRRStream::expires`].
pub fn verify_rr_stream<'a>(inp: &'a [RR]) -> Result<VerifiedRRStream<'a>, ValidationError> {
	let mut zone = ".";
	let mut res = Vec::new();
	let mut rrs_needing_non_existence_proofs = Vec::new();
	let mut nsec_records = Vec::new();
	let mut pending_ds_sets = Vec::with_capacity(1);
	let mut latest_inception = 0;
	let mut earliest_expiry = u64::MAX;
	let mut min_ttl = u32::MAX;
	let mut rrsig_sets_validated = 0;
	'next_zone: while zone == "." || !pending_ds_sets.is_empty() {
		let next_ds_set;
		if let Some((next_zone, ds_set)) = pending_ds_sets.pop() {
			next_ds_set = Some(ds_set);
			zone = next_zone;
		} else {
			debug_assert_eq!(zone, ".");
			next_ds_set = None;
		}

		rrsig_sets_validated += 1;
		if rrsig_sets_validated > MAX_PROOF_STEPS {
			return Err(ValidationError::ValidationCountLimited);
		}

		let dnskey_rrsigs = inp.iter()
			.filter_map(|rr| if let RR::RRSig(sig) = rr { Some(sig) } else { None })
			.filter(|rrsig| rrsig.name.as_str() == zone && rrsig.ty == DnsKey::TYPE);
		let dnskeys = inp.iter()
			.filter_map(|rr| if let RR::DnsKey(dnskey) = rr { Some(dnskey) } else { None })
			.filter(move |dnskey| dnskey.name.as_str() == zone);
		let root_hints = root_hints();
		let verified_dnskey_rrsig = if zone == "." {
			verify_dnskeys(dnskey_rrsigs, &root_hints, dnskeys.clone().collect())?
		} else {
			debug_assert!(next_ds_set.is_some());
			if next_ds_set.is_none() { break 'next_zone; }
			verify_dnskeys(dnskey_rrsigs, next_ds_set.clone().unwrap(), dnskeys.clone().collect())?
		};
		latest_inception = cmp::max(latest_inception, resolve_time(verified_dnskey_rrsig.inception));
		earliest_expiry = cmp::min(earliest_expiry, resolve_time(verified_dnskey_rrsig.expiration));
		min_ttl = cmp::min(min_ttl, verified_dnskey_rrsig.orig_ttl);

		for rrsig in inp.iter()
			.filter_map(|rr| if let RR::RRSig(sig) = rr { Some(sig) } else { None })
			.filter(move |rrsig| rrsig.key_name.as_str() == zone && rrsig.ty != DnsKey::TYPE)
		{
			rrsig_sets_validated += 1;
			if rrsig_sets_validated > MAX_PROOF_STEPS {
				return Err(ValidationError::ValidationCountLimited);
			}

			if !rrsig.name.ends_with_labels(zone) { return Err(ValidationError::Invalid); }
			let signed_records = inp.iter()
				.filter(|rr| rr.name() == &rrsig.name && rr.ty() == rrsig.ty);
			match verify_rrsig(rrsig, dnskeys.clone(), signed_records.clone().collect()) {
				Ok(()) => {},
				Err(ValidationError::UnsupportedAlgorithm) => continue,
				Err(ValidationError::ValidationCountLimited) => {
					debug_assert!(false, "verify_rrsig doesn't internally limit");
					return Err(ValidationError::ValidationCountLimited);
				},
				Err(ValidationError::Invalid) => {
					// If a signature is invalid, just immediately fail, avoiding KeyTrap issues.
					return Err(ValidationError::Invalid);
				}
			}
			latest_inception = cmp::max(latest_inception, resolve_time(rrsig.inception));
			earliest_expiry = cmp::min(earliest_expiry, resolve_time(rrsig.expiration));
			min_ttl = cmp::min(min_ttl, rrsig.orig_ttl);
			match rrsig.ty {
				// RRSigs shouldn't cover child `DnsKey`s or other `RRSig`s
				RRSig::TYPE|DnsKey::TYPE => return Err(ValidationError::Invalid),
				DS::TYPE => {
					// Ignore wildcard `DS` records as it would be impossible to include the
					// nearest-neighbor non-existence NSEC/NSEC3 required after the zone cut.
					if rrsig.labels != rrsig.name.labels() { continue; }
					if !pending_ds_sets.iter().any(|(pending_zone, _)| pending_zone == &rrsig.name.as_str()) {
						pending_ds_sets.push((
							&rrsig.name,
							signed_records.filter_map(|rr|
								if let RR::DS(ds) = rr { Some(ds) }
								else { debug_assert!(false, "We already filtered by type"); None })
						));
					}
				},
				_ => {
					if rrsig.labels != rrsig.name.labels() && rrsig.ty != NSec::TYPE {
						if rrsig.ty == NSec3::TYPE {
							// NSEC3 records should never appear on wildcards, so treat the
							// whole proof as invalid
							return Err(ValidationError::Invalid);
						}
						// If the RR used a wildcard, we need an NSEC/NSEC3 proof, which we
						// check for at the end. Note that the proof should be for the
						// "next closest" name, i.e. if the name here is a.b.c and it was
						// signed as *.c, we want a proof for nothing being in b.c.
						// Alternatively, if it was signed as *.b.c, we'd want a proof for
						// a.b.c.
						if rrsig.labels == u8::MAX { return Err(ValidationError::Invalid); }
						let proof_name = rrsig.name.trailing_n_labels(rrsig.labels + 1)
							.ok_or(ValidationError::Invalid)?;
						rrs_needing_non_existence_proofs.push((proof_name, &rrsig.key_name));
					}
					for record in signed_records {
						if !res.contains(&record) {
							if record.ty() == NSec::TYPE || record.ty() == NSec3::TYPE {
								nsec_records.push((record, &rrsig.key_name));
							}
							res.push(record);
						}
					}
				},
			}
		}
		continue 'next_zone;
	}
	if res.is_empty() { return Err(ValidationError::Invalid) }
	if latest_inception >= earliest_expiry { return Err(ValidationError::Invalid) }

	// First sort the proofs we're looking for so that the retains below avoid shifting.
	insertion_sort_by(&mut rrs_needing_non_existence_proofs, nsec_ord_extra);
	'proof_search_loop: while let Some((name, zone)) = rrs_needing_non_existence_proofs.pop() {
		let local_zone_nsecs =
			nsec_records.iter().filter(|(_, nsec_zone)| *nsec_zone == zone).map(|(rr, _)| rr);
		let nsec_search = local_zone_nsecs.clone()
			.filter_map(|rr| if let RR::NSec(nsec) = rr { Some(nsec) } else { None });
		for nsec in nsec_search {
			// If the NSEC next_name ends with the next closest name we're looking for we have an
			// overlap between a real subdomain (or a subdomain of one) and the name we were told
			// resolved to a wildcard. This is forbidden - if a.b.c.d.e exists, *.e cannot be used
			// for any of a.b.c.d.e, *.b.c.d.e, *.c.d.e or *.d.e.
			if name_ends_with_labels(&nsec.next_name, name) { continue; }
			// Note that the last NSEC in a zone's chain wraps around.
			let after_start = nsec_ord(nsec.name.as_bytes(), name.as_bytes()) == Ordering::Less;
			let before_end = nsec_ord(&nsec.next_name, name.as_bytes()) == Ordering::Greater;
			let name_contained = if nsec_ord(nsec.name.as_bytes(), &nsec.next_name) == Ordering::Less {
				after_start && before_end
			} else {
				after_start || before_end
			};
			if name_contained {
				rrs_needing_non_existence_proofs.retain(|(n, z)| *n != name || *z != zone);
				continue 'proof_search_loop;
			}
		}

		let nsec3_search = local_zone_nsecs.clone()
			.filter_map(|rr| if let RR::NSec3(nsec3) = rr { Some(nsec3) } else { None });
		// Because we will only ever have two entries, a Vec is simpler than a map here.
		let mut nsec3params_to_name_hash = Vec::new();
		for nsec3 in nsec3_search.clone() {
			if nsec3.hash_iterations > 2500 {
				// RFC 5115 places different limits on the iterations based on the signature key
				// length, but we just use 2500 for all key types
				continue;
			}
			if nsec3.hash_algo != 1 { continue; }
			if nsec3params_to_name_hash.iter()
				.any(|(iterations, salt, _)| *iterations == nsec3.hash_iterations && *salt == &nsec3.salt)
			{ continue; }

			let mut hasher = crypto::hash::Hasher::sha1();
			write_name(&mut hasher, name);
			hasher.update(&nsec3.salt);
			for _ in 0..nsec3.hash_iterations {
				let res = hasher.finish();
				hasher = crypto::hash::Hasher::sha1();
				hasher.update(res.as_ref());
				hasher.update(&nsec3.salt);
			}
			nsec3params_to_name_hash.push((nsec3.hash_iterations, &nsec3.salt, hasher.finish()));

			if nsec3params_to_name_hash.len() >= 2 {
				// We only allow for up to two sets of hash_iterations/salt per zone. Beyond that
				// we assume this is a malicious DoSing proof and give up.
				break;
			}
		}
		for nsec3 in nsec3_search {
			if nsec3.flags != 0 {
				// This is an opt-out NSEC3 (or has unknown flags set). Thus, we shouldn't rely on
				// it as proof that some record doesn't exist.
				continue;
			}
			if nsec3.hash_algo != 1 { continue; }
			let name_hash = if let Some((_, _, hash)) =
				nsec3params_to_name_hash.iter()
				.find(|(iterations, salt, _)| *iterations == nsec3.hash_iterations && *salt == &nsec3.salt)
			{
				hash
			} else { continue };

			let (start_hash_base32, _) = nsec3.name.split_once('.')
				.unwrap_or_else(|| { debug_assert!(false); ("", "")});
			let start_hash = if let Ok(start_hash) = base32::decode(start_hash_base32) {
				start_hash
			} else { continue };
			if start_hash.len() != 20 || nsec3.next_name_hash.len() != 20 { continue; }

			// Note that the last NSEC3 in a zone's chain wraps around.
			let after_start = &start_hash[..] < name_hash.as_ref();
			let before_end = &nsec3.next_name_hash[..] > name_hash.as_ref();
			let hash_contained = if start_hash[..] < nsec3.next_name_hash[..] {
				after_start && before_end
			} else {
				after_start || before_end
			};
			if hash_contained {
				rrs_needing_non_existence_proofs.retain(|(n, z)| *n != name || *z != zone);
				continue 'proof_search_loop;
			}
		}
		return Err(ValidationError::Invalid);
	}

	res.retain(|rr| rr.ty() != NSec::TYPE && rr.ty() != NSec3::TYPE);

	Ok(VerifiedRRStream {
		verified_rrs: res, valid_from: latest_inception, expires: earliest_expiry,
		max_cache_ttl: min_ttl,
	})
}

impl<'a> VerifiedRRStream<'a> {
	/// Given a name, resolve any [`CName`] records and return any verified records which were
	/// pointed to by the original name.
	///
	/// Note that because of [`CName`]s, the [`RR::name`] in the returned records may or may not be
	/// equal to `name`.
	///
	/// You MUST still check that the current UNIX time is between
	/// [`VerifiedRRStream::valid_from`] and [`VerifiedRRStream::expires`] before
	/// using any records returned here.
	pub fn resolve_name<'b>(&self, name_param: &'b Name) -> Vec<&'a RR> where 'a: 'b {
		let mut dname_name;
		let mut name = name_param;
		for _ in 0..MAX_PROOF_STEPS {
			let mut cname_search = self.verified_rrs.iter()
				.filter(|rr| rr.name() == name)
				.filter_map(|rr| if let RR::CName(cn) = rr { Some(cn) } else { None });
			if let Some(cname) = cname_search.next() {
				name = &cname.canonical_name;
				continue;
			}

			let mut dname_search = self.verified_rrs.iter()
				.filter(|rr| name.len() > rr.name().len() && name.ends_with_labels(&**rr.name()))
				.filter_map(|rr| if let RR::DName(dn) = rr { Some(dn) } else { None });
			if let Some(dname) = dname_search.next() {
				let prefix = name.strip_suffix(&*dname.name).expect("We just filtered for this");
				let resolved_name = if dname.delegation_name.as_str() == "." {
					prefix.to_owned()
				} else {
					prefix.to_owned() + &dname.delegation_name
				};
				dname_name = if let Ok(name) = resolved_name.try_into() {
					name
				} else {
					// This should only happen if the combined name ended up being too long
					return Vec::new();
				};
				name = &dname_name;
				continue;
			}

			return self.verified_rrs.iter().filter(|rr| rr.name() == name).copied().collect();
		}
		Vec::new()
	}
}

#[cfg(test)]
mod tests {
	#![allow(deprecated)]

	use super::*;

	use alloc::borrow::ToOwned;

	use crate::ser::{parse_rr_stream, write_rr};

	use hex_conservative::FromHex;
	use rand::seq::SliceRandom;

	fn root_dnskey() -> (Vec<DnsKey>, Vec<RR>) {
		let dnskeys = vec![DnsKey {
			name: ".".try_into().unwrap(), flags: 256, protocol: 3, alg: 8,
			pubkey: base64::decode("AwEAAeCYD6Z7WWKVLeuWgowKP+3g+Gs1cnLKq7a3CaQxQpv8bfuFVI0WnG33qaSH/Mw9IBgifrdzf4XY/DQLnyBJ9MfaOyAWuEaEmYJ+GQPiwVVfstGwSA1McfFJUttTgq2Huu74KARhtA8wPo/N3XcyYQtNhz+qCM5NBb3ecx/naw6sYab9LxS6f2cU0q03++BP5Ks0Uef8WJCa/1izCYE+vMkwoltV+tENa3hpXiZ7jle/xdgaZrPi5ZGmyLVI34g1XVYrNlsCCTmNvFQIfzW5STFQFsQpizczyFn9r3LzSxxPCNwdlCG84bER0BmdwqbF6Tanv+FxMOavrahkj4wIy5k=").unwrap(),
		}, DnsKey {
			name: ".".try_into().unwrap(), flags: 257, protocol: 3, alg: 8,
			pubkey: base64::decode("AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=").unwrap(),
		}, DnsKey {
			name: ".".try_into().unwrap(), flags: 257, protocol: 3, alg: 8,
			pubkey: base64::decode("AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=").unwrap(),
		}];
		let dnskey_rrsig = RRSig {
			name: ".".try_into().unwrap(), ty: DnsKey::TYPE, alg: 8, labels: 0, orig_ttl: 172800,
			expiration: 1787270400, inception: 1785456000, key_tag: 20326, key_name: ".".try_into().unwrap(),
			signature: base64::decode("kKpaPEyKDhNNs9rizpyOEcK2Nwg04lOQEeUgL175fR1W7zTzCo96Lpf5xuMeN9vZKHq362Yi6pX11BeCL5JejRJ0q4OflNu2jkjZpqW4JWNeim0gaJxd2fg8MMh7qg9gZnMfFLzK8y2Hudve+JF3LD/MjIPpdPd/GEISqynmOLYxNmol2eKMdiDJ3RNxVTfzmEo8QqXGGDEozWf5pM9XvTa22LLJ37NHblwT0eeHnhxKwt5q4RH7YabmC2NlUge5R/GoCQD0WJdmi139O7DyyRDa1YEHSPigdLDRjXuAmw1acBrLbmvS7F9j1Zbc2Mm1MO924z6z9L3GXPlaSV1NJw==").unwrap(),
		};
		let root_hints = root_hints();
		verify_dnskeys([&dnskey_rrsig], &root_hints, dnskeys.iter().collect()).unwrap();
		let rrs = vec![dnskeys[0].clone().into(), dnskeys[1].clone().into(), dnskeys[2].clone().into(), dnskey_rrsig.into()];
		(dnskeys, rrs)
	}

	fn com_dnskey() -> (Vec<DnsKey>, Vec<RR>) {
		let root_dnskeys = root_dnskey().0;
		let mut com_ds = vec![DS {
			name: "com.".try_into().unwrap(), key_tag: 19718, alg: 13, digest_type: 2,
			digest: Vec::from_hex("8ACBB0CD28F41250A80A491389424D341522D946B0DA0C0291F2D3D771D7805A").unwrap(),
		}];
		let ds_rrsig = RRSig {
			name: "com.".try_into().unwrap(), ty: DS::TYPE, alg: 8, labels: 1, orig_ttl: 86400,
			expiration: 1787115600, inception: 1785988800, key_tag: 57780, key_name: ".".try_into().unwrap(),
			signature: base64::decode("n8/OgzlB4FN+3Qmdv+U7tVrHXIRumf2fqRXun1TQW4GUwQr7RMFLiYuymzog8chIA+7RsIkTMTNmV2FezFqGWtl2/Kp1PSTtdEKgziLDtXz2em0KZmvoOdm/uH+37wRtgK91HdVXpKKhESp4zGYZKBQP1oMZQ4hsCHndZrIh7sHgmp7b7lypbqrPFSlDm71VZsYpEXKF+3nD3CUD3S0spCHkS5StcXNfxZGDyr/UBX3/gYWPyX9VU3zcHfShOckX+QLIKqtbbXzM8/LjMwZHnZdehv156JQzOJRoGGrhDlKZ6L5C5PPXVRi6JthP+bwGRFWeJ9/yyWbH6o/RtUJdLg==").unwrap(),
		};
		verify_rrsig(&ds_rrsig, &root_dnskeys, com_ds.iter().collect()).unwrap();
		let dnskeys = vec![DnsKey {
			name: "com.".try_into().unwrap(), flags: 256, protocol: 3, alg: 13,
			pubkey: base64::decode("o6onp+t66olg3PFhuIXaaatogT3OrqHrqt48IkYGuxwW8tSnQVMGyO+TSmp8sTRtkD9km+N/VQvvtqVM8ra9/Q==").unwrap(),
		}, DnsKey {
			name: "com.".try_into().unwrap(), flags: 257, protocol: 3, alg: 13,
			pubkey: base64::decode("tx8EZRAd2+K/DJRV0S+hbBzaRPS/G6JVNBitHzqpsGlz8huE61Ms9ANe6NSDLKJtiTBqfTJWDAywEp1FCsEINQ==").unwrap(),
		}];
		let dnskey_rrsig = RRSig {
			name: "com.".try_into().unwrap(), ty: DnsKey::TYPE, alg: 13, labels: 1, orig_ttl: 86400,
			expiration: 1787234555, inception: 1785938255, key_tag: 19718, key_name: "com.".try_into().unwrap(),
			signature: base64::decode("+mh5ldazL68oULmaud6VQrHXYpcjbUZ8sJLBlc8HWf4jaB7TXCSsnUCQhxpZ9wtemVxj7TptSGsAhHXEvrgpvw==").unwrap(),
		};
		verify_dnskeys([&dnskey_rrsig], &com_ds, dnskeys.iter().collect()).unwrap();
		let rrs = vec![com_ds.pop().unwrap().into(), ds_rrsig.into(),
			dnskeys[0].clone().into(), dnskeys[1].clone().into(), dnskey_rrsig.into()];
		(dnskeys, rrs)
	}

	fn ninja_dnskey() -> (Vec<DnsKey>, Vec<RR>) {
		let root_dnskeys = root_dnskey().0;
		let mut ninja_ds = vec![DS {
			name: "ninja.".try_into().unwrap(), key_tag: 46082, alg: 8, digest_type: 2,
			digest: Vec::from_hex("C8F816A7A575BDB2F997F682AAB2653BA2CB5EDDB69B036A30742A33BEFAF141").unwrap(),
		}];
		let ds_rrsig = RRSig {
			name: "ninja.".try_into().unwrap(), ty: DS::TYPE, alg: 8, labels: 1, orig_ttl: 86400,
			expiration: 1787115600, inception: 1785988800, key_tag: 57780, key_name: ".".try_into().unwrap(),
			signature: base64::decode("tCn+vWmRGtTe0aAIajh5+u0FDgs4u7+RLIkXyzjoE5RQ1wm9yO2pQDaGAvXZFI/gpu1AI0JRDHg8Wt5Pwcu6ng7UrhhrPEvATfTbPqRXVBix7GGbm7r3RjgNZriSBSJpP9ehiI56Ay/32TN1ejS5LfcLq0kCZX1MTh4vEhjy0vSzaf7f3QiyhUcTeg+1x+o2kVCKbvtsrTWhJXpt0Y5KGN/VaUUlMw80XTK42heYBz0U4OBZVhiYDem9uBozH2q0/8FxbAMqhLUuMcZNq1cSQ23LeuzbpvpjIul4dI3R0p2kCCIZx/weNGjVbsPNBt0FwVqeBCKaD7lUaMAiKBGqpQ==").unwrap(),
		};
		verify_rrsig(&ds_rrsig, &root_dnskeys, ninja_ds.iter().collect()).unwrap();
		let dnskeys = vec![DnsKey {
			name: "ninja.".try_into().unwrap(), flags: 256, protocol: 3, alg: 8,
			pubkey: base64::decode("AwEAAcEhG/hFkNTJK5wLP7a1xXzT076x5qG24PPISw5r+JSD9mS0mcaZX+87tmOmuiKPvxAZj14nnMjcHA4J/n2RTJkofPZ+SLASOxg/mngB2trNdFEUhmEbisqE7UOuPQD55C6jee4tJ9Xs0thHEXlN3gO6MJj0+jk17skLJuH4P+td").unwrap(),
		}, DnsKey {
			name: "ninja.".try_into().unwrap(), flags: 256, protocol: 3, alg: 8,
			pubkey: base64::decode("AwEAAc2FxKHX6CerPDnSAS8XKiERe1LU4K6Du1QW8WpR3c7D/6LWLnNQpNbRTZl/NIoAcoQ9sOLl2zvOMUR7KCBpC7DYvmG+Nh8dzwYWlI+rIZj9UUyy2f+9QB6gVMPeqF49vTzibNxeZf7ftiTHKi3ubcMYZdTA4JOdlX6hUL3w7+69").unwrap(),
		}, DnsKey {
			name: "ninja.".try_into().unwrap(), flags: 257, protocol: 3, alg: 8,
			pubkey: base64::decode("AwEAAcceTJ3Ekkmiez70L8uNVrTDrHZxXHrQHEHQ1DJZDRXDxizuSy0prDXy1yybMqcKAkPL0IruvJ9vHg5j2eHN/hM8RVqCQ1wHgLdQASyUL37VtmLuyNmuiFpYmT+njXVh/tzRHZ4cFxrLAtACWDe6YaPApnVkJ0FEcMnKCQaymBaLX02WQOYuG3XdBr5mQQTtMs/kR/oh83QBcSxyCg3KS7G8IPP6MQPK0za94gsW9zlI5rgN2gpSjbU2qViGjDhw7N3PsC37PLTSLirUmkufeMkP9sfhDjAbP7Nv6FmpTDAIRmBmV0HBT/YNBTUBP89DmEDsrYL8knjkrOaLqV5wgkk=").unwrap(),
		}];
		let dnskey_rrsig = RRSig {
			name: "ninja.".try_into().unwrap(), ty: DnsKey::TYPE, alg: 8, labels: 1, orig_ttl: 3600,
			expiration: 1787414103, inception: 1785596103, key_tag: 46082, key_name: "ninja.".try_into().unwrap(),
			signature: base64::decode("gx365BoyGgZpy1zqP9Ih8MAx0/SG0e5v1OR7Z7ecXONuufBne0ksny8IoMY7fxEj1Fug/7CJwJMqN1AICPVgK45u9wAPGMlIp552cTaQEw+YIoeOpYaIt5XbQ7xkbVTjoXNkMJQUam1cQrodQzvd5U6AlfoTAPAgWYzVXnbGFOeOjTNqmetf3hz13qDX5zNhG4TJOdOvdLplYXEpGZR+2CMRZTBguuwXEVTWVo9+Cyet+aKNQN0vx9aRanY6PMqbXgNxDFtFlBkqAdaESI2/6gz4QkDDZbG2R357wNqHM82FQdAu2FBSqH4NkhP0OBV6xTJ2EQrmwVsAz7R7rJOk3A==").unwrap(),
		};
		verify_dnskeys([&dnskey_rrsig], &ninja_ds, dnskeys.iter().collect()).unwrap();
		let rrs = vec![ninja_ds.pop().unwrap().into(), ds_rrsig.into(),
			dnskeys[0].clone().into(), dnskeys[1].clone().into(), dnskeys[2].clone().into(),
			dnskey_rrsig.into()];
		(dnskeys, rrs)
	}

	fn mattcorallo_dnskey() -> (Vec<DnsKey>, Vec<RR>) {
		let com_dnskeys = com_dnskey().0;
		let mattcorallo_ds = vec![DS {
			name: "mattcorallo.com.".try_into().unwrap(), key_tag: 9033, alg: 13, digest_type: 2,
			digest: Vec::from_hex("282511C1378832188575A172F29A89C09AC28C826FC4FE78534D4C6DF5EED2F0").unwrap(),
		}, DS {
			name: "mattcorallo.com.".try_into().unwrap(), key_tag: 58101, alg: 13, digest_type: 2,
			digest: Vec::from_hex("F0E161567D468087FF27B051ABC94476178A7CB635DA1AA705E05C77CA81DE52").unwrap(),
		}];
		let ds_rrsig = RRSig {
			name: "mattcorallo.com.".try_into().unwrap(), ty: DS::TYPE, alg: 13, labels: 2, orig_ttl: 86400,
			expiration: 1786415920, inception: 1785806920, key_tag: 41446, key_name: "com.".try_into().unwrap(),
			signature: base64::decode("e0j29NIzuHAvtSKf04LKShm2vVOiwkKlluoXyTsq9yB+prqyJ/RTU4Na/ZBHuH0ygnQUET6C5SEaQuM5gUd9+w==").unwrap(),
		};
		verify_rrsig(&ds_rrsig, &com_dnskeys, mattcorallo_ds.iter().collect()).unwrap();
		let dnskeys = vec![DnsKey {
			name: "mattcorallo.com.".try_into().unwrap(), flags: 256, protocol: 3, alg: 13,
			pubkey: base64::decode("eEAgU/iS8VR7ubg5lArqTACdBHxK8ERx5TpTWCw9wc25pe2JiN0/iN3QgfmOBs6AUpVu+iF36abdUdct/TRLjQ==").unwrap(),
		}, DnsKey {
			name: "mattcorallo.com.".try_into().unwrap(), flags: 256, protocol: 3, alg: 13,
			pubkey: base64::decode("yPAeYPanlAxAHZ9rb7LAqP2LrTZYVhECybfwXqn84b1kvhtBCS22I++mTIcYd681BKwv6WazOi03h8se5mK/KA==").unwrap(),
		}, DnsKey {
			name: "mattcorallo.com.".try_into().unwrap(), flags: 257, protocol: 3, alg: 13,
			pubkey: base64::decode("yN2riWFvCTElBchzLyt0U1RjCcXW+evRcq7Ap5EU6gOacleOXft49H2oQDcRqK6C/dJDPbZ52EB5C1WlIYDY4Q==").unwrap(),
		}];
		let dnskey_rrsig = RRSig {
			name: "mattcorallo.com.".try_into().unwrap(), ty: DnsKey::TYPE, alg: 13, labels: 2, orig_ttl: 604800,
			expiration: 1787071850, inception: 1785856850, key_tag: 9033, key_name: "mattcorallo.com.".try_into().unwrap(),
			signature: base64::decode("njvuObzGh/mdUjX5mmJKI+hw7ByPlKe6OKI5m/zhQloLXEg9DUxgS2ShV+twWZuuun5x7RXs1FzEIHxf8W6ikQ==").unwrap(),
		};
		verify_dnskeys([&dnskey_rrsig], &mattcorallo_ds, dnskeys.iter().collect()).unwrap();
		let rrs = vec![mattcorallo_ds[0].clone().into(), mattcorallo_ds[1].clone().into(),
			ds_rrsig.into(),
			dnskeys[0].clone().into(), dnskeys[1].clone().into(), dnskeys[2].clone().into(),
			dnskey_rrsig.into()];
		(dnskeys, rrs)
	}

	fn mattcorallo_txt_record() -> (Vec<Txt>, RRSig) {
		let txts = vec![Txt {
			name: "matt.user._bitcoin-payment.mattcorallo.com.".try_into().unwrap(),
			data: "as long as it doesn't start with bitcoin:, other records should be ignored".try_into().unwrap(),
		}, Txt {
			name: "matt.user._bitcoin-payment.mattcorallo.com.".try_into().unwrap(),
			data: "bitcoin:bc1qztwy6xen3zdtt7z0vrgapmjtfz8acjkfp5fp7l?lno=lno1zr5qyugqgskrk70kqmuq7v3dnr2fnmhukps9n8hut48vkqpqnskt2svsqwjakp7k6pyhtkuxw7y2kqmsxlwruhzqv0zsnhh9q3t9xhx39suc6qsr07ekm5esdyum0w66mnx8vdquwvp7dp5jp7j3v5cp6aj0w329fnkqqv60q96sz5nkrc5r95qffx002q53tqdk8x9m2tmt85jtpmcycvfnrpx3lr45h2g7na3sec7xguctfzzcm8jjqtj5ya27te60j03vpt0vq9tm2n9yxl2hngfnmygesa25s4u4zlxewqpvp94xt7rur4rhxunwkthk9vly3lm5hh0pqv4aymcqejlgssnlpzwlggykkajp7yjs5jvr2agkyypcdlj280cy46jpynsezrcj2kwa2lyr8xvd6lfkph4xrxtk2xc3lpq".try_into().unwrap(),
		}];
		let txt_rrsig = RRSig {
			name: "matt.user._bitcoin-payment.mattcorallo.com.".try_into().unwrap(),
			ty: Txt::TYPE, alg: 13, labels: 5, orig_ttl: 3600, expiration: 1787055757,
			inception: 1785840757, key_tag: 41141, key_name: "mattcorallo.com.".try_into().unwrap(),
			signature: base64::decode("u1Sl6uNJvSZcxoEsew6/MM7GI8smdPkuDSS26t8tEiFece6d8ezI6wcalSbkLKObXeUmdbW5lHZjnBKkUck3MA==").unwrap(),
		};
		(txts, txt_rrsig)
	}

	fn cloudflare_dnskey() -> (Vec<DnsKey>, Vec<RR>) {
		let com_dnskeys = com_dnskey().0;
		let mut cloudflare_ds = vec![DS {
			name: "cloudflare.com.".try_into().unwrap(), key_tag: 2371, alg: 13, digest_type: 2,
			digest: Vec::from_hex("32996839A6D808AFE3EB4A795A0E6A7A39A76FC52FF228B22B76F6D63826F2B9").unwrap(),
		}];
		let ds_rrsig = RRSig {
			name: "cloudflare.com.".try_into().unwrap(), ty: DS::TYPE, alg: 13, labels: 2, orig_ttl: 86400,
			expiration: 1786582833, inception: 1785973833, key_tag: 41446, key_name: "com.".try_into().unwrap(),
			signature: base64::decode("bj58c8zJI4N/l6M0CzR5/ANQTZBlUAzuxeBcz1Nt4M2B2UPM3LoYXQ8ASYZli5caWIkVq2B2kHs0N3dxmu2sUg==").unwrap(),
		};
		verify_rrsig(&ds_rrsig, &com_dnskeys, cloudflare_ds.iter().collect()).unwrap();
		let dnskeys = vec![DnsKey {
			name: "cloudflare.com.".try_into().unwrap(), flags: 256, protocol: 3, alg: 13,
			pubkey: base64::decode("oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==").unwrap(),
		}, DnsKey {
			name: "cloudflare.com.".try_into().unwrap(), flags: 257, protocol: 3, alg: 13,
			pubkey: base64::decode("mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==").unwrap(),
		}];
		let dnskey_rrsig = RRSig {
			name: "cloudflare.com.".try_into().unwrap(), ty: DnsKey::TYPE, alg: 13, labels: 2, orig_ttl: 3600,
			expiration: 1790916935, inception: 1785646535, key_tag: 2371, key_name: "cloudflare.com.".try_into().unwrap(),
			signature: base64::decode("14eL8GoAJFkezWYWQr6pcVSq55HRaaykMGstMqOW1bHXDb3Ll0gYj79po1sBCvqUAFEYXZmIBVcYfSytQ63MPw==").unwrap(),
		};
		verify_dnskeys([&dnskey_rrsig], &cloudflare_ds, dnskeys.iter().collect()).unwrap();
		let rrs = vec![cloudflare_ds.pop().unwrap().into(), ds_rrsig.into(),
			dnskeys[0].clone().into(), dnskeys[1].clone().into(), dnskey_rrsig.into()];
		(dnskeys, rrs)
	}

	fn cloudflare_online_signed_nsec() -> (NSec, RRSig) {
		let nsec = NSec {
			name: "online_signing_test.cloudflare.com.".try_into().unwrap(),
			next_name: b"\x00.online_signing_test.cloudflare.com.".to_vec(),
			types: NSecTypeMask::from_types(&[RRSig::TYPE, NSec::TYPE, 128]),
		};
		let nsec_rrsig = RRSig {
			name: "online_signing_test.cloudflare.com.".try_into().unwrap(),
			ty: NSec::TYPE, alg: 13, labels: 3, orig_ttl: 300, expiration: 1786137946,
			inception: 1785957946, key_tag: 34505, key_name: "cloudflare.com.".try_into().unwrap(),
			signature: base64::decode("wUIukIrWxEzb0SJOTEC7Kg7e/SbDzIIGZMWfOS7/IpToUYGuJj1Io13ufs5shP4MnfAAWxrfFLa6asyurF0OFg==").unwrap(),
		};
		(nsec, nsec_rrsig)
	}

	fn bitcoin_ninja_dnskey() -> (Vec<DnsKey>, Vec<RR>) {
		let ninja_dnskeys = ninja_dnskey().0;
		let bitcoin_ninja_ds = vec![DS {
			name: "bitcoin.ninja.".try_into().unwrap(), key_tag: 29036, alg: 13, digest_type: 2,
			digest: Vec::from_hex("3F7AD5A303E9C1CD1474B8DF2AE56F3F82DA8637CA55DB4D9A2BB85960CA698E").unwrap(),
		}, DS {
			name: "bitcoin.ninja.".try_into().unwrap(), key_tag: 30142, alg: 13, digest_type: 2,
			digest: Vec::from_hex("FB445ADFE3314DAAE4884B53592BED42DF1DD0B147B5930E8B16AF2AEAE94504").unwrap(),
		}];
		let ds_rrsig = RRSig {
			name: "bitcoin.ninja.".try_into().unwrap(), ty: DS::TYPE, alg: 8, labels: 2, orig_ttl: 3600,
			expiration: 1787414103, inception: 1785596103, key_tag: 19731, key_name: "ninja.".try_into().unwrap(),
			signature: base64::decode("n1wGkPRW8dbBvCD55EAMHR4WaZAxcXJW9Se8xUFr/D3qtJt6ydH5X/+9TqQMvgU/LYcWc0FeIKun5pTLzbDOkufEYfbE3tu+diI9y53zw6qjj0i2NRCj4BdyQletGVDqFfBKQIMs8lrwa+8eqm0lut30iOvu8FyS5RpyISwMkLw=").unwrap(),
		};
		verify_rrsig(&ds_rrsig, &ninja_dnskeys, bitcoin_ninja_ds.iter().collect()).unwrap();
		let dnskeys = vec![DnsKey {
			name: "bitcoin.ninja.".try_into().unwrap(), flags: 256, protocol: 3, alg: 13,
			pubkey: base64::decode("jQGaU+vc1XEIa4507tYhI7tVsKUp+Bd3zdtNMVVxIWSW0QJlJvsXBLnsw+vLHL9HYtYN68ECo1eInYfYk1fILg==").unwrap(),
		}, DnsKey {
			name: "bitcoin.ninja.".try_into().unwrap(), flags: 257, protocol: 3, alg: 13,
			pubkey: base64::decode("T0XjCLwz4dUK2iOKsFAo3j2CW0nEumfvpA5w6gKAAujcD11ewT/6+aRIejB64LG2HGw6J14wiRvxq7uREj972g==").unwrap(),
		}];
		let dnskey_rrsig = RRSig {
			name: "bitcoin.ninja.".try_into().unwrap(), ty: DnsKey::TYPE, alg: 13, labels: 2, orig_ttl: 604800,
			expiration: 1786846836, inception: 1785631836, key_tag: 30142, key_name: "bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("3jrUWhXokJjCCqhUbE6pac2cYHhW+gjZToZh7MaEWz+avKFHh8gC4BleAcrLUCAspemmNbGPU2ZMhW6L9w4o0w==").unwrap(),
		};
		verify_dnskeys([&dnskey_rrsig], &bitcoin_ninja_ds, dnskeys.iter().collect()).unwrap();
		let rrs = vec![bitcoin_ninja_ds[0].clone().into(), bitcoin_ninja_ds[1].clone().into(),
			ds_rrsig.into(),
			dnskeys[0].clone().into(), dnskeys[1].clone().into(), dnskey_rrsig.into()];
		(dnskeys, rrs)
	}

	fn bitcoin_ninja_txt_record() -> (Txt, RRSig) {
		let txt_resp = Txt {
			name: "txt_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			data: "dnssec_prover_test".try_into().unwrap(),
		};
		let txt_rrsig = RRSig {
			name: "txt_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			ty: Txt::TYPE, alg: 13, labels: 4, orig_ttl: 30, expiration: 1787178279,
			inception: 1785963279, key_tag: 62306, key_name: "bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("MtmxM8RekiyS716n4Oz4dmiO32VfHtdLoWVwMPD7o7hwAo3TZoFSi1QOmHEFsrn/wtjghuZTBz/IwVY/3Os1CQ==").unwrap(),
		};
		(txt_resp, txt_rrsig)
	}

	fn bitcoin_ninja_cname_record() -> (CName, RRSig) {
		let cname_resp = CName {
			name: "cname_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			canonical_name: "txt_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
		};
		let cname_rrsig = RRSig {
			name: "cname_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			ty: CName::TYPE, alg: 13, labels: 4, orig_ttl: 30, expiration: 1787178279,
			inception: 1785963279, key_tag: 62306, key_name: "bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("67U3kvg35HyzESYD4oQ6NtIklzuMUDGkmrP+Bu0Yt0ZWJ249a1+pOMD3IiltgV+kidT6e/17d1HUM7zIKROAJA==").unwrap(),
		};
		(cname_resp, cname_rrsig)
	}

	fn bitcoin_ninja_dname_record() -> (DName, RRSig) {
		let dname = DName {
			name: "dname_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			delegation_name: "cname_wildcard_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
		};
		let dname_rrsig = RRSig {
			name: "dname_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			ty: DName::TYPE, alg: 13, labels: 4, orig_ttl: 30, expiration: 1787178279,
			inception: 1785963279, key_tag: 62306, key_name: "bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("vxE+K/VVKWpnTPGSDYavj2WTWxCti4TV3KAhzExSaEQBCHbTh7qTptUT33mnOanYtcRV5X46IQRNqZUlHRrDtw==").unwrap(),
		};
		(dname, dname_rrsig)
	}

	fn bitcoin_ninja_dname_sibling_records() -> (Txt, RRSig, Txt, RRSig) {
		let sibling = Txt {
			name: "notdname_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			data: "not_dnamed".try_into().unwrap(),
		};
		let sibling_rrsig = RRSig {
			name: "notdname_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			ty: Txt::TYPE, alg: 13, labels: 4, orig_ttl: 30, expiration: 1787258898,
			inception: 1786043898, key_tag: 62306, key_name: "bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("CTnx0YktprRMA14f434Zwyu9NBYxti3NOfIcv5cPCnJxQvU7UmOOuBMtKpnSvvJBKpsbhXfnZCZFazG1Z6fdow==").unwrap(),
		};
		let redirected = Txt {
			name: "notcname_wildcard_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			data: "wrongly_dnamed".try_into().unwrap(),
		};
		let redirected_rrsig = RRSig {
			name: "notcname_wildcard_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			ty: Txt::TYPE, alg: 13, labels: 4, orig_ttl: 30, expiration: 1787258898,
			inception: 1786043898, key_tag: 62306, key_name: "bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("uwLsAhkqQHwafsp+mt5X0cwbNXEuIM0zCT+qEJaC65TxS5FNi9PFOS8zo730q70W53OMvDBSkw6xKdf4/mEsSg==").unwrap(),
		};
		(sibling, sibling_rrsig, redirected, redirected_rrsig)
	}

	fn bitcoin_ninja_txt_sort_edge_cases_records() -> (Vec<Txt>, RRSig) {
		let txts = vec![Txt {
			name: "txt_sort_order.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			data: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".try_into().unwrap(),
		}, Txt {
			name: "txt_sort_order.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			data: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".try_into().unwrap(),
		}, Txt {
			name: "txt_sort_order.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			data: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab".try_into().unwrap(),
		}, Txt {
			name: "txt_sort_order.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			data: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".try_into().unwrap(),
		}, Txt {
			name: "txt_sort_order.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			data: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaba".try_into().unwrap(),
		}, Txt {
			name: "txt_sort_order.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			data: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab".try_into().unwrap(),
		}, Txt {
			name: "txt_sort_order.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			data: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaba".try_into().unwrap(),
		}, Txt {
			name: "txt_sort_order.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			data: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabaa".try_into().unwrap(),
		}];
		let rrsig = RRSig {
			name: "txt_sort_order.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			ty: Txt::TYPE, alg: 13, labels: 4, orig_ttl: 30, expiration: 1787178279,
			inception: 1785963279, key_tag: 62306, key_name: "bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("EllHDC5WHigdu+L4HfKRN3wpXz+lfMLJim+qrIE8DTMvrkiNUFHHLnuayOihrl13MJ5FQPWsX3HgPCKfThvYjg==").unwrap(),
		};
		(txts, rrsig)
	}

	/// Note that the NSEC3 proof here is for asdf., any other prefix may fail NSEC checks.
	fn bitcoin_ninja_wildcard_record(pfx: &str) -> (Txt, RRSig, NSec3, RRSig) {
		let name: Name = (pfx.to_owned() + ".wildcard_test.dnssec_proof_tests.bitcoin.ninja.").try_into().unwrap();
		let txt_resp = Txt {
			name: name.clone(),
			data: "wildcard_test".try_into().unwrap(),
		};
		let txt_rrsig = RRSig {
			name: name.clone(),
			ty: Txt::TYPE, alg: 13, labels: 4, orig_ttl: 30, expiration: 1787178279,
			inception: 1785963279, key_tag: 62306, key_name: "bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("4oXWLvyfOvNunXWIWNEDDTjSKV6N7o8l4DAaZYT9xz0cqfaT2qA0iQ3JeIqwBsKGWVejPHlNhBvdd71Mfo1ZUw==").unwrap(),
		};
		let nsec3 = NSec3 {
			name: "gtcdha57vlrv1q1qrjf7vujvlfajtasp.bitcoin.ninja.".try_into().unwrap(),
			hash_algo: 1, flags: 0, hash_iterations: 0, salt: Vec::from_hex("057B0C54D4647530").unwrap(),
			next_name_hash: Vec::from_hex("958BD48D5AED2B834731866E15F2751AE7A920C9").unwrap(),
			types: NSecTypeMask::from_types(&[16, 46]),
		};
		let nsec3_rrsig = RRSig {
			name: "gtcdha57vlrv1q1qrjf7vujvlfajtasp.bitcoin.ninja.".try_into().unwrap(),
			ty: NSec3::TYPE, alg: 13, labels: 3, orig_ttl: 60, expiration: 1787229760,
			inception: 1786014760, key_tag: 62306, key_name: "bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("trwirnNf4Z4MKuUGQhD6ylyGF7zeOJdPuJeogKJ0bwH7dr9qcAQy9ZhaZI5TwdDhd2g85JvJ8hLGCjO5LzNCMQ==").unwrap(),
		};
		(txt_resp, txt_rrsig, nsec3, nsec3_rrsig)
	}

	fn bitcoin_ninja_cname_wildcard_record() -> (CName, RRSig, Txt, RRSig, [(NSec3, RRSig); 2]) {
		let cname_resp = CName {
			name: "asdf.cname_wildcard_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			canonical_name: "cname.wildcard_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
		};
		let cname_rrsig = RRSig {
			name: "asdf.cname_wildcard_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			ty: CName::TYPE, alg: 13, labels: 4, orig_ttl: 30, expiration: 1787178279,
			inception: 1785963279, key_tag: 62306, key_name: "bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("zZ/uy4AS7tPB1mjW0qAiRe7eqaI54VOt9MIeaQcjL+xls+OBK9Agtp2t9Z0bmyr5/7wo4l2uIKTFEYQyV4XSRg==").unwrap(),
		};
		let nsec3_a = NSec3 {
			name: "g1ae0emluagb7uci39ts11cgoh4sk2l0.bitcoin.ninja.".try_into().unwrap(),
			hash_algo: 1, flags: 0, hash_iterations: 0,
			salt: Vec::from_hex("057B0C54D4647530").unwrap(),
			next_name_hash: Vec::from_hex("832AF5BE3608C56209E4B83FD341299A4269854C").unwrap(),
			types: NSecTypeMask::from_types(&[1, 28, 46]),
		};
		let nsec3_a_rrsig = RRSig {
			name: "g1ae0emluagb7uci39ts11cgoh4sk2l0.bitcoin.ninja.".try_into().unwrap(),
			ty: NSec3::TYPE, alg: 13, labels: 3, orig_ttl: 60, expiration: 1787208167,
			inception: 1785993167, key_tag: 62306, key_name: "bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("sha0PpAzWuFHHXRa2umvNGYuZMy1JaLiDevBJyJmpsyLoskGBA5aLCvhXiQlT913pAPvhXzeXO7JkdPTTpjLag==").unwrap(),
		};
		let (txt_resp, txt_rrsig, nsec3_b, nsec3_b_rrsig) = bitcoin_ninja_wildcard_record("asdf");
		(cname_resp, cname_rrsig, txt_resp, txt_rrsig,
			[(nsec3_a, nsec3_a_rrsig), (nsec3_b, nsec3_b_rrsig)])
	}

	fn bitcoin_ninja_x_domain_cname_wildcard_record() -> (CName, RRSig, NSec3, RRSig) {
		let name = "wildcard.x_domain_cname_wild.dnssec_proof_tests.bitcoin.ninja.";
		let cname = CName {
			name: name.try_into().unwrap(),
			canonical_name: "matt.user._bitcoin-payment.mattcorallo.com.".try_into().unwrap(),
		};
		let cname_rrsig = RRSig {
			name: name.try_into().unwrap(), ty: CName::TYPE, alg: 13, labels: 4, orig_ttl: 30,
			expiration: 1786663415, inception: 1785448415, key_tag: 62306,
			key_name: "bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("HN8yF2eG5pUMWdUHBXK1PoUSTsCvJ89PrdvRIaTpOfdonxWUB4Mw093TefbGfXAWJYmLRRW4jd0B7LPIc3Jv7A==").unwrap(),
		};
		let nsec3 = NSec3 {
			name: "vpbup1es8cqpj16tgtgtas6fifbu8u73.bitcoin.ninja.".try_into().unwrap(),
			hash_algo: 1, flags: 0, hash_iterations: 0,
			salt: Vec::from_hex("180E9D1B9F24BAD7").unwrap(),
			next_name_hash: Vec::from_hex("02417EDCE26669601E9407D9B0A0E3AB1741B8E8").unwrap(),
			types: NSecTypeMask::from_types(&[33, RRSig::TYPE]),
		};
		let nsec3_rrsig = RRSig {
			name: "vpbup1es8cqpj16tgtgtas6fifbu8u73.bitcoin.ninja.".try_into().unwrap(),
			ty: NSec3::TYPE, alg: 13, labels: 3, orig_ttl: 60,
			expiration: 1786974157, inception: 1785759157, key_tag: 62306,
			key_name: "bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("F3GPW+yCZjHy8VA6BMhlH01ZyDHf94dD1r5bTN+AWDuDw2bPsCtVbrzvS0gNenxKBtOgg9kE3+WYiZkrGhaM5A==").unwrap(),
		};
		(cname, cname_rrsig, nsec3, nsec3_rrsig)
	}

	fn bitcoin_ninja_cname_target_wildcard_record() -> (Txt, RRSig, NSec3, RRSig) {
		let name = "cname.wildcard_test.dnssec_proof_tests.bitcoin.ninja.";
		let txt = Txt {
			name: name.try_into().unwrap(),
			data: "wildcard_test".try_into().unwrap(),
		};
		let txt_rrsig = RRSig {
			name: name.try_into().unwrap(), ty: Txt::TYPE, alg: 13, labels: 4, orig_ttl: 30,
			expiration: 1786663415, inception: 1785448415, key_tag: 62306,
			key_name: "bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("NvmdgkpvkZvnAOZbW9+XwJmV8HqMqreTKsLmrtC0q5GJI/26Z7u8PG3/hjPtEd5wShFfTd1xD3FYywOwkp682Q==").unwrap(),
		};
		let nsec3 = NSec3 {
			name: "k0k9mke3fif9p0oq11707a2oe440utb4.bitcoin.ninja.".try_into().unwrap(),
			hash_algo: 1, flags: 0, hash_iterations: 0,
			salt: Vec::from_hex("180E9D1B9F24BAD7").unwrap(),
			next_name_hash: Vec::from_hex("A62CCD9A3F946729008413B647E0E191E7713009").unwrap(),
			types: NSecTypeMask::from_types(&[Txt::TYPE, RRSig::TYPE]),
		};
		let nsec3_rrsig = RRSig {
			name: "k0k9mke3fif9p0oq11707a2oe440utb4.bitcoin.ninja.".try_into().unwrap(),
			ty: NSec3::TYPE, alg: 13, labels: 3, orig_ttl: 60, expiration: 1786987366,
			inception: 1785772366, key_tag: 62306, key_name: "bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("WhCMAfJ1hZ+QsOXhbbwKpBk9VhsZdfYhjUMXcQHLDolrmj3SETPPAkMiGtm2oBdPXZeWrhpPEmNFnpquEgI3Fg==").unwrap(),
		};
		(txt, txt_rrsig, nsec3, nsec3_rrsig)
	}

	/// The NSEC3 matching `override.wildcard_test.dnssec_proof_tests.bitcoin.ninja.`.
	///
	/// Takes the `bitcoin.ninja.` keys so that we can check the zone really did sign this.
	fn bitcoin_ninja_override_matching_nsec3(dnskeys: &[&DnsKey]) -> (NSec3, RRSig) {
		let overridden = "override.wildcard_test.dnssec_proof_tests.bitcoin.ninja.";
		let nsec3 = NSec3 {
			name: "i35lj8ddq83urbvibgi143qtdiu5kqlp.bitcoin.ninja.".try_into().unwrap(),
			hash_algo: 1, flags: 0, hash_iterations: 0,
			salt: Vec::from_hex("180E9D1B9F24BAD7").unwrap(),
			next_name_hash: crate::base32::decode("JO06SMGEHDFJ0I3MNHB1HMMNATA3TPIP").unwrap(),
			types: NSecTypeMask::from_types(&[Txt::TYPE, RRSig::TYPE]),
		};
		let nsec3_rrsig = RRSig {
			name: "i35lj8ddq83urbvibgi143qtdiu5kqlp.bitcoin.ninja.".try_into().unwrap(),
			ty: NSec3::TYPE, alg: 13, labels: 3, orig_ttl: 60,
			expiration: 1786987366, inception: 1785772366, key_tag: 62306,
			key_name: "bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("fYjOjpA3JKI1AlVmpmDemxzGxksQ2t3k2ChO0YCNVkp1Z1tvc91pb2SIBC/AZak4Do4qNl7OK9SkFa4otkU4jQ==").unwrap(),
		};
		verify_rrsig(&nsec3_rrsig, dnskeys.iter().copied(), vec![&nsec3]).unwrap();

		let mut hasher = crypto::hash::Hasher::sha1();
		write_name(&mut hasher, overridden);
		hasher.update(&nsec3.salt);
		let (owner_hash_base32, _) = nsec3.name.split_once('.').unwrap();
		assert_eq!(&base32::decode(owner_hash_base32).unwrap()[..], hasher.finish().as_ref(),
			"NSEC3 no longer matches the name it is supposed to match");
		assert!(nsec3.types.contains_type(Txt::TYPE),
			"NSEC3 must list TXT as present, else it proves absence by bitmap instead");

		(nsec3, nsec3_rrsig)
	}

	fn bitcoin_ninja_nsec_dnskey() -> (Vec<DnsKey>, Vec<RR>) {
		let bitcoin_ninja_dnskeys = bitcoin_ninja_dnskey().0;
		let mut bitcoin_ninja_ds = vec![DS {
			name: "nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			key_tag: 8036, alg: 13, digest_type: 2,
			digest: Vec::from_hex("8EC0DAE4501233979196EBED206212BCCC49E40E086EC2E56558EC1F6FB62715").unwrap(),
		}];
		let ds_rrsig = RRSig {
			name: "nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(), ty: DS::TYPE, alg: 13, labels: 4, orig_ttl: 30,
			expiration: 1787178279, inception: 1785963279, key_tag: 62306, key_name: "bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("a+selfmR4paAGLLAhJVT9x9tkCUDnmzM6yi40A6vKwB8G6vU4VR35gVfMgJjb3weWRAuk8AHoKDf4d0fTiESZA==").unwrap(),
		};
		verify_rrsig(&ds_rrsig, &bitcoin_ninja_dnskeys, bitcoin_ninja_ds.iter().collect()).unwrap();
		let dnskeys = vec![DnsKey {
			name: "nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(), flags: 256, protocol: 3, alg: 13,
			pubkey: base64::decode("cpJjguqPE/pALvfrer/FgTsU+Z/lqlzP0jR2uH1GJZ3XhScsAP2YLWwL+J+v0TQJNBBLxLIchjpxe7pYo0l16w==").unwrap(),
		}, DnsKey {
			name: "nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(), flags: 256, protocol: 3, alg: 13,
			pubkey: base64::decode("j4xLO1IMaoL6fNuB8lssMVTg4CvK8GZpyf5KVCSjmSueXJPMrpAvDvMpEgcrpi5nZr0CR132Sml9BT5E1cPVPg==").unwrap(),
		}, DnsKey {
			name: "nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(), flags: 257, protocol: 3, alg: 13,
			pubkey: base64::decode("MUnIhm31ySIr9WXIBVQc38wlSHHvYaKIOFR8WYl4O9MJBlywWeUdx16oGinCe2FjjMkUkKn9kV5zzWhGmrdIbQ==").unwrap(),
		}];
		let dnskey_rrsig = RRSig {
			name: "nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			ty: DnsKey::TYPE, alg: 13, labels: 4, orig_ttl: 604800, expiration: 1786993013,
			inception: 1785778013, key_tag: 8036, key_name: "nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("o+ve+8i6LwCpqZN5yS9CVsJOVIkjR5baM8Nf6m6HLp5Zfjkbi2ux3PjmwhKe7k1SitH29nK59xc5+8St4pO4iw==").unwrap(),
		};
		verify_dnskeys([&dnskey_rrsig], &bitcoin_ninja_ds, dnskeys.iter().collect()).unwrap();
		let rrs = vec![bitcoin_ninja_ds.pop().unwrap().into(), ds_rrsig.into(),
			dnskeys[0].clone().into(), dnskeys[1].clone().into(), dnskeys[2].clone().into(),
			dnskey_rrsig.into()];
		(dnskeys, rrs)
	}

	fn bitcoin_ninja_nsec_record() -> (Txt, RRSig) {
		let txt_resp = Txt {
			name: "a.nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			data: "txt_a".try_into().unwrap(),
		};
		let txt_rrsig = RRSig {
			name: "a.nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			ty: Txt::TYPE, alg: 13, labels: 5, orig_ttl: 30, expiration: 1787000213,
			inception: 1785785213, key_tag: 37278, key_name: "nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("+H03kpGz5pum4HmL1EgQXq8EF1QSbWsoiWA5NFWlX+bhd3mnQFZ8WyZzvkFI/T6KPhBsoEwAECh6FWtACLFkKA==").unwrap(),
		};
		(txt_resp, txt_rrsig)
	}

	fn bitcoin_ninja_nsec_wildcard_record(pfx: &str) -> (Txt, RRSig, NSec, RRSig) {
		let name: Name = (pfx.to_owned() + ".wildcard_test.nsec_tests.dnssec_proof_tests.bitcoin.ninja.").try_into().unwrap();
		let txt_resp = Txt {
			name: name.clone(),
			data: "wildcard_test".try_into().unwrap(),
		};
		let txt_rrsig = RRSig {
			name: name.clone(),
			ty: Txt::TYPE, alg: 13, labels: 5, orig_ttl: 30, expiration: 1787000213,
			inception: 1785785213, key_tag: 37278, key_name: "nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("5+BP2xI1BraLWhRS6RED4Ji8SlbK0rO0OpnrDohCpwQpd8HTPzhznOXZwfptN+GGruHJ1jHDmPsvWINf9n5tUg==").unwrap(),
		};
		let nsec = NSec {
			name: "*.wildcard_test.nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			next_name: "override.wildcard_test.nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			types: NSecTypeMask::from_types(&[Txt::TYPE, RRSig::TYPE, NSec::TYPE]),
		};
		let nsec_rrsig = RRSig {
			name: "*.wildcard_test.nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			ty: NSec::TYPE, alg: 13, labels: 5, orig_ttl: 60, expiration: 1787232803,
			inception: 1786017803, key_tag: 37278, key_name: "nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("eDqJ3Ly6uVa1phZPle8wChh5AYuy67TRIkeccJRUOv6uZlKcU+2CZ6UcesMjgXnjBbIlXuw0B0/hN78KT61LGQ==").unwrap(),
		};
		(txt_resp, txt_rrsig, nsec, nsec_rrsig)
	}

	fn bitcoin_ninja_nsec_post_override_wildcard_record(pfx: &str) -> (Txt, RRSig, NSec, RRSig) {
		let name: Name = (pfx.to_owned() + ".wildcard_test.nsec_tests.dnssec_proof_tests.bitcoin.ninja.").try_into().unwrap();
		let txt_resp = Txt {
			name: name.clone(),
			data: "wildcard_test".try_into().unwrap(),
		};
		let txt_rrsig = RRSig {
			name: name.clone(),
			ty: Txt::TYPE, alg: 13, labels: 5, orig_ttl: 30, expiration: 1787000213,
			inception: 1785785213, key_tag: 37278, key_name: "nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("5+BP2xI1BraLWhRS6RED4Ji8SlbK0rO0OpnrDohCpwQpd8HTPzhznOXZwfptN+GGruHJ1jHDmPsvWINf9n5tUg==").unwrap(),
		};
		let nsec = NSec {
			name: "override.wildcard_test.nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			next_name: "nested.zent_test.wildcard_test.nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			types: NSecTypeMask::from_types(&[16, 46, 47]),
		};
		let nsec_rrsig = RRSig {
			name: "override.wildcard_test.nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			ty: NSec::TYPE, alg: 13, labels: 6, orig_ttl: 60, expiration: 1787232803,
			inception: 1786017803, key_tag: 37278, key_name: "nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("FFmyd7Bmq8hmFmZOyNMfvJkCpdU9po4ogA41xUw+nZNLvtad/CN/7p9nJTcHTvmp0UEyg5t2K9yV9KhNRlaASg==").unwrap(),
		};
		(txt_resp, txt_rrsig, nsec, nsec_rrsig)
	}

	fn bitcoin_ninja_nsec_wraparound_wildcard_record(pfx: &str) -> (Txt, RRSig, NSec, RRSig) {
		let name: Name = (pfx.to_owned() + ".wildcard_test.nsec_tests.dnssec_proof_tests.bitcoin.ninja.").try_into().unwrap();
		let txt_resp = Txt {
			name: name.clone(),
			data: "wildcard_test".try_into().unwrap(),
		};
		let txt_rrsig = RRSig {
			name: name.clone(),
			ty: Txt::TYPE, alg: 13, labels: 5, orig_ttl: 30, expiration: 1787000213,
			inception: 1785785213, key_tag: 37278, key_name: "nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("5+BP2xI1BraLWhRS6RED4Ji8SlbK0rO0OpnrDohCpwQpd8HTPzhznOXZwfptN+GGruHJ1jHDmPsvWINf9n5tUg==").unwrap(),
		};
		let nsec = NSec {
			name: "nested.zent_test.wildcard_test.nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			next_name: "nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			types: NSecTypeMask::from_types(&[Txt::TYPE, RRSig::TYPE, NSec::TYPE]),
		};
		let nsec_rrsig = RRSig {
			name: "nested.zent_test.wildcard_test.nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			ty: NSec::TYPE, alg: 13, labels: 7, orig_ttl: 60, expiration: 1787232803,
			inception: 1786017803, key_tag: 37278, key_name: "nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap(),
			signature: base64::decode("y11K2pyk6NVCbXtdI4fFt8J9ox1kFUnpjMn8kocY3HYuU1eNdpPvOkEmVRmXyULDvgsksRdJ4yYqmrkeMQx9Lw==").unwrap(),
		};
		(txt_resp, txt_rrsig, nsec, nsec_rrsig)
	}

	#[test]
	fn check_txt_record_a() {
		let dnskeys = mattcorallo_dnskey().0;
		let (txts, txt_rrsig) = mattcorallo_txt_record();
		verify_rrsig(&txt_rrsig, &dnskeys, txts.iter().collect()).unwrap();
	}

	#[test]
	fn check_revoked_dnskey_is_not_used() {
		let dnskeys = bitcoin_ninja_dnskey().0;
		let (txt, txt_rrsig) = bitcoin_ninja_txt_record();
		let txt_resp = [txt];
		verify_rrsig(&txt_rrsig, &dnskeys, txt_resp.iter().collect()).unwrap();

		let signing_key = dnskeys.iter().find(|key| key.key_tag() == txt_rrsig.key_tag).unwrap();

		// Build a REVOKEd key which keeps the same key tag as the real signing key but whose
		// public key is corrupted. Setting REVOKE adds 0x80 to the key tag, so we take that back
		// out of an odd-indexed public key byte, which `key_tag` sums in un-shifted.
		let mut revoked = signing_key.clone();
		revoked.flags |= 0b0_1000_0000;
		let fixup_idx = revoked.pubkey.iter().enumerate()
			.position(|(idx, byte)| idx % 2 == 1 && *byte >= 0x80).unwrap();
		revoked.pubkey[fixup_idx] -= 0x80;
		assert_eq!(revoked.key_tag(), signing_key.key_tag());
		assert_ne!(revoked.pubkey, signing_key.pubkey);

		// A revoked key has to be skipped outright. If it isn't, it gets picked ahead of the real
		// key - it matches on key tag, protocol, ZONE flag and algorithm alike - and its corrupted
		// public key then fails the signature check, taking the whole proof down with it.
		verify_rrsig(&txt_rrsig, vec![&revoked, signing_key], txt_resp.iter().collect()).unwrap();
	}

	#[test]
	fn check_single_txt_proof() {
		let mut rr_stream = Vec::new();
		for rr in root_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in com_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in mattcorallo_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		let (txts, txt_rrsig) = mattcorallo_txt_record();
		for txt in txts { write_rr(&RR::Txt(txt), 1, &mut rr_stream); }
		write_rr(&RR::RRSig(txt_rrsig), 1, &mut rr_stream);

		let mut rrs = parse_rr_stream(&rr_stream).unwrap();
		rrs.shuffle(&mut rand::rngs::OsRng);
		let verified_rrs = verify_rr_stream(&rrs).unwrap();
		let mut txts = verified_rrs.verified_rrs.iter()
			.map(|rr| if let RR::Txt(txt) = rr { txt } else { panic!() })
			.collect::<Vec<_>>();
		txts.sort();
		assert_eq!(txts.len(), 2);
		assert!(txts.iter().all(|txt| txt.name.as_str() == "matt.user._bitcoin-payment.mattcorallo.com."));
		assert_eq!(txts[0].data.as_vec(),
			b"as long as it doesn't start with bitcoin:, other records should be ignored");
		assert_eq!(txts[1].data.as_vec(),
			b"bitcoin:bc1qztwy6xen3zdtt7z0vrgapmjtfz8acjkfp5fp7l?lno=lno1zr5qyugqgskrk70kqmuq7v3dnr2fnmhukps9n8hut48vkqpqnskt2svsqwjakp7k6pyhtkuxw7y2kqmsxlwruhzqv0zsnhh9q3t9xhx39suc6qsr07ekm5esdyum0w66mnx8vdquwvp7dp5jp7j3v5cp6aj0w329fnkqqv60q96sz5nkrc5r95qffx002q53tqdk8x9m2tmt85jtpmcycvfnrpx3lr45h2g7na3sec7xguctfzzcm8jjqtj5ya27te60j03vpt0vq9tm2n9yxl2hngfnmygesa25s4u4zlxewqpvp94xt7rur4rhxunwkthk9vly3lm5hh0pqv4aymcqejlgssnlpzwlggykkajp7yjs5jvr2agkyypcdlj280cy46jpynsezrcj2kwa2lyr8xvd6lfkph4xrxtk2xc3lpq");
		assert_eq!(verified_rrs.valid_from, 1785988800); // The com. DS RRSig was created last
		assert_eq!(verified_rrs.expires, 1786415920); // The mattcorallo.com. DNSKEY RRSig expires first
		assert_eq!(verified_rrs.max_cache_ttl, 3600); // The TXT record had the shortest TTL
	}

	#[test]
	fn check_txt_record_b() {
		let dnskeys = bitcoin_ninja_dnskey().0;
		let (txt, txt_rrsig) = bitcoin_ninja_txt_record();
		let txt_resp = [txt];
		verify_rrsig(&txt_rrsig, &dnskeys, txt_resp.iter().collect()).unwrap();
	}

	#[test]
	fn check_cname_record() {
		let dnskeys = bitcoin_ninja_dnskey().0;
		let (cname, cname_rrsig) = bitcoin_ninja_cname_record();
		let cname_resp = [cname];
		verify_rrsig(&cname_rrsig, &dnskeys, cname_resp.iter().collect()).unwrap();
	}

	#[test]
	fn check_dname_does_not_capture_sibling_name() {
		// We previously had a bug where we used string `ends_with` rather than label-based
		// `ends_with` to check for children, including in DNAME records, which we test here.
		let resolve = |extra: Vec<RR>| -> Vec<RR> {
			let mut rr_stream = Vec::new();
			for rr in root_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
			for rr in ninja_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
			for rr in bitcoin_ninja_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
			let (dname, dname_rrsig) = bitcoin_ninja_dname_record();
			for rr in [RR::DName(dname), RR::RRSig(dname_rrsig)] {
				write_rr(&rr, 1, &mut rr_stream);
			}
			for rr in extra { write_rr(&rr, 1, &mut rr_stream); }

			let mut rrs = parse_rr_stream(&rr_stream).unwrap();
			rrs.shuffle(&mut rand::rngs::OsRng);
			let verified_rrs = verify_rr_stream(&rrs).unwrap();
			let name = "notdname_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap();
			verified_rrs.resolve_name(&name).into_iter().cloned().collect()
		};

		let (sibling, sibling_rrsig, redirected, redirected_rrsig) = bitcoin_ninja_dname_sibling_records();

		assert_eq!(resolve(Vec::new()), Vec::new());
		assert_eq!(resolve(vec![RR::Txt(redirected.clone()), RR::RRSig(redirected_rrsig.clone())]), Vec::new());

		let resolved = resolve(vec![RR::Txt(sibling.clone()), RR::RRSig(sibling_rrsig.clone())]);
		let resolved_full = resolve(vec![
                    RR::Txt(sibling), RR::RRSig(sibling_rrsig), RR::Txt(redirected), RR::RRSig(redirected_rrsig),
                ]);
		assert_eq!(resolved, resolved_full);
		assert_eq!(resolved.len(), 1);
		if let RR::Txt(txt) = &resolved[0] {
			assert_eq!(txt.name.as_str(), "notdname_test.dnssec_proof_tests.bitcoin.ninja.");
			assert_eq!(txt.data.as_vec(), b"not_dnamed");
		} else { panic!(); }
	}

	#[test]
	fn check_dname_label_boundaries() {
		// The substitution cases from RFC 6672 section 2.2's Table 1. A TXT is placed wherever
		// the RFC says we should end up, so a wrong substitution finds nothing.
		let cases: &[(&str, &str, &str, Option<&str>)] = &[
			// query, DNAME owner, DNAME target, where the RFC says we land
			("a.example.com.", "example.com.", "example.net.", Some("a.example.net.")),
			("a.b.example.com.", "example.com.", "example.net.", Some("a.b.example.net.")),
			("a.x.example.com.", "x.example.com.", "example.net.", Some("a.example.net.")),
			("a.example.com.", "example.com.", "y.example.net.", Some("a.y.example.net.")),
			// Only whole labels are replaced, so this is no match at all.
			("ab.example.com.", "b.example.com.", "example.net.", None),
			// A DNAME does not redirect its own owner name (RFC 6672 section 2.3).
			("example.com.", "example.com.", "example.net.", None),
			// A root delegation name must not leave a trailing empty label behind.
			("a.x.", "x.", ".", Some("a.")),
		];
		for (query, owner, target, expected) in cases {
			// For the no-match rows the name resolves to itself, so that is where the TXT goes.
			let landing = expected.unwrap_or(query);
			let rrs = vec![
				RR::DName(DName {
					name: (*owner).try_into().unwrap(),
					delegation_name: (*target).try_into().unwrap(),
				}),
				RR::Txt(Txt {
					name: landing.try_into().unwrap(),
					data: (*landing).try_into().unwrap(),
				}),
			];
			let stream = VerifiedRRStream {
				verified_rrs: rrs.iter().collect(),
				valid_from: 0, expires: u64::MAX, max_cache_ttl: 0,
			};
			// Note that a DNAME's own owner name may carry other records, so for the rows which
			// resolve to the owner itself the DNAME comes back alongside the TXT.
			let resolved = stream.resolve_name(&(*query).try_into().unwrap());
			let txts: Vec<_> = resolved.iter()
				.filter_map(|rr| if let RR::Txt(txt) = rr { Some(txt) } else { None }).collect();
			assert_eq!(txts.len(), 1, "{} + DNAME {} -> {}", query, owner, target);
			assert_eq!(txts[0].name.as_str(), landing, "{} + DNAME {} -> {}", query, owner, target);
		}
	}

	#[test]
	fn check_alias_loops_terminate() {
		// A zone may legitimately sign a CName cycle or a self-referential DName (RFC 6672
		// section 2.2 gives the latter as a corner case), and we may be handed one in a proof.
		let cname_cycle = vec![
			RR::CName(CName {
				name: "a.example.com.".try_into().unwrap(),
				canonical_name: "b.example.com.".try_into().unwrap(),
			}),
			RR::CName(CName {
				name: "b.example.com.".try_into().unwrap(),
				canonical_name: "a.example.com.".try_into().unwrap(),
			}),
		];
		let self_dname = vec![
			RR::DName(DName {
				name: "example.com.".try_into().unwrap(),
				delegation_name: "example.com.".try_into().unwrap(),
			}),
		];
		for (rrs, query) in [(cname_cycle, "a.example.com."), (self_dname, "cyc.example.com.")] {
			let stream = VerifiedRRStream {
				verified_rrs: rrs.iter().collect(),
				valid_from: 0, expires: u64::MAX, max_cache_ttl: 0,
			};
			assert!(stream.resolve_name(&query.try_into().unwrap()).is_empty());
		}
	}

	#[test]
	fn check_multi_zone_proof() {
		let mut rr_stream = Vec::new();
		for rr in root_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in com_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in ninja_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in mattcorallo_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		let (txts, txt_rrsig) = mattcorallo_txt_record();
		for txt in txts { write_rr(&RR::Txt(txt), 1, &mut rr_stream); }
		write_rr(&RR::RRSig(txt_rrsig), 1, &mut rr_stream);
		for rr in bitcoin_ninja_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		let (txt, txt_rrsig) = bitcoin_ninja_txt_record();
		for rr in [RR::Txt(txt), RR::RRSig(txt_rrsig)] { write_rr(&rr, 1, &mut rr_stream); }
		let (cname, cname_rrsig) = bitcoin_ninja_cname_record();
		for rr in [RR::CName(cname), RR::RRSig(cname_rrsig)] { write_rr(&rr, 1, &mut rr_stream); }

		let mut rrs = parse_rr_stream(&rr_stream).unwrap();
		rrs.shuffle(&mut rand::rngs::OsRng);
		let mut verified_rrs = verify_rr_stream(&rrs).unwrap();
		verified_rrs.verified_rrs.sort();
		assert_eq!(verified_rrs.verified_rrs.len(), 4);
		if let RR::Txt(txt) = &verified_rrs.verified_rrs[0] {
			assert_eq!(txt.name.as_str(), "matt.user._bitcoin-payment.mattcorallo.com.");
			assert_eq!(txt.data.as_vec(),
				b"as long as it doesn't start with bitcoin:, other records should be ignored");
		} else { panic!(); }
		if let RR::Txt(txt) = &verified_rrs.verified_rrs[1] {
			assert_eq!(txt.name.as_str(), "matt.user._bitcoin-payment.mattcorallo.com.");
			assert_eq!(txt.data.as_vec(),
				b"bitcoin:bc1qztwy6xen3zdtt7z0vrgapmjtfz8acjkfp5fp7l?lno=lno1zr5qyugqgskrk70kqmuq7v3dnr2fnmhukps9n8hut48vkqpqnskt2svsqwjakp7k6pyhtkuxw7y2kqmsxlwruhzqv0zsnhh9q3t9xhx39suc6qsr07ekm5esdyum0w66mnx8vdquwvp7dp5jp7j3v5cp6aj0w329fnkqqv60q96sz5nkrc5r95qffx002q53tqdk8x9m2tmt85jtpmcycvfnrpx3lr45h2g7na3sec7xguctfzzcm8jjqtj5ya27te60j03vpt0vq9tm2n9yxl2hngfnmygesa25s4u4zlxewqpvp94xt7rur4rhxunwkthk9vly3lm5hh0pqv4aymcqejlgssnlpzwlggykkajp7yjs5jvr2agkyypcdlj280cy46jpynsezrcj2kwa2lyr8xvd6lfkph4xrxtk2xc3lpq");
		} else { panic!(); }
		if let RR::Txt(txt) = &verified_rrs.verified_rrs[2] {
			assert_eq!(txt.name.as_str(), "txt_test.dnssec_proof_tests.bitcoin.ninja.");
			assert_eq!(txt.data.as_vec(), b"dnssec_prover_test");
		} else { panic!(); }
		if let RR::CName(cname) = &verified_rrs.verified_rrs[3] {
			assert_eq!(cname.name.as_str(), "cname_test.dnssec_proof_tests.bitcoin.ninja.");
			assert_eq!(cname.canonical_name.as_str(), "txt_test.dnssec_proof_tests.bitcoin.ninja.");
		} else { panic!(); }

		let filtered_rrs =
			verified_rrs.resolve_name(&"cname_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap());
		assert_eq!(filtered_rrs.len(), 1);
		if let RR::Txt(txt) = &filtered_rrs[0] {
			assert_eq!(txt.name.as_str(), "txt_test.dnssec_proof_tests.bitcoin.ninja.");
			assert_eq!(txt.data.as_vec(), b"dnssec_prover_test");
		} else { panic!(); }
	}

	#[test]
	fn check_wildcard_record() {
		// Wildcard proof works for any name, even multiple names
		let dnskeys = bitcoin_ninja_dnskey().0;
		let (txt, txt_rrsig, _, _) = bitcoin_ninja_wildcard_record("name");
		let txt_resp = [txt];
		verify_rrsig(&txt_rrsig, &dnskeys, txt_resp.iter().collect()).unwrap();

		let (txt, txt_rrsig, _, _) = bitcoin_ninja_wildcard_record("anoter_name");
		let txt_resp = [txt];
		verify_rrsig(&txt_rrsig, &dnskeys, txt_resp.iter().collect()).unwrap();

		let (txt, txt_rrsig, _, _) = bitcoin_ninja_wildcard_record("multiple.names");
		let txt_resp = [txt];
		verify_rrsig(&txt_rrsig, &dnskeys, txt_resp.iter().collect()).unwrap();
	}

	#[test]
	fn check_wildcard_proof() {
		let mut rr_stream = Vec::new();
		for rr in root_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in ninja_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in bitcoin_ninja_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		let (cname, cname_rrsig, txt, txt_rrsig, nsec3s) = bitcoin_ninja_cname_wildcard_record();
		for rr in [RR::CName(cname), RR::RRSig(cname_rrsig)] { write_rr(&rr, 1, &mut rr_stream); }
		for rr in [RR::Txt(txt), RR::RRSig(txt_rrsig)] { write_rr(&rr, 1, &mut rr_stream); }
		for (rra, rrb) in nsec3s { write_rr(&rra, 1, &mut rr_stream); write_rr(&rrb, 1, &mut rr_stream); }

		let mut rrs = parse_rr_stream(&rr_stream).unwrap();
		rrs.shuffle(&mut rand::rngs::OsRng);
		let mut verified_rrs = verify_rr_stream(&rrs).unwrap();
		verified_rrs.verified_rrs.sort();
		assert_eq!(verified_rrs.verified_rrs.len(), 2);
		if let RR::Txt(txt) = &verified_rrs.verified_rrs[0] {
			assert_eq!(txt.name.as_str(), "asdf.wildcard_test.dnssec_proof_tests.bitcoin.ninja.");
			assert_eq!(txt.data.as_vec(), b"wildcard_test");
		} else { panic!(); }
		if let RR::CName(cname) = &verified_rrs.verified_rrs[1] {
			assert_eq!(cname.name.as_str(), "asdf.cname_wildcard_test.dnssec_proof_tests.bitcoin.ninja.");
			assert_eq!(cname.canonical_name.as_str(), "cname.wildcard_test.dnssec_proof_tests.bitcoin.ninja.");
		} else { panic!(); }

		let filtered_rrs =
			verified_rrs.resolve_name(&"asdf.wildcard_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap());
		assert_eq!(filtered_rrs.len(), 1);
		if let RR::Txt(txt) = &filtered_rrs[0] {
			assert_eq!(txt.name.as_str(), "asdf.wildcard_test.dnssec_proof_tests.bitcoin.ninja.");
			assert_eq!(txt.data.as_vec(), b"wildcard_test");
		} else { panic!(); }
	}

	#[test]
	fn check_simple_nsec_zone_proof() {
		let mut rr_stream = Vec::new();
		for rr in root_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in ninja_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in bitcoin_ninja_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in bitcoin_ninja_nsec_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		let (txt, txt_rrsig) = bitcoin_ninja_nsec_record();
		for rr in [RR::Txt(txt), RR::RRSig(txt_rrsig)] { write_rr(&rr, 1, &mut rr_stream); }

		let mut rrs = parse_rr_stream(&rr_stream).unwrap();
		rrs.shuffle(&mut rand::rngs::OsRng);
		let verified_rrs = verify_rr_stream(&rrs).unwrap();
		let filtered_rrs =
			verified_rrs.resolve_name(&"a.nsec_tests.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap());
		assert_eq!(filtered_rrs.len(), 1);
		if let RR::Txt(txt) = &filtered_rrs[0] {
			assert_eq!(txt.name.as_str(), "a.nsec_tests.dnssec_proof_tests.bitcoin.ninja.");
			assert_eq!(txt.data.as_vec(), b"txt_a");
		} else { panic!(); }
	}

	#[test]
	fn check_nsec_wildcard_proof() {
		let check_proof = |pfx: &str, post_override: bool| -> Result<(), ()> {
			let mut rr_stream = Vec::new();
			for rr in root_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
			for rr in ninja_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
			for rr in bitcoin_ninja_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
			for rr in bitcoin_ninja_nsec_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
			let (txt, txt_rrsig, nsec, nsec_rrsig) = if post_override {
				bitcoin_ninja_nsec_post_override_wildcard_record(pfx)
			} else {
				bitcoin_ninja_nsec_wildcard_record(pfx)
			};
			for rr in [RR::Txt(txt), RR::RRSig(txt_rrsig)] { write_rr(&rr, 1, &mut rr_stream); }
			for rr in [RR::NSec(nsec), RR::RRSig(nsec_rrsig)] { write_rr(&rr, 1, &mut rr_stream); }

			let mut rrs = parse_rr_stream(&rr_stream).unwrap();
			rrs.shuffle(&mut rand::rngs::OsRng);
			// If the post_override flag is wrong (or the pfx is override), this will fail. No
			// other calls in this lambda should fail.
			let verified_rrs = verify_rr_stream(&rrs).map_err(|_| ())?;
			let name: Name =
				(pfx.to_owned() + ".wildcard_test.nsec_tests.dnssec_proof_tests.bitcoin.ninja.").try_into().unwrap();
			let filtered_rrs = verified_rrs.resolve_name(&name);
			assert_eq!(filtered_rrs.len(), 1);
			if let RR::Txt(txt) = &filtered_rrs[0] {
				assert_eq!(txt.name, name);
				assert_eq!(txt.data.as_vec(), b"wildcard_test");
			} else { panic!(); }
			Ok(())
		};
		// Records up to override will only work with the pre-override NSEC, and afterwards with
		// the post-override NSEC. The literal override will always fail.
		check_proof("a", false).unwrap();
		check_proof("a", true).unwrap_err();
		check_proof("a.b", false).unwrap();
		check_proof("a.b", true).unwrap_err();
		check_proof("o", false).unwrap();
		check_proof("o", true).unwrap_err();
		check_proof("a.o", false).unwrap();
		check_proof("a.o", true).unwrap_err();
		check_proof("override", false).unwrap_err();
		check_proof("override", true).unwrap_err();
		// Subdomains of override are also overridden by the override TXT entry and cannot use the
		// wildcard record.
		check_proof("b.override", false).unwrap_err();
		check_proof("b.override", true).unwrap_err();
		check_proof("z", false).unwrap_err();
		check_proof("z", true).unwrap();
		check_proof("a.z", false).unwrap_err();
		check_proof("a.z", true).unwrap();
	}

	#[test]
	fn check_online_signed_nsec_next_name() {
		let dnskeys = cloudflare_dnskey().0;
		let (nsec, nsec_rrsig) = cloudflare_online_signed_nsec();
		assert_eq!(&nsec.next_name[..], b"\x00.online_signing_test.cloudflare.com.");

		// Check that the RR with a `\000` label survives round-trip
		let mut rr_stream = Vec::new();
		write_rr(&nsec, 300, &mut rr_stream);
		assert_eq!(parse_rr_stream(&rr_stream).unwrap(), vec![RR::NSec(nsec.clone())]);

		verify_rrsig(&nsec_rrsig, &dnskeys, vec![&nsec]).unwrap();

		assert_eq!(StaticRecord::json(&nsec), "{\"type\":\"nsec\",\
			\"name\":\"online_signing_test.cloudflare.com.\",\
			\"next_name\":\"\\u0000.online_signing_test.cloudflare.com.\",\
			\"types\":[\"NSEC\",\"RRSIG\",128]}");
	}

	#[test]
	fn check_nsec_wraparound_wildcard_proof() {
		let check_proof = |pfx: &str| -> Result<(), ()> {
			let mut rr_stream = Vec::new();
			for rr in root_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
			for rr in ninja_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
			for rr in bitcoin_ninja_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
			for rr in bitcoin_ninja_nsec_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
			let (txt, txt_rrsig, nsec, nsec_rrsig) =
				bitcoin_ninja_nsec_wraparound_wildcard_record(pfx);
			for rr in [RR::Txt(txt), RR::RRSig(txt_rrsig)] { write_rr(&rr, 1, &mut rr_stream); }
			for rr in [RR::NSec(nsec), RR::RRSig(nsec_rrsig)] { write_rr(&rr, 1, &mut rr_stream); }

			let mut rrs = parse_rr_stream(&rr_stream).unwrap();
			rrs.shuffle(&mut rand::rngs::OsRng);
			let verified_rrs = verify_rr_stream(&rrs).map_err(|_| ())?;
			let name: Name =
				(pfx.to_owned() + ".wildcard_test.nsec_tests.dnssec_proof_tests.bitcoin.ninja.").try_into().unwrap();
			let filtered_rrs = verified_rrs.resolve_name(&name);
			assert_eq!(filtered_rrs.len(), 1);
			if let RR::Txt(txt) = &filtered_rrs[0] {
				assert_eq!(txt.name, name);
				assert_eq!(txt.data.as_vec(), b"wildcard_test");
			} else { panic!(); }
			Ok(())
		};

		// `zz` sorts after `zent_test` (the last record) so sits in the wraparound NSEC.
		check_proof("zz").unwrap();
		check_proof("a.zz").unwrap();
		// `a` sorts after the zone apex record, so is past the wraparound NSEC.
		check_proof("a").unwrap_err();
		check_proof("nested.zent_test").unwrap_err();
	}

	#[test]
	fn check_descendant_zone_denial_rejected() {
		// A wildcard TXT signed by `bitcoin.ninja.`, whose next closer name therefore has to be
		// shown not to exist in `bitcoin.ninja.`.
		let build = |proof: Vec<RR>| {
			let mut rr_stream = Vec::new();
			for rr in root_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
			for rr in ninja_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
			for rr in bitcoin_ninja_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
			for rr in bitcoin_ninja_nsec_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
			let (txt, txt_rrsig, _, _) = bitcoin_ninja_wildcard_record("asdf");
			for rr in [RR::Txt(txt), RR::RRSig(txt_rrsig)] { write_rr(&rr, 1, &mut rr_stream); }
			for rr in proof { write_rr(&rr, 1, &mut rr_stream); }
			let mut rrs = parse_rr_stream(&rr_stream).unwrap();
			rrs.shuffle(&mut rand::rngs::OsRng);
			verify_rr_stream(&rrs).map(|_| ())
		};

		// `bitcoin.ninja.`'s own NSEC3 covering the name is the proof which actually applies.
		let (_, _, nsec3, nsec3_rrsig) = bitcoin_ninja_wildcard_record("asdf");
		build(vec![RR::NSec3(nsec3), RR::RRSig(nsec3_rrsig)]).unwrap();

		// The same query "proven" with a record from `nsec_tests.dnssec_proof_tests.bitcoin.ninja.`
		// instead - a zone delegated *beneath* `bitcoin.ninja.`, and so one whose names are still
		// suffixed by it. Its last NSEC wraps back to its own apex and so spans everything outside
		// that zone, which is not its to speak for. Note that this has to be the *wrapping* NSEC:
		// with any other one the name simply falls outside the range and the test would pass
		// without the zone check below ever being consulted.
		let (_, _, nsec, nsec_rrsig) = bitcoin_ninja_nsec_wraparound_wildcard_record("a");
		assert_eq!(build(vec![RR::NSec(nsec), RR::RRSig(nsec_rrsig)]).unwrap_err(),
			ValidationError::Invalid);
	}

	#[test]
	fn check_nsec_empty_non_terminal_is_not_nonexistence() {
		// `nested.zent_test.wildcard_test...` exists, which makes `zent_test.wildcard_test...`
		// an empty non-terminal: it exists, but owns no RRset. RFC 4035 section 2.3 forbids an
		// NSEC at such a name, so the zone's chain steps straight over it and the NSEC from
		// `bitcoin_ninja_nsec_post_override_wildcard_record` spans it. That NSEC must not be
		// read as proof the name is absent - RFC 4592 section 2.2.2 is explicit that empty
		// non-terminals "exist", and RFC 8198 Appendix B gives the test for spotting one: the
		// next name is a subdomain of the name in question.
		//
		// This is exploitable because an RRSIG's Labels field, not its owner name, decides what
		// was signed, and the owner name is not part of the signed data. The wildcard TXT's one
		// signature therefore verifies against any name under `wildcard_test...`, and the only
		// thing keeping it off names the zone never published it at is the next closer denial.
		let build = |pfx: &str| {
			let mut rr_stream = Vec::new();
			for rr in root_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
			for rr in ninja_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
			for rr in bitcoin_ninja_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
			for rr in bitcoin_ninja_nsec_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
			let (txt, txt_rrsig, nsec, nsec_rrsig) =
				bitcoin_ninja_nsec_post_override_wildcard_record(pfx);
			for rr in [RR::Txt(txt), RR::RRSig(txt_rrsig)] { write_rr(&rr, 1, &mut rr_stream); }
			for rr in [RR::NSec(nsec), RR::RRSig(nsec_rrsig)] { write_rr(&rr, 1, &mut rr_stream); }
			let mut rrs = parse_rr_stream(&rr_stream).unwrap();
			rrs.shuffle(&mut rand::rngs::OsRng);
			verify_rr_stream(&rrs).map(|_| ())
		};

		// `z.wildcard_test...` is genuinely absent and the same NSEC spans it, so that wildcard
		// expansion is real and must still validate - the empty non-terminal check must not cost
		// us legitimate wildcard proofs.
		build("z").unwrap();

		// `zent_test.wildcard_test...` is the empty non-terminal, so no denial of it is possible
		// and the RRset must not be accepted below it. Without the check this returns Ok, with
		// the TXT attributed to a name the zone never published it at.
		assert_eq!(build("x.zent_test").unwrap_err(), ValidationError::Invalid);
		// The depth of the forged name below the empty non-terminal is unconstrained.
		assert_eq!(build("y.x.zent_test").unwrap_err(), ValidationError::Invalid);
	}


	#[test]
	fn check_txt_sort_order() {
		let mut rr_stream = Vec::new();
		for rr in root_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in ninja_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in bitcoin_ninja_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		let (mut txts, rrsig) = bitcoin_ninja_txt_sort_edge_cases_records();
		write_rr(&rrsig, 1, &mut rr_stream);
		for txt in txts.iter() { write_rr(txt, 1, &mut rr_stream); }

		let mut rrs = parse_rr_stream(&rr_stream).unwrap();
		rrs.shuffle(&mut rand::rngs::OsRng);
		let verified_rrs = verify_rr_stream(&rrs).unwrap();
		let mut verified_txts = verified_rrs.verified_rrs
			.iter().map(|rr| if let RR::Txt(txt) = rr { txt.clone() } else { panic!(); })
			.collect::<Vec<_>>();
		verified_txts.sort();
		txts.sort();
		assert_eq!(verified_txts, txts);
	}

	#[test]
	fn rfc9102_parse_test() {
		// Note that this is the `AuthenticationChain` field only, and ignores the
		// `ExtSupportLifetime` field (stripping the top two 0 bytes from the front).
let rfc9102_test_vector = Vec::from_hex("045f343433045f74637003777777076578616d706c6503636f6d000034000100000e1000230301018bd1da95272f7fa4ffb24137fc0ed03aae67e5c4d8b3c50734e1050a7920b922045f343433045f74637003777777076578616d706c6503636f6d00002e000100000e10005f00340d0500000e105fc6d9005bfdda80074e076578616d706c6503636f6d00ce1d3adeb7dc7cee656d61cfb472c5977c8c9caeae9b765155c518fb107b6a1fe0355fbaaf753c192832fa621fa73a8b85ed79d374117387598fcc812e1ef3fb076578616d706c6503636f6d000030000100000e1000440101030d2670355e0c894d9cfea6c5af6eb7d458b57a50ba88272512d8241d8541fd54adf96ec956789a51ceb971094b3bb3f4ec49f64c686595be5b2e89e8799c7717cc076578616d706c6503636f6d00002e000100000e10005f00300d0200000e105fc6d9005bfdda80074e076578616d706c6503636f6d004628383075b8e34b743a209b27ae148d110d4e1a246138a91083249cb4a12a2d9bc4c2d7ab5eb3afb9f5d1037e4d5da8339c162a9298e9be180741a8ca74accc076578616d706c6503636f6d00002b00010002a3000024074e0d02e9b533a049798e900b5c29c90cd25a986e8a44f319ac3cd302bafc08f5b81e16076578616d706c6503636f6d00002e00010002a3000057002b0d020002a3005fc6d9005bfdda80861703636f6d00a203e704a6facbeb13fc9384fdd6de6b50de5659271f38ce81498684e6363172d47e2319fdb4a22a58a231edc2f1ff4fb2811a1807be72cb5241aa26fdaee03903636f6d00003000010002a30000440100030dec8204e43a25f2348c52a1d3bce3a265aa5d11b43dc2a471162ff341c49db9f50a2e1a41caf2e9cd20104ea0968f7511219f0bdc56b68012cc3995336751900b03636f6d00003000010002a30000440101030d45b91c3bef7a5d99a7a7c8d822e33896bc80a777a04234a605a4a8880ec7efa4e6d112c73cd3d4c65564fa74347c873723cc5f643370f166b43dedff836400ff03636f6d00003000010002a30000440101030db3373b6e22e8e49e0e1e591a9f5bd9ac5e1a0f86187fe34703f180a9d36c958f71c4af48ce0ebc5c792a724e11b43895937ee53404268129476eb1aed323939003636f6d00002e00010002a300005700300d010002a3005fc6d9005bfdda8049f303636f6d0018a948eb23d44f80abc99238fcb43c5a18debe57004f7343593f6deb6ed71e04654a433f7aa1972130d9bd921c73dcf63fcf665f2f05a0aaebafb059dc12c96503636f6d00002e00010002a300005700300d010002a3005fc6d9005bfdda80708903636f6d006170e6959bd9ed6e575837b6f580bd99dbd24a44682b0a359626a246b1812f5f9096b75e157e77848f068ae0085e1a609fc19298c33b736863fbccd4d81f5eb203636f6d00002b000100015180002449f30d0220f7a9db42d0e2042fbbb9f9ea015941202f9eabb94487e658c188e7bcb5211503636f6d00002b000100015180002470890d02ad66b3276f796223aa45eda773e92c6d98e70643bbde681db342a9e5cf2bb38003636f6d00002e0001000151800053002b0d01000151805fc6d9005bfdda807cae00122e276d45d9e9816f7922ad6ea2e73e82d26fce0a4b718625f314531ac92f8ae82418df9b898f989d32e80bc4deaba7c4a7c8f172adb57ced7fb5e77a784b0700003000010001518000440100030dccacfe0c25a4340fefba17a254f706aac1f8d14f38299025acc448ca8ce3f561f37fc3ec169fe847c8fcbe68e358ff7c71bb5ee1df0dbe518bc736d4ce8dfe1400003000010001518000440100030df303196789731ddc8a6787eff24cacfeddd032582f11a75bb1bcaa5ab321c1d7525c2658191aec01b3e98ab7915b16d571dd55b4eae51417110cc4cdd11d171100003000010001518000440101030dcaf5fe54d4d48f16621afb6bd3ad2155bacf57d1faad5bac42d17d948c421736d9389c4c4011666ea95cf17725bd0fa00ce5e714e4ec82cfdfacc9b1c863ad4600002e000100015180005300300d00000151805fc6d9005bfdda80b79d00de7a6740eeecba4bda1e5c2dd4899b2c965893f3786ce747f41e50d9de8c0a72df82560dfb48d714de3283ae99a49c0fcb50d3aaadb1a3fc62ee3a8a0988b6be").unwrap();

		let mut rrs = parse_rr_stream(&rfc9102_test_vector).unwrap();
		rrs.shuffle(&mut rand::rngs::OsRng);
		let verified_rrs = verify_rr_stream(&rrs).unwrap();
		assert_eq!(verified_rrs.verified_rrs.len(), 1);
		if let RR::TLSA(tlsa) = &verified_rrs.verified_rrs[0] {
			assert_eq!(tlsa.cert_usage, 3);
			assert_eq!(tlsa.selector, 1);
			assert_eq!(tlsa.data_ty, 1);
			assert_eq!(tlsa.data, Vec::from_hex("8bd1da95272f7fa4ffb24137fc0ed03aae67e5c4d8b3c50734e1050a7920b922").unwrap());
		} else { panic!(); }
	}

	#[test]
	fn check_nsec3_wraparound_wildcard_proof() {
		// A wildcard-generated CNAME whose "next closer" name hashes *above* the highest hash in
		// bitcoin.ninja's NSEC3 chain. It is therefore covered by the chain's last NSEC3, whose
		// `next_name_hash` wraps back around to the zone's lowest hash (RFC 5155 section 3.1.7).
		// We used to reject such proofs, only accepting non-wrapping [start, next) ranges.
		let mut rr_stream = Vec::new();
		for rr in root_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in com_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in ninja_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in mattcorallo_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in bitcoin_ninja_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		let (cname, cname_rrsig, nsec3, nsec3_rrsig) = bitcoin_ninja_x_domain_cname_wildcard_record();
		for rr in [RR::CName(cname), RR::RRSig(cname_rrsig)] { write_rr(&rr, 1, &mut rr_stream); }
		for rr in [RR::NSec3(nsec3), RR::RRSig(nsec3_rrsig)] { write_rr(&rr, 1, &mut rr_stream); }
		let (txts, txt_rrsig) = mattcorallo_txt_record();
		for txt in txts { write_rr(&txt, 1, &mut rr_stream); }
		write_rr(&txt_rrsig, 1, &mut rr_stream);

		let mut rrs = parse_rr_stream(&rr_stream).unwrap();

		// Ensure the fixture still actually exercises the wrap-around, in case it is regenerated.
		let mut wrapping_nsec3s = 0;
		for nsec3 in rrs.iter().filter_map(|rr| if let RR::NSec3(n) = rr { Some(n) } else { None }) {
			let (start_hash_base32, _) = nsec3.name.split_once('.').unwrap();
			let start_hash = crate::base32::decode(start_hash_base32).unwrap();
			if start_hash[..] > nsec3.next_name_hash[..] { wrapping_nsec3s += 1; }
		}
		assert_eq!(wrapping_nsec3s, 1, "fixture no longer covers the NSEC3 wrap-around case");

		rrs.shuffle(&mut rand::rngs::OsRng);
		let verified_rrs = verify_rr_stream(&rrs).unwrap();

		let name = "wildcard.x_domain_cname_wild.dnssec_proof_tests.bitcoin.ninja.";
		let filtered_rrs = verified_rrs.resolve_name(&name.try_into().unwrap());
		assert!(filtered_rrs.iter().any(|rr| if let RR::Txt(txt) = rr {
			txt.name.as_str() == "matt.user._bitcoin-payment.mattcorallo.com."
				&& txt.data.as_vec().starts_with(b"bitcoin:")
		} else { false }));
	}

	#[test]
	fn check_nsec3_matching_name_does_not_cover_it() {
		// An NSEC3 whose owner hash *matches* the name we want a non-existence proof for shows
		// that the name exists, so it must not be treated as covering that name. Otherwise a
		// wildcard-signed RRSet could be substituted for the real records at an existing name.
		let mut rr_stream = Vec::new();
		for rr in root_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in ninja_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		for rr in bitcoin_ninja_dnskey().1 { write_rr(&rr, 1, &mut rr_stream); }
		let (txt, txt_rrsig, nsec3, nsec3_rrsig) = bitcoin_ninja_cname_target_wildcard_record();
		for rr in [RR::Txt(txt), RR::RRSig(txt_rrsig)] { write_rr(&rr, 1, &mut rr_stream); }
		for rr in [RR::NSec3(nsec3), RR::RRSig(nsec3_rrsig)] { write_rr(&rr, 1, &mut rr_stream); }

		// As built, this is a perfectly good wildcard proof - which also confirms the whole
		// chain and all the signature validity windows line up.
		let rrs = parse_rr_stream(&rr_stream).unwrap();
		verify_rr_stream(&rrs).unwrap();

		// Now relabel the wildcard-signed TXT onto `override.wildcard_test...`, which really
		// exists in the zone, and supply only the NSEC3 matching that name.
		let overridden: Name =
			"override.wildcard_test.dnssec_proof_tests.bitcoin.ninja.".try_into().unwrap();
		let mut rrs: Vec<RR> = rrs.into_iter()
			.filter(|rr| rr.ty() != NSec3::TYPE)
			.filter(|rr| !matches!(rr, RR::RRSig(sig) if sig.ty == NSec3::TYPE))
			.map(|rr| match rr {
				RR::Txt(mut txt) => { txt.name = overridden.clone(); RR::Txt(txt) },
				RR::RRSig(mut sig) if sig.ty == Txt::TYPE => {
					sig.name = overridden.clone();
					RR::RRSig(sig)
				},
				rr => rr,
			})
			.collect();

		// The relabelled records still carry a valid wildcard signature, so any rejection below
		// has to come from the NSEC3 handling rather than from a broken signature.
		let dnskeys = rrs.iter()
			.filter_map(|rr| if let RR::DnsKey(k) = rr { Some(k) } else { None })
			.filter(|k| k.name.as_str() == "bitcoin.ninja.")
			.collect::<Vec<_>>();
		let txt = rrs.iter()
			.find_map(|rr| if let RR::Txt(txt) = rr { Some(txt) } else { None }).unwrap();
		let txt_rrsig = rrs.iter()
			.find_map(|rr| if let RR::RRSig(sig) = rr {
				if sig.ty == Txt::TYPE { Some(sig) } else { None }
			} else { None }).unwrap();
		assert_eq!(txt.name, overridden);
		verify_rrsig(txt_rrsig, dnskeys.iter().copied(), vec![txt]).unwrap();

		// Likewise, this NSEC3 is genuinely signed by the zone and genuinely matches the name, so
		// the rejection below can only come from it matching rather than covering.
		let (nsec3, nsec3_rrsig) = bitcoin_ninja_override_matching_nsec3(&dnskeys);
		rrs.push(RR::NSec3(nsec3));
		rrs.push(RR::RRSig(nsec3_rrsig));
		rrs.shuffle(&mut rand::rngs::OsRng);
		assert_eq!(verify_rr_stream(&rrs).unwrap_err(), ValidationError::Invalid);
	}

}
