//! Logic to read and write resource record (streams)

use alloc::vec::Vec;
use alloc::string::String;

use crate::rr::*;
use crate::query::QueryBuf;

pub(crate) fn read_u8(inp: &mut &[u8]) -> Result<u8, ()> {
	let res = *inp.first().ok_or(())?;
	*inp = &inp[1..];
	Ok(res)
}
pub(crate) fn read_u16(inp: &mut &[u8]) -> Result<u16, ()> {
	if inp.len() < 2 { return Err(()); }
	let mut bytes = [0; 2];
	bytes.copy_from_slice(&inp[..2]);
	*inp = &inp[2..];
	Ok(u16::from_be_bytes(bytes))
}
pub(crate) fn read_u32(inp: &mut &[u8]) -> Result<u32, ()> {
	if inp.len() < 4 { return Err(()); }
	let mut bytes = [0; 4];
	bytes.copy_from_slice(&inp[..4]);
	*inp = &inp[4..];
	Ok(u32::from_be_bytes(bytes))
}

pub(crate) fn read_u8_len_prefixed_bytes(inp: &mut &[u8]) -> Result<Vec<u8>, ()> {
	let len = *inp.first().ok_or(())?;
	*inp = &inp[1..];
	if inp.len() < len.into() { return Err(()); }
	let mut res = Vec::with_capacity(len.into());
	res.extend_from_slice(&inp[..len.into()]);
	*inp = &inp[len.into()..];
	Ok(res)
}

pub(crate) fn read_nsec_types_bitmap(inp: &mut &[u8]) -> Result<NSecTypeMaskBytes, ()> {
	let mut res = NSecTypeMaskBytes::new();
	while !inp.is_empty() {
		let block = *inp.get(0).ok_or(())?;
		let len = *inp.get(1).ok_or(())?;
		*inp = &inp[2..];
		if len == 0 || len > 32 { return Err(()); }
		if inp.len() < len as usize { return Err(()); }
		res.resize(core::cmp::max(block as usize * 32 + len as usize, res.len()));
		res[block as usize * 32..block as usize * 32 + len as usize]
			.copy_from_slice(&inp[..len as usize]);
		*inp = &inp[len as usize..];
	}
	Ok(res)
}

fn do_read_wire_packet_labels(inp: &mut &[u8], wire_packet: &[u8], name: &mut Vec<u8>, recursion_limit: usize) -> Result<(), ()> {
	loop {
		let len = read_u8(inp)? as usize;
		if len == 0 {
			if name.is_empty() { name.push(b'.'); }
			break;
		} else if len >= 0xc0 && recursion_limit > 0 {
			let offs = ((len & !0xc0) << 8) | read_u8(inp)? as usize;
			if offs >= wire_packet.len() { return Err(()); }
			do_read_wire_packet_labels(&mut &wire_packet[offs..], wire_packet, name, recursion_limit - 1)?;
			break;
		}
		if inp.len() <= len { return Err(()); }
		if len > 63 { return Err(()); }
		name.extend_from_slice(&inp[..len]);
		name.push(b'.');
		*inp = &inp[len..];
		if name.len() > 255 { return Err(()); }
	}
	Ok(())
}

fn read_wire_packet_labels(inp: &mut &[u8], wire_packet: &[u8], name: &mut Vec<u8>) -> Result<(), ()> {
	do_read_wire_packet_labels(inp, wire_packet, name, 255)
}

pub(crate) fn read_wire_packet_name_bytes(inp: &mut &[u8], wire_packet: &[u8]) -> Result<Vec<u8>, ()> {
	let mut name = Vec::with_capacity(1024);
	read_wire_packet_labels(inp, wire_packet, &mut name)?;
	if name.len() > 255 { return Err(()); }
	Ok(name)
}

pub(crate) fn read_wire_packet_name(inp: &mut &[u8], wire_packet: &[u8]) -> Result<Name, ()> {
	let mut name = Vec::with_capacity(1024);
	read_wire_packet_labels(inp, wire_packet, &mut name)?;
	String::from_utf8(name).map_err(|_| ())?.try_into()
}

pub(crate) trait Writer { fn write(&mut self, buf: &[u8]); }
impl Writer for Vec<u8> { fn write(&mut self, buf: &[u8]) { self.extend_from_slice(buf); } }
impl Writer for QueryBuf { fn write(&mut self, buf: &[u8]) { self.extend_from_slice(buf); } }
#[cfg(feature = "validation")]
impl Writer for crate::crypto::hash::Hasher { fn write(&mut self, buf: &[u8]) { self.update(buf); } }
pub(crate) fn write_name<W: Writer>(out: &mut W, name: &str) {
	write_name_without_case_modification(out, &name.to_ascii_lowercase().as_bytes());
}
pub(crate) fn write_name_without_case_modification<W: Writer>(out: &mut W, name_bytes: &[u8]) {
	if name_bytes == b"." {
		out.write(&[0]);
	} else {
		for label in name_bytes.split(|c| *c == b'.') {
			out.write(&(label.len() as u8).to_be_bytes());
			out.write(label);
		}
	}
}
pub(crate) fn name_len(name: &Name) -> u16 {
	name_bytes_len(name.as_str().as_bytes())
}
pub(crate) fn name_bytes_len(name: &[u8]) -> u16 {
	if name == b"." {
		1
	} else {
		let mut res = 0;
		for label in name.split(|c| *c == b'.') {
			res += 1 + label.len();
		}
		res as u16
	}
}

pub(crate) fn parse_wire_packet_rr(inp: &mut &[u8], wire_packet: &[u8]) -> Result<(RR, u32), ()> {
	let name = read_wire_packet_name(inp, wire_packet)?;
	let ty = read_u16(inp)?;
	let class = read_u16(inp)?;
	if class != 1 { return Err(()); } // We only support the INternet
	let ttl = read_u32(inp)?;
	let data_len = read_u16(inp)? as usize;
	if inp.len() < data_len { return Err(()); }
	let data = &inp[..data_len];
	*inp = &inp[data_len..];

	let rr = match ty {
		A::TYPE => RR::A(A::read_from_data(name, data, wire_packet)?),
		AAAA::TYPE => RR::AAAA(AAAA::read_from_data(name, data, wire_packet)?),
		NS::TYPE => RR::NS(NS::read_from_data(name, data, wire_packet)?),
		Txt::TYPE => RR::Txt(Txt::read_from_data(name, data, wire_packet)?),
		CName::TYPE => RR::CName(CName::read_from_data(name, data, wire_packet)?),
		DName::TYPE => RR::DName(DName::read_from_data(name, data, wire_packet)?),
		TLSA::TYPE => RR::TLSA(TLSA::read_from_data(name, data, wire_packet)?),
		DnsKey::TYPE => RR::DnsKey(DnsKey::read_from_data(name, data, wire_packet)?),
		DS::TYPE => RR::DS(DS::read_from_data(name, data, wire_packet)?),
		RRSig::TYPE => RR::RRSig(RRSig::read_from_data(name, data, wire_packet)?),
		NSec::TYPE => RR::NSec(NSec::read_from_data(name, data, wire_packet)?),
		NSec3::TYPE => RR::NSec3(NSec3::read_from_data(name, data, wire_packet)?),
		_ => return Err(()),
	};
	Ok((rr, ttl))
}

pub(crate) fn parse_rr(inp: &mut &[u8]) -> Result<RR, ()> {
	parse_wire_packet_rr(inp, &[]).map(|(rr, _)| rr)
}

/// Parse a stream of [`RR`]s from the format described in [RFC 9102](https://www.rfc-editor.org/rfc/rfc9102.html).
///
/// Note that this is only the series of `AuthenticationChain` records, and does not read the
/// `ExtSupportLifetime` field at the start of a `DnssecChainExtension`.
pub fn parse_rr_stream(mut inp: &[u8]) -> Result<Vec<RR>, ()> {
	let mut res = Vec::with_capacity(32);
	while !inp.is_empty() {
		let rr = parse_rr(&mut inp)?;
		#[cfg(fuzzing)]
		let _ = rr.json(); // Make sure we can JSON the RR when fuzzing, cause why not
		res.push(rr);
	}
	Ok(res)
}

/// Writes the given resource record in its wire encoding to the given `Vec`.
///
/// An [RFC 9102](https://www.rfc-editor.org/rfc/rfc9102.html) `AuthenticationChain` is simply a
/// series of such records with no additional bytes in between.
pub fn write_rr<RR: Record>(rr: &RR, ttl: u32, out: &mut Vec<u8>) {
	write_name(out, rr.name());
	out.extend_from_slice(&rr.ty().to_be_bytes());
	out.extend_from_slice(&1u16.to_be_bytes()); // The INternet class
	out.extend_from_slice(&ttl.to_be_bytes());
	rr.write_u16_len_prefixed_data(out);
}
