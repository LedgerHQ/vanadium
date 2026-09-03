pub(crate) const fn unhex<const N: usize>(s: &str) -> [u8; N] {
	let mut res = [0; N];
	if s.len() != res.len() * 2 {
		panic!("Bad length strin");
	}

	let mut i = 0;
	while i < N * 2 {
		let mut j = 0;
		let mut b = 0;
		while j < 2 {
			b <<= 4;
			b |= match s.as_bytes()[i] {
				b'0' => 0x0,
				b'1' => 0x1,
				b'2' => 0x2,
				b'3' => 0x3,
				b'4' => 0x4,
				b'5' => 0x5,
				b'6' => 0x6,
				b'7' => 0x7,
				b'8' => 0x8,
				b'9' => 0x9,
				b'a'|b'A' => 0xa,
				b'b'|b'B' => 0xb,
				b'c'|b'C' => 0xc,
				b'd'|b'D' => 0xd,
				b'e'|b'E' => 0xe,
				b'f'|b'F' => 0xf,
				_ => panic!("Invalid hex character"),
			};
			i += 1;
			j += 1;
		}
		res[i / 2 - 1] = b;
	}

	res
}
