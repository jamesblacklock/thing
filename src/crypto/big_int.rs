use std::fmt;

#[allow(non_camel_case_types)]
pub type u256 = BigInt<4>;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BigInt<const W: usize>([u64; W]);

impl <const W: usize> From<u64> for BigInt<W> { fn from(n: u64) -> BigInt<W> { Self::from_u64(n as u64) } }

impl <const W: usize> BigInt<W> {
	pub const fn from_raw_le(raw: [u64; W]) -> Self {
		BigInt(raw)
	}

	pub fn resize<const X: usize>(self) -> BigInt<X> {
		let mut arr = [0; X];
		for i in 0..(std::cmp::min(X, W)) {
			arr[i] = self.0[i];
		}
		BigInt(arr)
	}

	pub fn bit(&self, b: usize) -> bool {
		if b >= W*64 {
			false
		} else {
			self.0[b/64] & 1 << b % 64 != 0
		}
	}

	pub fn is_odd(&self) -> bool {
		self.0[0] & 1 != 0
	}

	pub fn mod_inv(self, modulo: Self) -> Self {
		self.pow_mod(modulo - 2.into(), modulo)
	}

	pub fn div_with_remainder(self, other: Self) -> (Self, Self) {
		if other == 0.into() {
			panic!("divide by zero");
		} else if other == 1.into() {
			return (self, 0.into());
		} else if other > self {
			return (0.into(), self);
		}

		let mut acc = other;
		let mut next_acc = acc + acc;
		let mut count = Self::from(1);
		let mut powers = vec![(acc, 1.into())];
		while next_acc > acc && next_acc < self {
			acc = next_acc;
			count = count + count;
			powers.push((acc, count));
			next_acc = acc + acc;
		}
		let (mut n, mut power) = powers.pop().unwrap();
		while acc < self {
			next_acc = acc + n;
			if next_acc > acc && next_acc <= self {
				count = count + power;
				acc = next_acc;
			} else if powers.len() == 0 {
				return (count, self - acc);
			} else {
				(n, power) = powers.pop().unwrap();
			}
		}
		assert!(acc == self);
		(count, 0.into())
	}

	pub fn fast_rem(self, modulo: Self) -> Self {
		let result = if self >= modulo {
			self - modulo
		} else {
			self
		};

		assert!(result < modulo);
		result
	}

	pub fn overflowing_add(self, other: Self) -> (Self, bool) {
		let mut result = Self::default();
		let mut last_carry = 0;
		for i in 0..W {
			let (n, carry1) = self.0[i].overflowing_add(other.0[i]);
			let (n, carry2) = n.overflowing_add(last_carry);
			result.0[i] = n;
			last_carry = (carry1 || carry2) as u64;
		}

		(result, last_carry != 0)
	}

	pub fn overflowing_sub(self, other: Self) -> (Self, bool) {
		let mut result = Self::default();
		let mut last_borrow = 0;
		for i in 0..W {
			let (n, borrow1) = self.0[i].overflowing_sub(other.0[i]);
			let (n, borrow2) = n.overflowing_sub(last_borrow);
			result.0[i] = n;
			last_borrow = (borrow1 || borrow2) as u64;
		}
		(result, last_borrow != 0)
	}

	pub fn pow(self, other: Self) -> Self {
		let mut a = self;
		let mut res = Self::from(1);
		for b in 0..(W*64) {
			if other.bit(b) { res = res * a; }
			a = a * a;
		}
		return res;
	}
	
	pub fn pow_mod(self, other: Self, modulo: Self) -> Self {
		let (mut a, m) = (self, modulo);
		a = a % m;
		let mut res = Self::from(1);

		for b in 0..(W*64) {
			if other.bit(b) { res = res.mul_mod(a, m); }
			a = a.mul_mod(a, m);
		}
		return res;
	}

	pub fn add_mod(self, other: Self, modulo: Self) -> Self {
		let (res, carry) = self.overflowing_add(other);
		if carry || res > modulo {
			res - modulo
		} else {
			res
		}
	}

	pub fn sub_mod(self, other: Self, modulo: Self) -> Self {
		if other > self {
			self - other + modulo
		} else {
			self - other
		}
	}

	pub fn mul_mod(self, other: Self, modulo: Self) -> Self {
		let mut n = self;
		let mut r: Self = 0.into();
		for b in 0..(W*64) {
			if other.bit(b) { r = r.add_mod(n, modulo) }
			n = n.add_mod(n, modulo);
		}
		r
	}

	fn fmt_hex(&self, f: &mut fmt::Formatter, upper: bool, print_leading_zeros: bool) -> fmt::Result {
		if !print_leading_zeros && *self == 0.into() {
			return write!(f, "0");
		}
		let mut chars = Vec::new();
		let digits = if upper {
			['0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F']
		} else {
			['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
		};
		let mut leading_zeros = true;
		for n64 in self.0.iter().copied().rev() {
				for b in n64.to_be_bytes() {
					if print_leading_zeros || !(leading_zeros && b & 0xf0 == 0) {
						leading_zeros = leading_zeros && b & 0xf0 == 0;
						chars.push(digits[(b >> 4) as usize]);
					}
					if print_leading_zeros || !(leading_zeros && b & 0x0f == 0) {
						leading_zeros = leading_zeros && b & 0x0f == 0;
						chars.push(digits[(b & 0xf) as usize]);
					}
			}
		}
		write!(f, "{}", chars.iter().collect::<String>())
	}

	pub fn to_f64(&self) -> f64 {
		let mut a = 0.0;
		for b in (0..(W*64)).rev() {
			a *= 2.0;
			if self.bit(b) {
				a += 1.0;
			}
		}
		a
	}

	pub fn from_f64(n: f64) -> Self {
		assert!(n.is_finite() && n >= 0.0);

		let bits = n.to_bits();
		let mut exp: i16 = ((bits >> 52) & 0x7ff) as i16;
		let mantissa = if exp == 0 {
			(bits & 0xfffffffffffff) << 1
		} else {
			(bits & 0xfffffffffffff) | 0x10000000000000
		};
		exp -= 1023 + 52;

		if exp < 0 {
			Self::from_u64(mantissa) >> i16::abs(exp) as u64
		} else {
			Self::from_u64(mantissa) << exp as u64
		}
	}


	pub fn from_u64(n: u64) -> Self {
		let mut result = BigInt([0; W]);
		result.0[0] = n;
		result
	}

	pub fn hex(s: &str) -> Self {
		let bytes = crate::common::hex_to_bytes_le(s).unwrap();
		let mut arr = [0u64; W];
		for (i, chunk) in bytes.chunks(8).enumerate() {
			let mut q = 0u64;
			for &b in chunk.iter().rev() {
				q = (q << 8) | b as u64;
			}
			arr[i] = q;
		}
		Self(arr)
	}

	pub fn dec(s: &str) -> Self {
		let mut acc = Self::default();
		for c in s.chars() {
			if !('0'..='9').contains(&c) {
				panic!("invalid decimal character in string: {}", c);
			}
			let n = c as u64 - '0' as u64;
			acc = acc * 10.into() + n.into()
		}
		acc
	}

	pub fn as_bytes<'a>(&'a self) -> &'a[u8] {
		unsafe { std::slice::from_raw_parts(std::mem::transmute(&self.0[0]), W * 8)}
	}
}

impl <const W: usize> Default for BigInt<W> {
	fn default() -> Self {
		Self([0; W])
	}
}

impl <const W: usize> std::ops::Add for BigInt<W> {
	type Output = Self;
	fn add(self, other: Self) -> Self {
		self.overflowing_add(other).0
	}
}

impl <const W: usize> std::ops::Sub for BigInt<W> {
	type Output = Self;
	fn sub(self, other: Self) -> Self {
		self.overflowing_sub(other).0
	}
}

impl <const W: usize> std::ops::Mul for BigInt<W> {
	type Output = Self;
	fn mul(self, other: Self) -> Self {
		let mut n = self;
		let mut r = 0.into();
		for b in 0..(W*64) {
			if other.bit(b) { r = r + n }
			n = n + n;
		}
		r
	}
}

impl <const W: usize> std::ops::Div for BigInt<W> {
	type Output = Self;
	fn div(self, other: Self) -> Self {
		self.div_with_remainder(other).0
	}
}

impl <const W: usize> std::ops::Rem for BigInt<W> {
	type Output = Self;
	fn rem(self, other: Self) -> Self {
		self.fast_rem(other)
		// self.div_with_remainder(other).1
	}
}

impl <const W: usize> std::ops::Shl<u64> for BigInt<W> {
	type Output = Self;
	
	fn shl(self, bits: u64) -> Self {
		let mut result = self;
		let mut count = 0;
		while count + 64 <= bits {
			for i in 1..W {
				result.0[W-i] = result.0[W-i-1];
			}
			result.0[0] = 0;
			count += 64;
		}
		if count < bits {
			let remaining = bits - count;
			let mask = !(0xffffffffffffffffu64 >> remaining);
			for i in 1..W {
				result.0[W-i] = (result.0[W-i] << remaining) | ((result.0[W-i-1] & mask) >> 64 - remaining);
			}
			result.0[0] = result.0[0] << remaining;
		}
		result
	}
}

impl <const W: usize> std::ops::Shr<u64> for BigInt<W> {
	type Output = Self;
	
	fn shr(self, bits: u64) -> Self {
		let mut result = self;
		let mut count = 0;
		while count + 64 <= bits {
			for i in 0..W-1 {
				result.0[i] = result.0[i+1];
			}
			result.0[W-1] = 0;
			count += 64;
		}
		if count < bits {
			let remaining = bits - count;
			let mask = !(0xffffffffffffffffu64 << remaining);
			for i in 0..W-1 {
				result.0[i] = (result.0[i] >> remaining) | ((result.0[i+1] & mask) << 64 - remaining);
			}
			result.0[W-1] = result.0[W-1] >> remaining;
		}

		result
	}
}

impl <const W: usize> std::cmp::Ord for BigInt<W> {
	fn cmp(&self, other: &Self) -> std::cmp::Ordering {
		for (l, r) in self.0.iter().copied().zip(other.0).rev() {
			if l != r {
				return l.cmp(&r)
			}
		}
		std::cmp::Ordering::Equal
	}
}

impl <const W: usize> std::cmp::PartialOrd for BigInt<W> {
	fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
		Some(self.cmp(other))
	}
}

impl <const W: usize> fmt::Debug for BigInt<W> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		fmt::Display::fmt(self, f)
	}
}

impl <const W: usize> fmt::Display for BigInt<W> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		if *self == 0.into() {
			return write!(f, "0");
		}
		let mut chars = Vec::new();
		let mut temp = *self;
		while temp > 0.into() {
			let rem;
			(temp, rem) = temp.div_with_remainder(10.into());
			chars.push((rem.0[0] as u8 + '0' as u8) as char);
		}
		write!(f, "{}", chars.iter().rev().collect::<String>())
	}
}

impl <const W: usize> fmt::LowerHex for BigInt<W> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		self.fmt_hex(f, false, false)
	}
}

impl <const W: usize> fmt::UpperHex for BigInt<W> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		self.fmt_hex(f, true, false)
	}
}

impl From<[u8; 32]> for u256 {
	fn from(bytes: [u8; 32]) -> u256 {
		Self(unsafe { std::mem::transmute(bytes) })
	}
}

#[test]
fn arithmetic() {
	assert!(u256::dec("23489572932348752890384578248572839485") * u256::dec("23487562237458920834537834562") ==
		u256::dec("551712806179871778515292239903303072204368058405080230739511280570"));
	assert!(BigInt::<8>::from(12746 + 91741) == BigInt::<8>::from(12746) + BigInt::<8>::from(91741));
	assert!(BigInt::<8>::from(12746 * 91741) == BigInt::<8>::from(12746) * BigInt::<8>::from(91741));
	assert!(
		(BigInt::<8>::hex("bb9a2a8b89f893001028bc78239263765deadbeef00183565261712567dddddd") *
		BigInt::<8>::hex("16247672677231782376dbdbdbdbdbd91723787aaaccacac0001928938432736")).resize() == 
		u256::hex("547f88cc7bafe691df998b5382332dd9be595b049f00919e006e0d951e70779e"));
	assert!(
		BigInt::<8>::hex("28c787be787b787bd787182732873222222") << 4 ==
		BigInt::<8>::hex("28c787be787b787bd7871827328732222220"));
	assert!(
		BigInt::<8>::hex("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee") >> 128 ==
		BigInt::<8>::hex("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"));
	assert!(
		BigInt::<8>::hex("187236471892734617892374617829873467") >> 17 ==
		BigInt::<8>::hex("c391b238c4939a30bc491ba30bc14c3"));
	assert!(BigInt::<8>::from(2).pow(10.into()) == 1024.into());
	assert!(
		BigInt::<8>::from(0xffffffffffffffffu64).pow(4.into()) ==
		BigInt::<8>::hex("fffffffffffffffc0000000000000005fffffffffffffffc0000000000000001"));
	assert!(
		BigInt::<8>::from(1781).pow(47001.into()).resize() ==
		u256::hex("c369fec67afdbf59284fd836d84f138c5342dc52a45c8cf443f4668ae16b3595"));
	assert!(
		(BigInt::<8>::hex("00000000000000000000000000009187f891827489f8789bdbd289e89a98deef") -
		BigInt::<8>::hex("0000000000000000000ff982789feeeaadbcbde78a76d787c67829376789d97d")).resize() ==
		u256::hex("fffffffffffffffffff0067d8760a29d4ad4c48cff81a114155a60b1330f0572"));
	assert!(
		BigInt::<8>::hex("0000062374985273465728937456278374652783deadbeefdeadbeefdeadbeef") -
		BigInt::<8>::hex("0000000000000000000000000000000000000000000000005273657287abcdef") ==
		BigInt::<8>::hex("0000062374985273465728937456278374652783deadbeef8c3a597d5701f100"));
	assert!(
		BigInt::<8>::hex("0000000000000000010000000000000000000123856276386abababdefaaa334") / 
		BigInt::<8>::hex("00000000000000000000000000000000000000000000010000727272111000bb") ==
		BigInt::<8>::hex("000000000000000000000000000000000000ffff8d8dc118f9e0a95c57a8194c"));
	assert!(
		BigInt::<8>::hex("0000000000000000000000008756234895623478527364572893746527839475") %
		BigInt::<8>::hex("0000000000000000000000000000000000378491723647283746713457163456") ==
		BigInt::<8>::hex("00000000000000000000000000000000002a26830d0b01fcda67f4eeb0c70dcb"));
}