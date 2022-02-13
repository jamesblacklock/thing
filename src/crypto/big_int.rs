use std::fmt;

pub const U256: usize = 4;
pub type u256 = UnsignedBigInt<U256>;
pub const I256: usize = 4;
pub type i256 = SignedBigInt<I256>;
pub const U512: usize = 8;
pub type u512 = UnsignedBigInt<U512>;
pub const I512: usize = 8;
pub type i512 = SignedBigInt<I512>;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UnsignedBigInt<const W: usize>([u64; W]);

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SignedBigInt<const W: usize>(UnsignedBigInt<W>);

impl <const W: usize> From<u64> for UnsignedBigInt<W> { fn from(n: u64) -> UnsignedBigInt<W> { Self::from_u64(n as u64) } }
impl <const W: usize> From<i64> for   SignedBigInt<W> { fn from(n: i64) ->   SignedBigInt<W> { Self::from_i64(n as i64) } }

impl <const W: usize> UnsignedBigInt<W> {
	pub const fn from_raw_le(raw: [u64; W]) -> Self {
		UnsignedBigInt(raw)
	}

	pub fn to_signed(self) -> SignedBigInt<W> {
		SignedBigInt(self)
	}

	pub fn resize<const X: usize>(self) -> UnsignedBigInt<X> {
		let mut arr = [0; X];
		for i in 0..(std::cmp::min(X, W)) {
			arr[i] = self.0[i];
		}
		UnsignedBigInt(arr)
	}

	pub fn resize_signed<const X: usize>(self) -> SignedBigInt<X> {
		self.to_signed().resize()
	}

	pub fn truncate(self) -> u64 {
		self.0[0]
	}

	// pub fn as_bytes<'a>(&'a self) -> &'a [u8] {
	// 	unsafe { std::slice::from_raw_parts(std::mem::transmute(&self.0[0]), 8 * W) }
	// }

	pub fn is_odd(&self) -> bool {
		self.0[0] & 1 != 0
	}

	pub fn gcd(self, other: Self) -> Self {
		let (mut a, mut b) = (self, other);
		while b != 0.into() {
			(a, b) = (b, a % b);
		}
		a
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
		assert!(acc - self == 0.into());
		(count, 0.into())
	}

	pub fn pow(self, other: Self) -> Self {
		self.pow_impl(other, None)
	}
	
	pub fn pow_mod(self, other: Self, modulo: Self) -> Self {
		self.pow_impl(other, Some(modulo))
	}

	fn pow_impl(self, other: Self, modulo: Option<Self>) -> Self {
		let mut powers = vec![(self, 1.into())];
		let mut acc = self;
		let mut count = Self::from(1);
		let mut next_count = Self::from(2);
		while next_count > count && next_count < other {
			count = next_count;
			acc = acc * acc;
			if let Some(modulo) = modulo { acc = acc % modulo; }
			powers.push((acc, count));
			next_count = count * 2.into();
		}
		let (mut n, mut power) = powers.pop().unwrap();
		while count < other {
			next_count = count + power;
			if next_count > count && next_count <= other {
				acc = acc * n;
				if let Some(modulo) = modulo { acc = acc % modulo; }
				count = next_count;
			} else if powers.len() == 0 {
				break;
			} else {
				(n, power) = powers.pop().unwrap();
			}
		}
		acc
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
						// println!("{}", digits[(b >> 4) as usize]);
						chars.push(digits[(b >> 4) as usize]);
					}
					if print_leading_zeros || !(leading_zeros && b & 0x0f == 0) {
						leading_zeros = leading_zeros && b & 0x0f == 0;
						// println!("{}", digits[(b & 0xf) as usize]);
						chars.push(digits[(b & 0xf) as usize]);
					}
			}
		}
		write!(f, "{}", chars.iter().collect::<String>())
	}

	pub fn from_u64(n: u64) -> Self {
		let mut result = UnsignedBigInt([0; W]);
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
}

impl <const W: usize> Default for UnsignedBigInt<W> {
	fn default() -> Self {
		Self([0; W])
	}
}

impl <const W: usize> std::ops::Add for UnsignedBigInt<W> {
	type Output = Self;

	fn add(self, other: Self) -> Self {
		let (result, _) = self.overflowing_add(other);
		result
	}
}

impl <const W: usize> std::ops::Sub for UnsignedBigInt<W> {
	type Output = Self;
	fn sub(self, other: Self) -> Self {
		let (result, _) = self.overflowing_sub(other);
		result
	}
}

impl <const W: usize> std::ops::Mul for UnsignedBigInt<W> {
	type Output = Self;
	fn mul(self, other: Self) -> Self {
		if self == 0.into() || other == 0.into() {
			return 0.into();
		}
		let mut powers = vec![(self, 1.into())];
		let mut acc = self;
		let mut count = Self::from(1);
		let mut next_count = count + count;
		while next_count > count && next_count < other {
			count = next_count;
			acc = acc + acc;
			powers.push((acc, count));
			next_count = count + count;
		}
		let (mut n, mut power) = powers.pop().unwrap();
		while count < other {
			next_count = count + power;
			if next_count > count && next_count <= other {
				acc = acc + n;
				count = next_count;
			} else if powers.len() == 0 {
				break;
			} else {
				(n, power) = powers.pop().unwrap();
			}
		}
		acc
	}
}

impl <const W: usize> std::ops::Div for UnsignedBigInt<W> {
	type Output = Self;
	fn div(self, other: Self) -> Self {
		let (n, _)  = self.div_with_remainder(other);
		n
	}
}

impl <const W: usize> std::ops::Rem for UnsignedBigInt<W> {
	type Output = Self;
	fn rem(self, other: Self) -> Self {
		let (_, n) = self.div_with_remainder(other);
		n
	}
}

impl <const W: usize> std::ops::Shl<u64> for UnsignedBigInt<W> {
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

impl <const W: usize> std::ops::Shr<u64> for UnsignedBigInt<W> {
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

impl <const W: usize> std::cmp::Ord for UnsignedBigInt<W> {
	fn cmp(&self, other: &Self) -> std::cmp::Ordering {
		for (l, r) in self.0.iter().copied().zip(other.0).rev() {
			if l != r {
				return l.cmp(&r)
			}
		}
		std::cmp::Ordering::Equal
	}
}

impl <const W: usize> std::cmp::PartialOrd for UnsignedBigInt<W> {
	fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
		Some(self.cmp(other))
	}
}

impl <const W: usize> fmt::Debug for UnsignedBigInt<W> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		// self.fmt_hex(f, false, true)
		fmt::Display::fmt(self, f)
	}
}

impl <const W: usize> fmt::Display for UnsignedBigInt<W> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		if *self == 0.into() {
			return write!(f, "0");
		}
		let mut chars = Vec::new();
		let mut temp = *self;
		while temp > 0.into() {
			let rem;
			(temp, rem) = temp.div_with_remainder(10.into());
			chars.push((rem.truncate() as u8 + '0' as u8) as char);
		}
		write!(f, "{}", chars.iter().rev().collect::<String>())
	}
}

impl <const W: usize> fmt::LowerHex for UnsignedBigInt<W> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		self.fmt_hex(f, false, false)
	}
}

impl <const W: usize> fmt::UpperHex for UnsignedBigInt<W> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		self.fmt_hex(f, true, false)
	}
}

impl <const W: usize> SignedBigInt<W> {
	pub const fn from_raw_le(raw: [u64; W]) -> Self {
		Self(UnsignedBigInt(raw))
	}

	pub fn to_unsigned(self) -> UnsignedBigInt<W> {
		self.0
	}

	pub fn resize<const X: usize>(self) -> SignedBigInt<X> {
		let sign = if self >= 0.into() { 0 } else { 0xffffffff_ffffffff };
		let mut arr = [sign; X];
		for i in 0..(std::cmp::min(X, W)) {
			arr[i] = self.0.0[i];
		}
		SignedBigInt(UnsignedBigInt(arr))
	}

	pub fn truncate(self) -> i64 {
		self.0.0[0] as i64
	}

	pub fn sign(&self) -> bool {
		self.0.0.last().unwrap() >> 63 != 0
	}

	pub fn abs(&self) -> Self {
		if self.sign() {
			-*self
		} else {
			*self
		}
	}

	// pub fn as_bytes<'a>(&'a self) -> &'a [u8] {
	// 	self.0.as_bytes()
	// }

	pub fn is_odd(&self) -> bool {
		self.0.is_odd()
	}

	pub fn gcd(self, other: Self) -> Self {
		let (res, ..) = self.egcd(other);
		res
	}

	pub fn egcd(self, other: Self) -> (Self, Self, Self) {
		// adapted from: https://shirshak55.github.io/articles/gcd-in-rust/#extended-euclid-algorithm
		let (mut x, mut y) = (self, other);
		let (mut a0, mut a1, mut b0, mut b1) =
			(Self::from_i64(1), Self::from_i64(0), Self::from_i64(0), Self::from_i64(1)) ;
	
		while y != 0.into() {
			let (q, r) = (x / y, x % y);
			let (c, d) = (a0 - q * a1, b0 - q * b1);
			x = y;
			y = r;
			a0 = a1;
			a1 = c;
			b0 = b1;
			b1 = d;
		}
		(x, a0, b0)
	}

	pub fn mod_inv(self, other: Self) -> Option<Self> {
		let (d, x, _) = self.egcd(other);
		if d != 1.into() {
			dbg!(self, other, d, x);
			None
		} else if x < 0.into() {
			Some(other + x)
		} else {
			Some(x)
		}
	}

	pub fn modulo(self, other: Self) -> Self {
		let (_, rem) = self.div_with_remainder(other);
		if rem < 0.into() {
			other + rem
		} else {
			rem
		}
	}

	pub fn overflowing_add(self, other: Self) -> (Self, bool) {
		let (res, ovf) = self.0.overflowing_add(other.0);
		(Self(res), ovf)
	}

	pub fn overflowing_sub(self, other: Self) -> (Self, bool) {
		let (res, ovf) = self.0.overflowing_sub(other.0);
		(Self(res), ovf)
	}

	pub fn div_with_remainder(self, other: Self) -> (Self, Self) {
		let (res, rem) = self.abs().0.div_with_remainder(other.abs().0);
		let res = if self.sign() ^ other.sign() {
			-Self(res)
		} else {
			Self(res)
		};
		let rem = if self.sign() {
			-Self(rem)
		} else {
			Self(rem)
		};
		(res, rem)
	}

	pub fn pow(self, other: Self) -> Self {
		// if self.sign() && other.is_odd() {
		// 	-Self(self.abs().0.pow(other))
		// } else {
		// 	Self(self.abs().0.pow(other))
		// }
		Self(self.0.pow(other.0))
	}
	
	pub fn pow_mod(self, other: Self, modulo: Self) -> Self {
	// 	if self.sign() && other.is_odd() {
	// 		-Self(self.abs().0.pow_mod(other, modulo))
	// 	} else {
	// 		Self(self.abs().0.pow_mod(other, modulo))
	// 	}
		Self(self.0.pow_mod(other.0, modulo.0))
	}

	pub fn from_i64(n: i64) -> Self {
		let sign = if n >= 0 { 0 } else { 0xffffffff_ffffffff };
		let mut result = Self(UnsignedBigInt([sign; W]));
		result.0.0[0] = n as u64;
		result
	}

	pub fn hex(s: &str) -> Self {
		Self(UnsignedBigInt::hex(s))
	}

	pub fn dec(s: &str) -> Self {
		let (chars, sign) = if let Some('-') = s.chars().nth(0) {
			(&s[1..], true)
		} else {
			(s, false)
		};
		let mut res = Self(UnsignedBigInt::dec(chars));
		if sign {
			res = -res;
		}
		res
	}
}

impl <const W: usize> Default for SignedBigInt<W> {
	fn default() -> SignedBigInt<W> {
		Self(Default::default())
	}
}

impl <const W: usize> std::ops::Add for SignedBigInt<W> {
	type Output = Self;
	fn add(self, other: Self) -> Self {
		Self(self.0 + other.0)
	}
}

impl <const W: usize> std::ops::Sub for SignedBigInt<W> {
	type Output = Self;
	fn sub(self, other: Self) -> Self {
		Self(self.0 - other.0)
	}
}

impl <const W: usize> std::ops::Mul for SignedBigInt<W> {
	type Output = Self;
	fn mul(self, other: Self) -> Self {
		// let result = Self(self.abs().0 * other.abs().0);
		// if self.sign() ^ other.sign() {
		// 	-result
		// } else {
		// 	result
		// }
		Self(self.0 * other.0)
	}
}

impl <const W: usize> std::ops::Div for SignedBigInt<W> {
	type Output = Self;

	fn div(self, other: Self) -> Self {
		let result = Self(self.abs().0 / other.abs().0);
		if self.sign() ^ other.sign() {
			-result
		} else {
			result
		}
	}
}

impl <const W: usize> std::ops::Rem for SignedBigInt<W> {
	type Output = Self;

	fn rem(self, other: Self) -> Self {
		let (_, res) = self.div_with_remainder(other);
		res
	}
}

impl <const W: usize> std::ops::Shl<u64> for SignedBigInt<W> {
	type Output = Self;
	fn shl(self, bits: u64) -> Self {
		Self(self.0 << bits)
	}
}

impl <const W: usize> std::ops::Shr<u64> for SignedBigInt<W> {
	type Output = Self;
	fn shr(self, bits: u64) -> Self {
		let mut result = Self(self.0 >> bits);
		if self.sign() {
			let mut n = 1;
			while (n * 64) < bits as usize {
				result.0.0[W - n] = 0xffffffff_ffffffff;
				n += 1;
			}
			result.0.0[W - n] |= !(0xffffffff_ffffffffu64 >> (bits % 64));
		}
		result
	}
}

impl <const W: usize> std::cmp::Ord for SignedBigInt<W> {
	fn cmp(&self, other: &Self) -> std::cmp::Ordering {
		if self.sign() && !other.sign() {
			return std::cmp::Ordering::Less;
		} else if !self.sign() && other.sign() {
			return std::cmp::Ordering::Greater;
		}
		self.0.cmp(&other.0)
	}
}

impl <const W: usize> std::cmp::PartialOrd for SignedBigInt<W> {
	fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
		Some(self.cmp(other))
	}
}

impl <const W: usize> std::ops::Neg for SignedBigInt<W> {
	type Output = Self;
	fn neg(mut self) -> Self {
		for n in 0..self.0.0.len() {
			self.0.0[n] = !self.0.0[n];
		}
		self + 1.into()
	}
}

impl <const W: usize> fmt::Debug for SignedBigInt<W> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		// fmt::Debug::fmt(&self.0, f)
		fmt::Display::fmt(self, f)
	}
}

impl <const W: usize> fmt::Display for SignedBigInt<W> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		if self.sign() {
			write!(f, "-")?;
			fmt::Display::fmt(&(-*self).0, f)
		} else {
			fmt::Display::fmt(&self.0, f)
		}
	}
}

impl <const W: usize> fmt::LowerHex for SignedBigInt<W> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		fmt::LowerHex::fmt(&self.0, f)
	}
}

impl <const W: usize> fmt::UpperHex for SignedBigInt<W> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		fmt::UpperHex::fmt(&self.0, f)
	}
}


impl From<[u8; 32]> for u256 {
	fn from(bytes: [u8; 32]) -> u256 {
		Self(unsafe { std::mem::transmute(bytes) })
	}
}

impl From<[u8; 32]> for i256 {
	fn from(bytes: [u8; 32]) -> i256 {
		Self(unsafe { std::mem::transmute(bytes) })
	}
}


#[test]
fn test_arithmetic() {
	assert!(u256::dec("23489572932348752890384578248572839485") * u256::dec("23487562237458920834537834562").into() ==
		u256::dec("551712806179871778515292239903303072204368058405080230739511280570"));
	assert!(u512::from(12746 + 91741) == u512::from(12746) + u512::from(91741));
	assert!(u512::from(12746 * 91741) == u512::from(12746) * u512::from(91741));
	assert!(
		(u512::hex("bb9a2a8b89f893001028bc78239263765deadbeef00183565261712567dddddd") *
		u512::hex("16247672677231782376dbdbdbdbdbd91723787aaaccacac0001928938432736")).resize() == 
		u256::hex("547f88cc7bafe691df998b5382332dd9be595b049f00919e006e0d951e70779e"));
	assert!(
		u512::hex("28c787be787b787bd787182732873222222") << 4 ==
		u512::hex("28c787be787b787bd7871827328732222220"));
	assert!(
		u512::hex("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee") >> 128 ==
		u512::hex("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"));
	assert!(
		u512::hex("187236471892734617892374617829873467") >> 17 ==
		u512::hex("c391b238c4939a30bc491ba30bc14c3"));
	assert!(u512::from(2).pow(10.into()) == 1024.into());
	assert!(
		u512::from(0xffffffffffffffffu64).pow(4.into()) ==
		u512::hex("fffffffffffffffc0000000000000005fffffffffffffffc0000000000000001"));
	assert!(
		u512::from(1781).pow(47001.into()).resize() ==
		u256::hex("c369fec67afdbf59284fd836d84f138c5342dc52a45c8cf443f4668ae16b3595"));
	assert!(
		(u512::hex("00000000000000000000000000009187f891827489f8789bdbd289e89a98deef") -
		u512::hex("0000000000000000000ff982789feeeaadbcbde78a76d787c67829376789d97d")).resize() ==
		u256::hex("fffffffffffffffffff0067d8760a29d4ad4c48cff81a114155a60b1330f0572"));
	assert!(
		u512::hex("0000062374985273465728937456278374652783deadbeefdeadbeefdeadbeef") -
		u512::hex("0000000000000000000000000000000000000000000000005273657287abcdef") ==
		u512::hex("0000062374985273465728937456278374652783deadbeef8c3a597d5701f100"));
	assert!(
		u512::hex("0000000000000000010000000000000000000123856276386abababdefaaa334") / 
		u512::hex("00000000000000000000000000000000000000000000010000727272111000bb") ==
		u512::hex("000000000000000000000000000000000000ffff8d8dc118f9e0a95c57a8194c"));
	assert!(
		u512::hex("0000000000000000000000008756234895623478527364572893746527839475") %
		u512::hex("0000000000000000000000000000000000378491723647283746713457163456") ==
		u512::hex("00000000000000000000000000000000002a26830d0b01fcda67f4eeb0c70dcb"));
	assert!(
		u256::hex("8000000000000000000000000000000000000000000000000000000000000000").to_signed().resize() ==
		i512::hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8000000000000000000000000000000000000000000000000000000000000000"));
	assert!(i512::from(-201) < i512::from(-2));
	assert!(i512::from(201)  > i512::from(-2));
	assert!(i512::from(-201) < i512::from(2));
	assert!(i512::from(-2)   < i512::from(2));
	assert!((i512::from(-17) * i512::from(2)).0.0[0] == u64::MAX - (34 - 1));
	assert!((i512::from(422) * i512::from(-800)).0.0[0] == u64::MAX - (337600 - 1));
	assert!(
		i256::hex("8000000000000000000000000000b00000000000000000000000000000000000").resize::<I512>() >> 112 ==
		i256::hex("ffffffffffffffffffffffffffff8000000000000000000000000000b0000000").resize::<I512>());
}