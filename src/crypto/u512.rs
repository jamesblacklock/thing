use std::fmt;
use crate::{
	err::*,
	common::*,
	sha256::*,
};
use super::u256::*;

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct u512([u64; 8]);

impl u512 {
	pub const fn from_u256_raw(raw: [u64; 4]) -> Self {
		u512([raw[0], raw[1], raw[2], raw[3], 0, 0, 0, 0])
	}

	pub fn truncate(self) -> u256 {
		u256::from_raw([self.0[3], self.0[2], self.0[1], self.0[0]])
	}

	pub fn as_bytes<'a>(&'a self) -> &'a [u8] {
		unsafe { std::slice::from_raw_parts(std::mem::transmute(&self.0[0]), 64) }
	}

	pub fn is_odd(&self) -> bool {
		return self.0[0] & 1 != 0;
	}

	pub fn overflowing_add(self, other: u512) -> (u512, bool) {
		let mut result = u512::default();
		let mut last_carry = 0;
		for i in 0..self.0.len() {
			let (n, carry1) = self.0[i].overflowing_add(other.0[i]);
			let (n, carry2) = n.overflowing_add(last_carry);
			result.0[i] = n;
			last_carry = (carry1 || carry2) as u64;
		}

		(result, last_carry != 0)
	}

	pub fn overflowing_sub(self, other: u512) -> (u512, bool) {
		let mut result = u512::default();
		let mut last_borrow = 0;
		for i in 0..self.0.len() {
			let (n, borrow1) = self.0[i].overflowing_sub(other.0[i]);
			let (n, borrow2) = n.overflowing_sub(last_borrow);
			result.0[i] = n;
			last_borrow = (borrow1 || borrow2) as u64;
		}

		(result, last_borrow != 0)
	}

	pub fn div_with_remainder(self, other: u512) -> (u512, u512) {
		if other == 0.into() {
			panic!("divide by zero");
		} else if other == 1.into() {
			return (self, 0.into());
		} else if other > self {
			return (0.into(), self);
		}

		let mut acc = other;
		let mut next_acc = acc + acc;
		let mut count = u512::from(1);
		let mut powers = vec![(acc, 1.into())];
		while next_acc < self {
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

	pub fn pow(self, other: u512) -> u512 {
		self.pow_impl(other, None)
	}
	
	pub fn pow_mod(self, other: u512, modulo: u512) -> u512 {
		self.pow_impl(other, Some(modulo))
	}

	fn pow_impl(self, other: u512, modulo: Option<u512>) -> u512 {
		let mut powers = vec![(self, 1.into())];
		let mut acc = self;
		let mut count = u512::from(1);
		let mut next_count = u512::from(2);
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
}

impl Default for u512 {
	fn default() -> u512 {
		u512([0; 8])
	}
}

impl From<u64> for u512 {
	fn from(n: u64) -> u512 {
		u512([n, 0, 0, 0, 0, 0, 0, 0])
	}
}

impl From<&str> for u512 {
	fn from(s: &str) -> Self {
		u256::from(s).extend()
	}
}

impl std::ops::Add for u512 {
	type Output = u512;

	fn add(self, other: u512) -> u512 {
		let (result, _) = self.overflowing_add(other);
		result
	}
}

impl std::ops::Sub for u512 {
	type Output = u512;

	fn sub(self, other: u512) -> u512 {
		let (result, _) = self.overflowing_sub(other);
		result
	}
}

impl std::ops::Mul for u512 {
	type Output = u512;
	fn mul(self, other: u512) -> u512 {
		let mut powers = vec![(self, 1.into())];
		let mut acc = self;
		let mut count = u512::from(1);
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

impl std::ops::Div for u512 {
	type Output = u512;

	fn div(self, other: u512) -> u512 {
		let (n, _)  = self.div_with_remainder(other);
		n
	}
}

impl std::ops::Rem for u512 {
	type Output = u512;

	fn rem(self, other: u512) -> u512 {
		let (_, n) = self.div_with_remainder(other);
		n
	}
}

impl std::ops::Shl<u8> for u512 {
	type Output = u512;
	
	fn shl(self, bits: u8) -> u512 {
		let mut result = self;
		let mut count = 0;
		let len = self.0.len();
		while count + 64 <= bits {
			for i in 1..len {
				result.0[len-i] = result.0[len-i-1];
			}
			result.0[0] = 0;
			count += 64;
		}
		if count < bits {
			let remaining = bits - count;
			let mask = !(0xffffffffffffffffu64 >> remaining);
			for i in 1..len {
				result.0[len-i] = (result.0[len-i] << remaining) | ((result.0[len-i-1] & mask) >> 64 - remaining);
			}
			result.0[0] = result.0[0] << remaining;
		}
		result
	}
}

impl std::ops::Shr<u8> for u512 {
	type Output = u512;
	
	fn shr(self, bits: u8) -> u512 {
		let mut result = self;
		let mut count = 0;
		let len = self.0.len();
		while count + 64 <= bits {
			for i in 0..len-1 {
				result.0[i] = result.0[i+1];
			}
			result.0[len-1] = 0;
			count += 64;
		}
		if count < bits {
			let remaining = bits - count;
			let mask = !(0xffffffffffffffffu64 << remaining);
			for i in 0..len-1 {
				result.0[i] = (result.0[i] >> remaining) | ((result.0[i+1] & mask) << 64 - remaining);
			}
			result.0[len-1] = result.0[len-1] >> remaining;
		}

		result
	}
}

impl std::cmp::Ord for u512 {
	fn cmp(&self, other: &u512) -> std::cmp::Ordering {
		for (l, r) in self.0.iter().copied().zip(other.0).rev() {
			if l != r {
				return l.cmp(&r)
			}
		}
		std::cmp::Ordering::Equal
	}
}

impl std::cmp::PartialOrd for u512 {
	fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
		Some(self.cmp(other))
	}
}

impl fmt::Debug for u512 {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", bytes_to_hex_le(self.as_bytes()))
	}
}

impl fmt::Display for u512 {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", bytes_to_hex_le(self.as_bytes()))
	}
}


#[test]
fn test_arithmetic() {
	assert!(u512::from(12746 + 91741) == u512::from(12746) + u512::from(91741));
	assert!(u512::from(12746 * 91741) == u512::from(12746) * u512::from(91741));
	assert!(
		(u512::from("bb9a2a8b89f893001028bc78239263765deadbeef00183565261712567dddddd") *
		u512::from("16247672677231782376dbdbdbdbdbd91723787aaaccacac0001928938432736")).truncate() ==
		u256::from("547f88cc7bafe691df998b5382332dd9be595b049f00919e006e0d951e70779e"));
	assert!(
		u512::from("0000000000000000000000000000028c787be787b787bd787182732873222222") << 4 ==
		u512::from("000000000000000000000000000028c787be787b787bd7871827328732222220"));
	assert!(
		u512::from("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee") >> 128 ==
		u512::from("00000000000000000000000000000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"));
	assert!(
		u512::from("0000000000000000000000000000187236471892734617892374617829873467") >> 17 ==
		u512::from("000000000000000000000000000000000c391b238c4939a30bc491ba30bc14c3"));
	assert!(u512::from(2).pow(10.into()) == 1024.into());
	assert!(
		u512::from(0xffffffffffffffffu64).pow(4.into()) ==
		"fffffffffffffffc0000000000000005fffffffffffffffc0000000000000001".into());
	assert!(
		u512::from(1781).pow(47001.into()).truncate() ==
		"c369fec67afdbf59284fd836d84f138c5342dc52a45c8cf443f4668ae16b3595".into());
	assert!(
		(u512::from("00000000000000000000000000009187f891827489f8789bdbd289e89a98deef") -
		u512::from("0000000000000000000ff982789feeeaadbcbde78a76d787c67829376789d97d")).truncate() ==
		u256::from("fffffffffffffffffff0067d8760a29d4ad4c48cff81a114155a60b1330f0572"));
	assert!(
		u512::from("0000062374985273465728937456278374652783deadbeefdeadbeefdeadbeef") -
		u512::from("0000000000000000000000000000000000000000000000005273657287abcdef") ==
		u512::from("0000062374985273465728937456278374652783deadbeef8c3a597d5701f100"));
	assert!(
		u512::from("0000000000000000010000000000000000000123856276386abababdefaaa334") / 
		u512::from("00000000000000000000000000000000000000000000010000727272111000bb") ==
		u512::from("000000000000000000000000000000000000ffff8d8dc118f9e0a95c57a8194c"));
	assert!(
		u512::from("0000000000000000000000008756234895623478527364572893746527839475") %
		u512::from("0000000000000000000000000000000000378491723647283746713457163456") ==
		u512::from("00000000000000000000000000000000002a26830d0b01fcda67f4eeb0c70dcb"));
}