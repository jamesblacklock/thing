use std::fmt;
use crate::{
	err::*,
	common::*,
	sha256::*,
};

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct u256([u64; 4]);

impl u256 {
	pub fn as_bytes<'a>(&'a self) -> &'a [u8] {
		unsafe { std::slice::from_raw_parts(std::mem::transmute(&self.0[0]), 32) }
	}

	pub fn overflowing_add(self, other: u256) -> (u256, bool) {
		let mut result = u256::default();
		let mut last_carry = 0;
		for i in 0..4 {
			let (n, carry1) = self.0[i].overflowing_add(other.0[i]);
			let (n, carry2) = n.overflowing_add(last_carry);
			result.0[i] = n;
			last_carry = (carry1 || carry2) as u64;
		}

		(result, last_carry != 0)
	}

	pub fn pow(self, other: u256) -> u256 {
		let mut powers = vec![(self, 1.into())];
		let mut acc = self;
		let mut count = u256::from(1);
		let mut next_count = u256::from(2);
		let mut next = acc * acc;
		while next > acc && next_count < other {
			acc = next;
			count = next_count;
			powers.push((acc, count));
			next = acc * acc;
			next_count = count * 2.into();
		}
		let (mut n, mut power) = powers.pop().unwrap();
		next_count = count + power;
		while count < other {
			if next_count <= other {
				acc = acc * n;
				count = next_count;
				next_count = next_count + power;
			} else if powers.len() == 0 {
				break;
			} else {
				(n, power) = powers.pop().unwrap();
				next_count = count + power;
			}
		}
		acc
	}
}

impl Default for u256 {
	fn default() -> u256 {
		u256([0;4])
	}
}

impl TryFrom<&[u8]> for u256 {
	type Error = Err;

	fn try_from(bytes: &[u8]) -> Result<Self> {
		if bytes.len() != 32 {
			return Err(Err::ValueError("cannot convert to u256".to_owned()));
		}
		let mut ints: [u64; 4] = [0; 4];
		ints.copy_from_slice(unsafe { std::slice::from_raw_parts(std::mem::transmute(&bytes[0]), 4) });
		Ok(u256(ints))
	}
}

impl From<Sha256> for u256 {
	fn from(sha256: Sha256) -> u256 {
		sha256.as_bytes().try_into().unwrap()
	}
}

impl From<[u8; 32]> for u256 {
	fn from(bytes: [u8; 32]) -> u256 {
		u256(unsafe { std::mem::transmute(bytes) })
	}
}

impl From<u64> for u256 {
	fn from(n: u64) -> u256 {
		u256([n, 0, 0, 0])
	}
}

impl From<&str> for u256 {
	fn from(s: &str) -> Self {
		if let Ok(n) = hex_to_bytes_le(s) {
			if let Ok(n) = u256::try_from(&*n) {
				return n;
			}
		}
		panic!("could not convert string to u256");
	}
}

impl std::ops::Add for u256 {
	type Output = u256;

	fn add(self, other: u256) -> u256 {
		let (result, _) = self.overflowing_add(other);
		result
	}
}

impl std::ops::Mul for u256 {
	type Output = u256;
	fn mul(self, other: u256) -> u256 {
		let mut powers = vec![(self, 1.into())];
		let mut count = u256::from(1);
		let mut acc = self;
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

impl std::ops::Shl<u8> for u256 {
	type Output = u256;
	
	fn shl(self, bits: u8) -> u256 {
		let mut result = self;
		let mut count = 0;
		while count + 64 <= bits {
			result.0[3] = result.0[2];
			result.0[2] = result.0[1];
			result.0[1] = result.0[0];
			result.0[0] = 0;
			count += 64;
		}
		if count < bits {
			let remaining = bits - count;
			let mask = !(0xffffffffffffffffu64 >> remaining);
			result.0[3] = (result.0[3] << remaining) | ((result.0[2] & mask) >> 64 - remaining);
			result.0[2] = (result.0[2] << remaining) | ((result.0[1] & mask) >> 64 - remaining);
			result.0[1] = (result.0[1] << remaining) | ((result.0[0] & mask) >> 64 - remaining);
			result.0[0] = result.0[0] << remaining;
		}

		result
	}
}

impl std::cmp::Ord for u256 {
	fn cmp(&self, other: &u256) -> std::cmp::Ordering {
		for (l, r) in self.0.iter().copied().zip(other.0).rev() {
			if l != r {
				return l.cmp(&r)
			}
		}
		std::cmp::Ordering::Equal
	}
}

impl std::cmp::PartialOrd for u256 {
	fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
		Some(self.cmp(other))
	}
}

impl fmt::Debug for u256 {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", bytes_to_hex_le(self.as_bytes()))
	}
}

impl fmt::Display for u256 {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", bytes_to_hex_le(self.as_bytes()))
	}
}


#[test]
fn test_arithmetic() {
	assert!(u256::from(12746 + 91741) == u256::from(12746) + u256::from(91741));
	assert!(u256::from(12746 * 91741) == u256::from(12746) * u256::from(91741));
	assert!(
		u256::from("bb9a2a8b89f893001028bc78239263765deadbeef00183565261712567dddddd") *
		u256::from("16247672677231782376dbdbdbdbdbd91723787aaaccacac0001928938432736") ==
		u256::from("547f88cc7bafe691df998b5382332dd9be595b049f00919e006e0d951e70779e"));
	assert!(
		u256::from("0000000000000000000000000000028c787be787b787bd787182732873222222") << 4 ==
		u256::from("000000000000000000000000000028c787be787b787bd7871827328732222220"));
	assert!(u256::from(2).pow(10.into()) == 1024.into());
	assert!(
		u256::from(0xffffffffffffffffu64).pow(4.into()) ==
		"fffffffffffffffc0000000000000005fffffffffffffffc0000000000000001".into());
}