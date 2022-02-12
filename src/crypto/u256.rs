use std::fmt;
use crate::{
	err::*,
	common::*,
	sha256::*,
};
use super::u512::*;

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct u256([u64; 4]);

impl u256 {
	pub const fn from_raw(raw: [u64; 4]) -> Self {
		u256([raw[3], raw[2], raw[1], raw[0]])
	}

	pub fn as_bytes<'a>(&'a self) -> &'a [u8] {
		unsafe { std::slice::from_raw_parts(std::mem::transmute(&self.0[0]), 32) }
	}

	pub fn extend(self) -> u512 {
		u512::from_u256_raw(self.0)
	}

	pub fn sign_extend(self) -> i512 {
		i512::from_u256_raw(self.0)
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
