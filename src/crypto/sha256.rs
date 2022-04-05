use std::fmt;

use crate::err::*;
use crate::common::hex_to_bytes_le;

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub struct Sha256 {
	digest: [u32; 8]
}

impl Sha256 {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		for i in self.as_bytes().iter().rev() {
			write!(f, "{:02x}", i)?;
		}

		Ok(())
	}

	pub fn as_words<'a>(&'a self) -> &'a[u32] {
		&self.digest
	}

	pub fn as_bytes<'a>(&'a self) -> &'a[u8] {
		unsafe { std::slice::from_raw_parts(std::mem::transmute(&self.digest[0]), 32)}
	}

	pub fn to_u256_be(&self) -> super::big_int::u256 {
		let b: [u8;32] = (&*self.as_bytes().iter().copied().rev().collect::<Vec<_>>()).try_into().unwrap();
		super::big_int::u256::from_raw_le(unsafe { std::mem::transmute(b) })
	}

	pub fn to_u256(&self) -> super::big_int::u256 {
		let b: [u8;32] = self.as_bytes().try_into().unwrap();
		super::big_int::u256::from_raw_le(unsafe { std::mem::transmute(b) })
	}
}

impl Default for Sha256 {
	fn default() -> Sha256 {
		Sha256 { digest: [0; 8] }
	}
}

impl std::convert::From<[u8; 32]> for Sha256 {
	fn from(bytes: [u8; 32]) -> Self {
		let words: &[u32] = unsafe { std::slice::from_raw_parts(std::mem::transmute(&bytes), 8)};
		let mut digest = [0; 8];
		digest.copy_from_slice(words);
		Sha256 { digest }
	}
}

impl std::convert::TryFrom<&str> for Sha256 {
	type Error = crate::err::Err;

	fn try_from(s: &str) -> crate::err::Result<Self> {
		let digest = hex_to_bytes_le(s)?;
		let digest: [u8; 32] = digest.as_slice()
			.try_into().map_err(|_| Err::ValueError(format!("the input `{}` cannot be converted to sha256", s)))?;
		Ok(Sha256::from(digest))
	}
}

impl fmt::Debug for Sha256 {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		(self as &Self).fmt(f)
	}
}

impl fmt::Display for Sha256 {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		(self as &Self).fmt(f)
	}
}

struct Chunks<'a> {
	message: &'a [u8],
	index: usize,
	count: usize,
	extra1: [u8; 64],
	extra2: [u8; 64],
}

impl <'a> Chunks<'a> {
	fn from(message: &'a [u8]) -> Chunks {
		Chunks {
			message,
			index: 0,
			count: message.len() / 64,
			extra1: [0; 64],
			extra2: [0; 64],
		}
	}
}

impl <'a> Iterator for Chunks<'a> {
	type Item = &'a[u32; 16];

	fn next(&mut self) -> Option<Self::Item> {
		if self.index < self.count {
			let byte_index = self.index * 64;
			self.index += 1;
			unsafe { std::mem::transmute(&self.message[byte_index]) }
		} else if self.index == self.count {
			self.index += 1;
			let leftover_bytes = self.message.len() % 64;
			let leftover_offset = self.message.len() - leftover_bytes;
			self.extra1[0..leftover_bytes].copy_from_slice(&self.message[leftover_offset..]);
			self.extra1[leftover_bytes] = 0x80;
			if leftover_bytes < 56 {
				let len_bytes = (self.message.len() * 8).to_be_bytes();
				for (i, &b) in len_bytes.iter().enumerate() {
					self.extra1[56 + i] = b;
				}
				self.index += 1;
			}
			unsafe { std::mem::transmute(&self.extra1) }
		} else if self.index == self.count + 1 {
			self.index += 1;
			if self.message.len() % 64 == 0 {
				self.extra2[0] = 0x80;
			}
			let len_bytes = (self.message.len() * 8).to_be_bytes();
			for (i, &b) in len_bytes.iter().enumerate() {
				self.extra2[56 + i] = b;
			}
			unsafe { std::mem::transmute(&self.extra2) }
		} else {
			None
		}
	}
}

fn digest_sha256_chunk(chunk: &[u32; 16], digest: &mut [u32; 8]) {
	const K: [u32; 64] = [
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
		0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
		0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
		0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
		0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
		0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
		0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
		0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	];
	
	fn rotr(word: u32, n: u8) -> u32 {
		(word>>n) | (word<<(32-n))
	}

	fn ch(x: u32, y: u32, z: u32) -> u32 {
		(x & y) ^ (!x & z)
	}

	fn maj(x: u32, y: u32, z: u32) -> u32 {
		(x & y) ^ (x & z) ^ (y & z)
	}

	fn bsig0(word: u32) -> u32 {
		rotr(word, 2) ^ rotr(word, 13) ^ rotr(word, 22)
	}

	fn bsig1(word: u32) -> u32 {
		rotr(word, 6) ^ rotr(word, 11) ^ rotr(word, 25)
	}
	
	fn ssig0(word: u32) -> u32 {
		rotr(word, 7) ^ rotr(word, 18) ^ (word >> 3)
	}

	fn ssig1(word: u32) -> u32 {
		rotr(word, 17) ^ rotr(word, 19) ^ (word >> 10)
	}

	let mut sched = [0; 64];
	for i in 0..16 {
		sched[i] = u32::from_be_bytes(chunk[i].to_ne_bytes());
	}
	for i in 16..64 {
		sched[i] = ssig1(sched[i-2])
			.wrapping_add(sched[i-7])
			.wrapping_add(ssig0(sched[i - 15]))
			.wrapping_add(sched[i-16]);
	}

	let mut var: [u32; 8] = *digest;

	for i in 0..64 {
		let t1 = var[7]
			.wrapping_add(bsig1(var[4]))
			.wrapping_add(ch(var[4], var[5], var[6]))
			.wrapping_add(K[i])
			.wrapping_add(sched[i]);
		
        let t2 = bsig0(var[0])
			.wrapping_add(maj(var[0], var[1], var[2]));
		
        var[7] = var[6];
        var[6] = var[5];
        var[5] = var[4];
        var[4] = var[3].wrapping_add(t1);
        var[3] = var[2];
        var[2] = var[1];
        var[1] = var[0];
        var[0] = t1.wrapping_add(t2);
	}

	for i in 0..8 {
		digest[i] = digest[i].wrapping_add(var[i]);
	}
}

pub fn compute_sha256<'a, T: Into<&'a [u8]>>(message: T) -> Sha256 {
	let bytes = message.into();
	let mut digest: [u32; 8] = [
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	];
	for chunk in Chunks::from(bytes) {
		digest_sha256_chunk(chunk, &mut digest);
	}

	for i in 0..8 {
		digest[i] = u32::from_be_bytes(digest[i].to_ne_bytes());
	}

	Sha256 { digest }
}

pub fn compute_double_sha256<'a, T: Into<&'a [u8]>>(message: T) -> Sha256 {
	let sha256 = compute_sha256(message);
	compute_sha256(sha256.as_bytes())
}