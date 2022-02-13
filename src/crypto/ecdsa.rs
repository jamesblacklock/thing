use std::io::Read;
use crate::{
	network::Deserialize,
	err::*,
	common::*,
	json::*,
};

use super::big_int::*;
use super::sha256::Sha256;

const ECDSA_PRIME: u256 = u256::from_raw_le([0xfffffffefffffc2f, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff]);
const ECDSA_ORDER: u256 = u256::from_raw_le([0xbfd25e8cd0364141, 0xbaaedce6af48a03b, 0xfffffffffffffffe, 0xffffffffffffffff]);
const ECDSA_BASE: ECDSAPoint = ECDSAPoint {
	x: u256::from_raw_le([0x59f2815b16f81798, 0x029bfcdb2dce28d9, 0x55a06295ce870b07, 0x79be667ef9dcbbac]),
	y: u256::from_raw_le([0x9c47d08ffb10d4b8, 0xfd17b448a6855419, 0x5da4fbfc0e1108a8, 0x483ada7726a3c465]),
};

pub struct ECDSAPoint {
	x: u256,
	y: u256,
}

pub type ECDSAPubKey = ECDSAPoint;

impl ToJson for ECDSAPoint {
	fn to_json(&self) -> JsonValue {
		JsonValue::object([
			("x", JsonValue::string(format!("{}", self.x))),
			("y", JsonValue::string(format!("{}", self.y))),
		])
	}
}

impl Deserialize for ECDSAPoint {
	fn deserialize(stream: &mut dyn Read) -> Result<Self> {
		let mut x = [0; 32];
		let mut y = [0; 32];
		
		let header = read_u8(stream)?;
		read_buf_exact(stream, &mut x)?;
		let temp = x.iter().copied().rev().collect::<Vec<_>>();
		x.copy_from_slice(&temp);

		let y_is_odd = match header {
			0x04 => {
				read_buf_exact(stream, &mut y)?;
				let temp = y.iter().copied().rev().collect::<Vec<_>>();
				y.copy_from_slice(&temp);

				return Ok(ECDSAPoint {
					x: x.into(),
					y: y.into(),
				})
			},
			0x03 => true,
			0x02 => false,
			_ => return Err(Err::ValueError("invalid pubkey".to_owned()))
		};

		let x: u512 = u256::from(x).resize();
		let p: u512 = ECDSA_PRIME.resize();

		// y² = x³ + 7 mod p
		let y2 = (x.pow_mod(3.into(), p) + 7.into()) % p;

		// from an online source: "Secp256k1 is chosen in a special way so that the square root of y² is y²^((p+1)/4)"
		let exp = (p + 1.into()) / 4.into();
		let mut y = y2.pow_mod(exp, p);
		
		if y_is_odd != y.is_odd() {
			y = (p - y) % p;
		}

		Ok(ECDSAPoint {
			x: x.resize(),
			y: y.resize(),
		})
	}
}

// #[derive(Debug)]
// pub enum HashType {
// 	SigHashAll = 0x01,
// 	SigHashNone = 0x02,
// 	SigHashSingle = 0x03,
// 	SigHashAnyoneCanPay = 0x80,
// }

// impl TryFrom<u8> for HashType {
// 	type Error = Err;
// 	fn try_from(n: u8) -> Result<Self> {
// 		match n {
// 			0x01 => Ok(HashType::SigHashAll),
// 			0x02 => Ok(HashType::SigHashNone),
// 			0x03 => Ok(HashType::SigHashSingle),
// 			0x80 => Ok(HashType::SigHashAnyoneCanPay),
// 			_ => Err(Err::ValueError("invalid hash type".to_owned()))
// 		}
// 	}
// }

pub struct ECDSASig {
	r: u256,
	s: u256,
	hash_type: u8,//HashType,
}

impl ECDSASig {
	pub fn hash_type(&self) -> u8 {//HashType {
		self.hash_type
	}

	pub fn verify(&self, pub_key: ECDSAPubKey, hash: Sha256) -> bool {
		// adapted from https://github.com/tlsfuzzer/python-ecdsa/blob/master/src/ecdsa/ecdsa.py (public domain)
		unimplemented!();
		// let hash = u256::from(hash).extend();
		// let g = ECDSA_BASE;
		// let n = ECDSA_ORDER.extend();
		// let r = self.r.extend();
		// let s = self.s.extend();
		// if r < 1.into() || r > n - 1.into() {
		// 	return false;
		// } else if s < 1.into() || s > n - 1.into() {
		// 	return false
		// }
		// let c = s.inverse_mod(s, n);
		// let u1 = (hash * c) % n;
		// let u2 = (r * c) % n;
		// let point = u1 * g + u2 * pub_key;
		// let v = point.x % n;
		// v == r
	}
}

impl ToJson for ECDSASig {
	fn to_json(&self) -> JsonValue {
		JsonValue::object([
			("s", JsonValue::string(format!("{}", self.s))),
			("r", JsonValue::string(format!("{}", self.r))),
			// ("hash_type", JsonValue::string(format!("{:?}", self.hash_type))),
			("hash_type", JsonValue::number(self.hash_type)),
		])
	}
}

fn read_der_32_byte_int(stream: &mut dyn Read) -> Result<(u8, [u8; 32])> {
	// "int" indicator
	if read_u8(stream)? != 0x02 {
		return Err(Err::ValueError("invalid signature".to_owned()));
	}
	let size = read_u8(stream)?;
	if size < 32 || size > 33 {
		return Err(Err::ValueError("invalid signature".to_owned()));
	} else if size == 33 && read_u8(stream)? != 0 {
		return Err(Err::ValueError("invalid signature".to_owned()));
	}
	let mut value = [0; 32];
	read_buf_exact(stream, &mut value)?;
	if size == 33 && value[0] < 0x80 {
		return Err(Err::ValueError("invalid signature".to_owned()));
	}
	Ok(((size == 33) as u8, value))
}

impl Deserialize for ECDSASig {
	fn deserialize(stream: &mut dyn Read) -> Result<Self> {
		// "compound structure" indicator
		if read_u8(stream)? != 0x30 {
			return Err(Err::ValueError("invalid signature".to_owned()));
		}
		let total_size = read_u8(stream)?;
		if total_size < 68 || total_size > 70 {
			return Err(Err::ValueError("invalid signature".to_owned()));
		}
		let (r_extra_byte, r) = read_der_32_byte_int(stream)?;
		let (s_extra_byte, s) = read_der_32_byte_int(stream)?;
		if total_size != 68 + r_extra_byte + s_extra_byte {
			return Err(Err::ValueError("invalid signature".to_owned()));
		}

		let hash_type = read_u8(stream)?;//.try_into()?;

		Ok(ECDSASig{s: s.into(), r: r.into(), hash_type})
	}
}

#[test]
fn decompress_pub_keys() {
	// first item: compressed pub key (i.e. x coord preceded by 0x02 or 0x03)
	// second item: y coord
	let keys = [
		("02b4632d08485ff1df2db55b9dafd23347d1c47a457072a1e87be26896549a8737", "8ec38ff91d43e8c2092ebda601780485263da089465619e0358a5c1be7ac91f4"),
		("0229b3e0919adc41a316aad4f41444d9bf3a9b639550f2aa735676ffff25ba3898", "d6881e81d2e0163348ff07b3a9a3968401572aa79c79e7edb522f41addc8e6ce"),
		("02f15446771c5c585dd25d8d62df5195b77799aa8eac2f2196c54b73ca05f72f27", "4d335b71c85e064f80191e1f7e2437afa676a3e2a5a5fafcf0d27940cd33e4b4"),
	];

	for (compressed, expected_y) in keys {
		let key = ECDSAPubKey::deserialize(&mut &*hex_to_bytes(compressed).unwrap()).unwrap();
		assert!(u256::hex(expected_y) == key.y);
	}
}