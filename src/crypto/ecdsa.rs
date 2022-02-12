use std::io::Read;
use crate::{
	network::Deserialize,
	err::*,
	common::*,
	json::*,
};

use super::u256::u256;

const ECDSA_PRIME: u256 = u256::from_raw([0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xfffffffefffffc2f]);
const ECDSA_ORDER: u256 = u256::from_raw([0xffffffffffffffff, 0xfffffffffffffffe, 0xbaaedce6af48a03b, 0xbfd25e8cd0364141]);
const ECDSA_BASE: ECDSAPoint = ECDSAPoint {
	x: u256::from_raw([0x79be667ef9dcbbac, 0x55a06295ce870b07, 0x029bfcdb2dce28d9, 0x59f2815b16f81798]),
	y: u256::from_raw([0x483ada7726a3c465, 0x5da4fbfc0e1108a8, 0xfd17b448a6855419, 0x9c47d08ffb10d4b8]),
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

				let test_x = u256::from(x);
				let test_y = u256::from(y);
				println!("     y² = {}", test_y * test_y % ECDSA_PRIME);
				println!("x³ + 7  = {}", (test_x.pow(3.into()) + 7.into()) % ECDSA_PRIME);

				return Ok(ECDSAPoint {
					x: x.into(),
					y: y.into(),
				})
			},
			0x03 => true,
			0x02 => false,
			_ => return Err(Err::ValueError("invalid pubkey".to_owned()))
		};

		let x = u256::from(x);
		// x.pow(3) + 7.into();
		// y² = x³ + 7
		unimplemented!();

		Ok(ECDSAPoint {
			x: x.into(),
			y: y.into(),
		})
	}
}

#[derive(Debug)]
pub enum HashType {
	SigHashAll = 0x01,
	SigHashNone = 0x02,
	SigHashSingle = 0x03,
	SigHashAnyoneCanPay = 0x80,
}

impl TryFrom<u8> for HashType {
	type Error = Err;
	fn try_from(n: u8) -> Result<Self> {
		match n {
			0x01 => Ok(HashType::SigHashAll),
			0x02 => Ok(HashType::SigHashNone),
			0x03 => Ok(HashType::SigHashSingle),
			0x80 => Ok(HashType::SigHashAnyoneCanPay),
			_ => Err(Err::ValueError("invalid hash type".to_owned()))
		}
	}
}

pub struct ECDSASig {
	r: [u8; 32],
	s: [u8; 32],
	hash_type: HashType,
}

impl ToJson for ECDSASig {
	fn to_json(&self) -> JsonValue {
		JsonValue::object([
			("s", JsonValue::string(bytes_to_hex(&self.s))),
			("r", JsonValue::string(bytes_to_hex(&self.r))),
			("hash_type", JsonValue::string(format!("{:?}", self.hash_type))),
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

		let hash_type = read_u8(stream)?.try_into()?;

		Ok(ECDSASig{s, r, hash_type})
	}
}