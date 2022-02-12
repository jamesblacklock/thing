use std::io::Read;
use crate::{
	network::Deserialize,
	err::*,
	common::*,
	json::*,
};

use super::u256::u256;

pub struct ECDSAPubKey {
	x: u256,
	y: u256,
}

impl ToJson for ECDSAPubKey {
	fn to_json(&self) -> JsonValue {
		JsonValue::object([
			("x", JsonValue::string(format!("{}", self.x))),
			("y", JsonValue::string(format!("{}", self.y))),
		])
	}
}

impl Deserialize for ECDSAPubKey {
	fn deserialize(stream: &mut dyn Read) -> Result<Self> {
		let mut x = [0; 32];
		let mut y = [0; 32];
		
		let header = read_u8(stream)?;
		read_buf_exact(stream, &mut x)?;

		let y_is_odd = match header {
			0x04 => {
				read_buf_exact(stream, &mut y)?;
				return Ok(ECDSAPubKey {
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

		Ok(ECDSAPubKey {
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