use std::{
	io::{Read, Write},
	cell::Cell,
};

use crate::{
	err::*,
	json::*,
	crypto::sha256::*,
	crypto::big_int::u256,
};

use crate::common::{
	read_u32,
	read_i32,
	read_sha256,
	read_var_int,
	write_u32,
	write_i32,
	write_sha256,
	write_var_int,
};

use super::{
	Deserialize,
	Serialize,
};

#[derive(Clone, Debug)]
pub struct Header {
	pub version: i32,
	pub prev_block: Sha256,
	pub merkle_root: Sha256,
	pub timestamp: u32,
	pub bits: u32,
	pub nonce: u32,
	pub tx_count: usize,
	hash: Cell<Option<Sha256>>,
}

impl Header {
	pub fn new(
		version: i32,
		prev_block: Sha256,
		merkle_root: Sha256,
		timestamp: u32,
		bits: u32,
		nonce: u32,
		tx_count: usize) -> Self {
		Header {
			version,
			prev_block,
			merkle_root,
			timestamp,
			bits,
			nonce,
			tx_count,
			hash: Cell::new(None),
		}
	}
	
	pub fn tx_count(&self) -> usize {
		self.tx_count
	}

	pub fn compute_hash(&self) -> Sha256 {
		if let Some(hash) = self.hash.get() {
			return hash;
		}
		let mut buf = Vec::new();
		self.serialize_without_tx_count(&mut buf).unwrap();
		let hash = compute_double_sha256(&*buf);
		self.hash.set(Some(hash));
		hash
	}

	pub fn compute_target(&self) -> u256 {
		let base = (self.bits & 0x00_ff_ff_ff) as u64;
		let exp = (((self.bits >> 24) - 3) * 8) as u64;
		u256::from_u64(base) << exp
	}

	fn serialize_without_tx_count(&self, stream: &mut dyn Write) -> Result<()> {
		write_i32(stream, self.version)?;
		write_sha256(stream, &self.prev_block)?;
		write_sha256(stream, &self.merkle_root)?;
		write_u32(stream, self.timestamp)?;
		write_u32(stream, self.bits)?;
		write_u32(stream, self.nonce)
	}
}

impl ToJson for Header {
	fn to_json(&self) -> JsonValue {
		JsonValue::object([
			("version", JsonValue::number(self.version)),
			("prev_block", JsonValue::string(format!("{}", self.prev_block))),
			("merkle_root", JsonValue::string(format!("{}", self.merkle_root))),
			("timestamp", JsonValue::number(self.timestamp)),
			("bits", JsonValue::number(self.bits)),
			("nonce", JsonValue::number(self.nonce)),
		])
	}
}

impl Deserialize for Header {
	fn deserialize(stream: &mut dyn Read) -> Result<Header> {
		let version = read_i32(stream)?;
		let prev_block = read_sha256(stream)?;
		let merkle_root = read_sha256(stream)?;
		let timestamp = read_u32(stream)?;
		let bits = read_u32(stream)?;
		let nonce = read_u32(stream)?;
		let tx_count = read_var_int(stream)? as usize;

		Ok(Header { 
			version,
			prev_block,
			merkle_root,
			timestamp,
			bits,
			nonce,
			tx_count,
			hash: Cell::new(None),
		})
	}
}

impl Serialize for Header {
	fn serialize(&self, stream: &mut dyn Write) -> Result<()> {
		self.serialize_without_tx_count(stream)?;
		write_var_int(stream, self.tx_count as u64)
	}
}

#[derive(Clone)]
pub struct Headers(Vec<Header>);

impl Headers {
	// pub fn new() -> Self {
	// 	Headers {
	// 		???
	// 	}
	// }

	pub fn iter(&self) -> std::slice::Iter<Header> {
		self.0.iter()
	}
}

impl ToJson for Headers {
	fn to_json(&self) -> JsonValue {
		JsonValue::array(self.0.iter().map(|e| e.to_json()))
	}
}

impl<'a> IntoIterator for Headers {
    type Item = Header;
    type IntoIter = std::vec::IntoIter<Header>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl Deserialize for Headers {
	fn deserialize(stream: &mut dyn Read) -> Result<Headers> {
		let count = read_var_int(stream)? as usize;
		let mut headers = Vec::new();
		for _ in 0..count {
			headers.push(Header::deserialize(stream)?);
		}
		Ok(Headers(headers))
	}
}

impl Serialize for Headers {
	fn serialize(&self, stream: &mut dyn Write) -> Result<()> {
		write_var_int(stream, self.0.len() as u64)?;
		for header in self.0.iter() {
			header.serialize(stream)?;
		}
		Ok(())
	}
}