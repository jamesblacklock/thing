use std::{
	io::{Read, Write},
};

use crate::{
	err::*,
	json::JsonValue,
    sha256::Sha256,
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

#[derive(Clone)]
pub struct Header {
    version: i32,
    prev_block: Sha256,
    merkle_root: Sha256,
    timestamp: u32,
    bits: u32,
    nonce: u32,
}

impl Header {
	pub fn into_json(&self) -> JsonValue {
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
        let tx_count = read_var_int(stream)?;

        if tx_count != 0 {
            return Err(Err::ValueError("invalid block header: non-zero value in field `tx_count`".to_owned()));
        }

		Ok(Header { 
            version,
            prev_block,
            merkle_root,
            timestamp,
            bits,
            nonce,
        })
	}
}

impl Serialize for Header {
	fn serialize(&self, stream: &mut dyn Write) -> Result<()> {
        write_i32(stream, self.version)?;
        write_sha256(stream, &self.prev_block)?;
        write_sha256(stream, &self.merkle_root)?;
        write_u32(stream, self.timestamp)?;
        write_u32(stream, self.bits)?;
        write_u32(stream, self.nonce)?;
        write_var_int(stream, 0)
	}
}

#[derive(Clone)]
pub struct Headers(Vec<Header>);

impl Headers {
	// pub fn new() -> Self {
	// 	Headers {
	// 		nonce: rand::random(),
	// 	}
	// }

	pub fn into_json(&self) -> JsonValue {
		JsonValue::array(self.0.iter().map(|e| e.into_json()))
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