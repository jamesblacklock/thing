use std::{
	io::{Read, Write},
};

use crate::{
	err::*,
	json::JsonValue,
};

use crate::common::{
	read_u64,
	write_u64,
};

use super::{
	Deserialize,
	Serialize,
};

#[derive(Clone)]
pub struct Ping {
	nonce: u64,
}

impl Ping {
	// pub fn new() -> Self {
	// 	Ping {
	// 		nonce: rand::random(),
	// 	}
	// }

	pub fn to_json(&self) -> JsonValue {
		JsonValue::number(self.nonce)
	}

	pub fn nonce(&self) -> u64 {
		self.nonce
	}
}

impl Deserialize for Ping {
	fn deserialize(stream: &mut dyn Read) -> Result<Ping> {
		Ok(Ping { nonce: read_u64(stream)? })
	}
}

impl Serialize for Ping {
	fn serialize(&self, stream: &mut dyn Write) -> Result<()> {
		write_u64(stream, self.nonce)
	}
}