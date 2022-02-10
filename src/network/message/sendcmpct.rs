use std::{
	io::{Read, Write},
};

use crate::{
	err::*,
	json::*,
};

use crate::common::{
	read_bool,
	read_u64,
	write_bool,
	write_u64,
};

use super::{
	Deserialize,
	Serialize,
};

#[derive(Clone)]
pub struct SendCmpct {
	set: bool,
    version: u64,
}

impl SendCmpct {
	// pub fn new() -> Self {
	// 	SendCmpct {
	// 		set: true,
	// 		version: 1,
	// 	}
	// }
}

impl ToJson for SendCmpct {
	fn to_json(&self) -> JsonValue {
		JsonValue::object([
			("set",     JsonValue::bool(self.set)),
			("version", JsonValue::number(self.version)),
		])
	}
}

impl Deserialize for SendCmpct {
	fn deserialize(stream: &mut dyn Read) -> Result<SendCmpct> {
		let set = read_bool(stream)?;
		let version = read_u64(stream)?;

		Ok(SendCmpct {
			set,
			version,
		})
	}
}

impl Serialize for SendCmpct {
	fn serialize(&self, stream: &mut dyn Write) -> Result<()> {
		write_bool(stream, self.set)?;
		write_u64(stream, self.version)
	}
}