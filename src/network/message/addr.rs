use std::{
	io::{Read, Write},
};

use crate::{
	err::*,
	json::JsonValue,
};

use super::{
	Deserialize,
	Serialize,
    NetAddr,
    VarInt,
};

#[derive(Clone)]
pub struct Addr {
	addrs: Vec<NetAddr>,
}

impl Addr {
	// pub fn new() -> Self {
	// 	Addr {
	// 		addrs: Vec::new(),
	// 	}
	// }

	pub fn into_json(&self) -> JsonValue {
        JsonValue::Array(self.addrs.iter().map(|e| e.into_json()).collect())
	}
}

impl Deserialize for Addr {
	fn deserialize(stream: &mut dyn Read) -> Result<Addr> {
		let count = VarInt::deserialize(stream)?.0 as usize;
        let mut addrs = Vec::new();
        for _ in 0..count {
            addrs.push(NetAddr::deserialize(stream)?);
        }

        Ok(Addr {addrs})
	}
}

impl Serialize for Addr {
	fn serialize(&self, stream: &mut dyn Write) -> Result<()> {
        VarInt(self.addrs.len() as u64).serialize(stream)?;
		for addr in &self.addrs {
            addr.serialize(stream)?;
        }
        Ok(())
	}
}