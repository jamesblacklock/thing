use std::{
	io::{Read, Write},
	net::ToSocketAddrs,
};

use crate::{
	err::*,
	json::*,
	common::now,
};

use crate::common::{
	read_bool,
	read_i32,
	read_u32,
	read_i64,
	read_u64,
	read_var_str,
	write_bool,
	write_i32,
	write_u32,
	write_i64,
	write_u64,
	write_var_str,
};

use super::{
	ShortNetAddr,
	Deserialize,
	Serialize,
};

pub const PROTOCOL_VERSION: i32 = 70016;
pub const BIP_0037: i32         = 70001;

// mod Services {
// 	const NODE_NETWORK: u64         = 0x0001;
// 	const NODE_GETUTXO: u64         = 0x0002;
// 	const NODE_BLOOM: u64           = 0x0004;
// 	const NODE_WITNESS: u64         = 0x0008;
// 	const NODE_XTHIN: u64           = 0x0010;
// 	const NODE_COMPACT_FILTERS: u64 = 0x0040;
// 	const NODE_NETWORK_LIMITED: u64 = 0x0400;
// }

#[derive(Clone)]
pub struct Version {
	version: i32,
	services: u64,
	timestamp: i64,
	addr_recv: ShortNetAddr,
	addr_from: ShortNetAddr,
	nonce: u64,
	user_agent: String,
	start_height: u32,
	relay: bool,
}

impl Version {
	pub fn new<A: ToSocketAddrs>(addr: A) -> Self {
		Version {
			version: PROTOCOL_VERSION,
			services: 0,
			timestamp: now() as i64,
			addr_recv: ShortNetAddr::from(&addr),
			addr_from: ShortNetAddr::from("[::0]:0"),
			nonce: rand::random(),
			user_agent: String::from("/Frabjous:0.1.0/"),
			start_height: 0,
			relay: true,
		}
	}
}

impl ToJson for Version {
	fn to_json(&self) -> JsonValue {
		JsonValue::object([
			("version",      JsonValue::number(self.version)),
			("services",     JsonValue::number(self.services)),
			("timestamp",    JsonValue::number(self.timestamp)),
			("addr_recv",    self.addr_recv.to_json()),
			("addr_from",    self.addr_from.to_json()),
			("nonce",        JsonValue::number(self.nonce)),
			("user_agent",   JsonValue::string(&self.user_agent)),
			("start_height", JsonValue::number(self.start_height)),
			("relay",        JsonValue::bool(self.relay)),
		])
	}
}

impl Deserialize for Version {
	fn deserialize(stream: &mut dyn Read) -> Result<Version> {
		let version = read_i32(stream)?;
		let services = read_u64(stream)?;
		let timestamp = read_i64(stream)?;
		let addr_recv = ShortNetAddr::deserialize(stream)?;
		let addr_from = ShortNetAddr::deserialize(stream)?;
		let nonce = read_u64(stream)?;
		let user_agent = read_var_str(stream)?;
		let start_height = read_u32(stream)?;
		let relay = if version > BIP_0037 {
			read_bool(stream)?
		} else {
			true
		};
		
		Ok(Version {
			version,
			services,
			timestamp,
			addr_recv,
			addr_from,
			nonce,
			user_agent,
			start_height,
			relay,
		})
	}
}

impl Serialize for Version {
	fn serialize(&self, stream: &mut dyn Write) -> Result<()> {
		write_i32(stream, self.version)?;
		write_u64(stream, self.services)?;
		write_i64(stream, self.timestamp)?;
		self.addr_recv.serialize(stream)?;
		self.addr_from.serialize(stream)?;
		write_u64(stream, self.nonce)?;
		write_var_str(stream, &self.user_agent)?;
		write_u32(stream, self.start_height)?;
		if self.version > BIP_0037 {
			write_bool(stream, self.relay)?;
		}
		Ok(())
	}
}