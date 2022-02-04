use std::net::{ToSocketAddrs, SocketAddr, IpAddr};
use std::io::{Write, Read};
use std::fmt;

use crate::{
    err::*,
    sha256::compute_double_sha256,
    json::JsonValue,
	// common::now,
};

use super::{
	Serialize,
	Deserialize,
	read_u8,
	read_u16,
	read_u16_be,
	read_u32,
	read_u32_be,
	read_u64,
	read_buf_exact,
	read_str_exact,
	write_u8,
	write_u16,
	write_u16_be,
	write_u32,
	write_u32_be,
	write_u64,
	write_buf_exact,
	write_str_exact,
};

mod version;
mod sendcmpct;
mod ping;
mod pong;
mod addr;
mod feefilter;
mod inv;

pub use {
    version::*,
	sendcmpct::*,
	ping::*,
	pong::*,
	addr::*,
	feefilter::*,
	inv::*,
};

struct VarInt(u64);

impl Serialize for VarInt {
	fn serialize(&self, stream: &mut dyn Write) -> Result<()> {
		if self.0 < 0xfd {
			write_u8(stream, self.0 as u8)
		} else if self.0 < 0xffff {
			write_u8(stream, 0xfd)?;
			write_u16(stream, self.0 as u16)
		} else if self.0 < 0xffff_ffff {
			write_u8(stream, 0xfe)?;
			write_u32(stream, self.0 as u32)
		} else {
			write_u8(stream, 0xff)?;
			write_u64(stream, self.0 as u64)
		}
	}
}

impl Deserialize for VarInt {
	fn deserialize(stream: &mut dyn Read) -> Result<Self> {
		match read_u8(stream)? {
			0xfd => {
				Ok(VarInt(read_u16(stream)? as u64))
			},
			0xfe => {
				Ok(VarInt(read_u32(stream)? as u64))
			},
			0xff => {
				Ok(VarInt(read_u64(stream)? as u64))
			},
			b => {
				Ok(VarInt(b as u64))
			}
		}
	}
}

struct VarStr(String);

impl Serialize for VarStr {
	fn serialize(&self, stream: &mut dyn Write) -> Result<()> {
		VarInt(self.0.len() as u64).serialize(stream)?;
		if self.0.len() > 0 {
			stream.write(self.0.as_bytes())
				.map_err(|err| Err::NetworkError(err.to_string()))?;
		}
		Ok(())
	}
}

impl Deserialize for VarStr {
	fn deserialize(stream: &mut dyn Read) -> Result<Self> {
		let len = VarInt::deserialize(stream)?.0 as usize;
		let mut buf = vec![0; len];
		read_buf_exact(stream, &mut buf)?;
		Ok(VarStr(String::from_utf8(buf).unwrap()))
	}
}

#[derive(Clone)]
struct ShortNetAddr {
	services: u64,
	addr: SocketAddr,
}

impl ShortNetAddr {
	fn from<A: ToSocketAddrs>(addr: A) -> Self {
		let addr = addr.to_socket_addrs().unwrap().next().unwrap();
		ShortNetAddr {
			services: 0,
			addr,
		}
	}

	fn into_json(&self) -> JsonValue {
		JsonValue::object([
			("services", JsonValue::number(self.services)),
			("addr",     JsonValue::string(format!("{}", self.addr))),
		])
	}
}

impl Serialize for ShortNetAddr {
	fn serialize(&self, stream: &mut dyn Write) -> Result<()> {
		write_u64(stream, self.services)?;
		let bytes = match self.addr.ip() {
			IpAddr::V4(ip) => ip.to_ipv6_compatible().octets(),
			IpAddr::V6(ip) => ip.octets(),
		};
		write_buf_exact(stream, &bytes)?;
		write_u16_be(stream, self.addr.port())
	}
}

impl Deserialize for ShortNetAddr {
	fn deserialize(stream: &mut dyn Read) -> Result<Self> {
		let services = read_u64(stream)?;

		let mut octets = [0; 16];
		read_buf_exact(stream, &mut octets)?;
		let ip = IpAddr::from(octets);
		
		let port = read_u16_be(stream)?;
		
		Ok(ShortNetAddr {
			services,
			addr: SocketAddr::new(ip, port),
		})
	}
}

#[derive(Clone)]
struct NetAddr {
	timestamp: u32,
	services: u64,
	addr: SocketAddr,
}

impl NetAddr {
	// fn from<A: ToSocketAddrs>(addr: A) -> Self {
	// 	let addr = addr.to_socket_addrs().unwrap().next().unwrap();
	// 	NetAddr {
	// 		timestamp: now() as u32,
	// 		services: 0,
	// 		addr,
	// 	}
	// }

	fn into_json(&self) -> JsonValue {
		JsonValue::object([
			("timestamp", JsonValue::number(self.timestamp)),
			("services", JsonValue::number(self.services)),
			("addr",     JsonValue::string(format!("{}", self.addr))),
		])
	}
}

impl Serialize for NetAddr {
	fn serialize(&self, stream: &mut dyn Write) -> Result<()> {
		write_u32(stream, self.timestamp)?;
		write_u64(stream, self.services)?;
		let bytes = match self.addr.ip() {
			IpAddr::V4(ip) => ip.to_ipv6_compatible().octets(),
			IpAddr::V6(ip) => ip.octets(),
		};
		write_buf_exact(stream, &bytes)?;
		write_u16_be(stream, self.addr.port())
	}
}

impl Deserialize for NetAddr {
	fn deserialize(stream: &mut dyn Read) -> Result<Self> {
		let timestamp = read_u32(stream)?;
		let services = read_u64(stream)?;
		let mut octets = [0; 16];
		read_buf_exact(stream, &mut octets)?;
		let ip = IpAddr::from(octets);
		let port = read_u16_be(stream)?;
		
		Ok(NetAddr {
			timestamp,
			services,
			addr: SocketAddr::new(ip, port),
		})
	}
}

#[repr(u32)]
#[derive(Clone, Copy)]
enum Network {
	Main = 0xD9B4BEF9,
	TestNet = 0xDAB5BFFA,
	TestNet3 = 0x0709110B,
	SigNet = 0x40CF030A,
	NameCoin = 0xFEB4BEF9,
}

impl TryFrom<u32> for Network {
    type Error = Err;

    fn try_from(v: u32) -> Result<Self> {
        match v {
            x if x == Network::Main as u32 => Ok(Network::Main),
            x if x == Network::TestNet as u32 => Ok(Network::TestNet),
            x if x == Network::TestNet3 as u32 => Ok(Network::TestNet3),
            x if x == Network::SigNet as u32 => Ok(Network::SigNet),
            x if x == Network::NameCoin as u32 => Ok(Network::NameCoin),
            _ => Err(Err::NetworkError("invalid magic number in message".to_owned())),
        }
    }
}

impl fmt::Display for Network {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Network::Main => write!(f, "main"),
			Network::TestNet => write!(f, "testnet"),
			Network::TestNet3 => write!(f, "testnet3"),
			Network::SigNet => write!(f, "signet"),
			Network::NameCoin => write!(f, "namecoin"),
		}
	}
}

pub enum Payload {
	Version(Version),
	Verack,
	WTxIdRelay,
	SendAddrV2,
	SendHeaders,
	Addr(Addr),
	Inv(Inv),
	GetData,
	NotFound,
	GetBlocks,
	GetHeaders,
	Tx,
	Block,
	Headers,
	GetAddr,
	MemPool,
	CheckOrder,
	SubmitOrder,
	Reply,
	Ping(Ping),
	Pong(Pong),
	Reject,
	FilterLoad,
	FilterAdd,
	FilterClear,
	MerkleBlock,
	Alert,
	FeeFilter(FeeFilter),
	SendCmpct(SendCmpct),
	CmpctBlock,
	GetBlockTxn,
	BlockTxn,
}

impl Payload {
	pub fn name(&self) -> &'static str {
		match self {
			Payload::Version(_) => "version",
			Payload::Verack => "verack",
			Payload::WTxIdRelay => "wtxidrelay",
			Payload::SendAddrV2 => "sendaddrv2",
			Payload::SendHeaders => "sendheaders",
			Payload::Addr(_) => "addr",
			Payload::Inv(_) => "inv",
			Payload::GetData => "getdata",
			Payload::NotFound => "notfound",
			Payload::GetBlocks => "getblocks",
			Payload::GetHeaders => "getheaders",
			Payload::Tx => "tx",
			Payload::Block => "block",
			Payload::Headers => "headers",
			Payload::GetAddr => "getaddr",
			Payload::MemPool => "mempool",
			Payload::CheckOrder => "checkorder",
			Payload::SubmitOrder => "submitorder",
			Payload::Reply => "reply",
			Payload::Ping(_) => "ping",
			Payload::Pong(_) => "pong",
			Payload::Reject => "reject",
			Payload::FilterLoad => "filterload",
			Payload::FilterAdd => "filteradd",
			Payload::FilterClear => "filterclear",
			Payload::MerkleBlock => "merkleblock",
			Payload::Alert => "alert",
			Payload::FeeFilter(_) => "feefilter",
			Payload::SendCmpct(_) => "sendcmpct",
			Payload::CmpctBlock => "cmpctblock",
			Payload::GetBlockTxn => "getblocktxn",
			Payload::BlockTxn => "blocktxn",
		}
	}
	fn into_json(&self) -> JsonValue {
		match self {
			Payload::Version(x) => x.into_json(),
			Payload::Addr(x) => x.into_json(),
			Payload::Inv(x) => x.into_json(),
			Payload::Ping(x) => x.into_json(),
			Payload::Pong(x) => x.into_json(),
			Payload::FeeFilter(x) => x.into_json(),
			Payload::SendCmpct(x) => x.into_json(),
			_ => JsonValue::null(),
		}
	}
}

impl Serialize for Payload {
	fn serialize(&self, stream: &mut dyn Write) -> Result<()> {
		match self {
			Payload::Version(x) => x.serialize(stream),
			Payload::Addr(x) => x.serialize(stream),
			Payload::Inv(x) => x.serialize(stream),
			Payload::Ping(x) => x.serialize(stream),
			Payload::Pong(x) => x.serialize(stream),
			Payload::FeeFilter(x) => x.serialize(stream),
			Payload::SendCmpct(x) => x.serialize(stream),
			_ => Ok(()),
		}
	}
}

pub struct Message {
    network: Network,
	payload: Payload,
}

impl Message {
	pub fn version<A: ToSocketAddrs>(addr: A) -> Self {
		Message {
			network: Network::Main,
			payload: Payload::Version(Version::new(&addr)),
		}
	}

	pub fn verack() -> Self {
		Message {
			network: Network::Main,
			payload: Payload::Verack,
		}
	}

	pub fn pong(nonce: u64) -> Self {
		Message {
			network: Network::Main,
			payload: Payload::Pong(Pong::new(nonce)),
		}
	}

	// pub fn wtxidrelay() -> Self {
	// 	Message {
	// 		network: Network::Main,
	// 		payload: Payload::WTxIdRelay,
	// 	}
	// }

	// pub fn sendaddrv2() -> Self {
	// 	Message {
	// 		network: Network::Main,
	// 		payload: Payload::SendAddrV2,
	// 	}
	// }

	// pub fn sendheaders() -> Self {
	// 	Message {
	// 		network: Network::Main,
	// 		payload: Payload::SendHeaders,
	// 	}
	// }

	pub fn payload(&self) -> &Payload {
		&self.payload
	}
}

impl fmt::Display for Message {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let json = JsonValue::object([
			("network", JsonValue::string(format!("{}", self.network))),
			("message", JsonValue::string(self.payload.name())),
			("payload", self.payload.into_json()),
		]);
		
		write!(f, "{}", json)
	}
}

impl Serialize for Message {
	fn serialize(&self, stream: &mut dyn Write) -> Result<()> {
		write_u32(stream, self.network as u32)?;
		write_str_exact(stream, self.payload().name(), 12)?;
		let mut payload_bytes = Vec::new();
		self.payload.serialize(&mut payload_bytes)?;
		write_u32(stream, payload_bytes.len() as u32)?;
		let sha256 = compute_double_sha256(&*payload_bytes);
		let checksum = u32::from_be_bytes(sha256.as_bytes()[0..4].try_into().unwrap());
		write_u32_be(stream, checksum)?;
		write_buf_exact(stream, &payload_bytes)
	}
}

pub const MAX_PAYLOAD_SIZE: usize = 32 * 1024 * 1024;

impl Deserialize for Message {
	fn deserialize(stream: &mut dyn Read) -> Result<Self> {
		let magic = read_u32(stream)?;
		let network = Network::try_from(magic)?;
		let name = read_str_exact(stream, 12)?;
		let size = read_u32(stream)? as usize;
		let checksum = read_u32_be(stream)?;

		if size > MAX_PAYLOAD_SIZE {
			Err(Err::NetworkError(format!("max payload size exceeded: {}", size)))?;
		}

		let mut payload_bytes = vec![0; size as usize];
		read_buf_exact(stream, &mut payload_bytes)?;

		let sha256 = compute_double_sha256(&*payload_bytes);
		let real_checksum = u32::from_be_bytes(sha256.as_bytes()[0..4].try_into().unwrap());
		
		if checksum != real_checksum {
			return Err(Err::NetworkError(format!("checksum failure: expected {}, found {}", real_checksum, checksum)));
		}

		let payload = match name.as_str() {
			"version" => Payload::Version(Version::deserialize(&mut &*payload_bytes)?),
			"verack" => Payload::Verack,
			"wtxidrelay" => Payload::WTxIdRelay,
			"sendaddrv2" => Payload::SendAddrV2,
			"sendheaders" => Payload::SendHeaders,
			"addr" => Payload::Addr(Addr::deserialize(&mut &*payload_bytes)?),
			"inv" => Payload::Inv(Inv::deserialize(&mut &*payload_bytes)?),
			"getdata" => Payload::GetData,
			"notfound" => Payload::NotFound,
			"getblocks" => Payload::GetBlocks,
			"getheaders" => Payload::GetHeaders,
			"tx" => Payload::Tx,
			"block" => Payload::Block,
			"headers" => Payload::Headers,
			"getaddr" => Payload::GetAddr,
			"mempool" => Payload::MemPool,
			"checkorder" => Payload::CheckOrder,
			"submitorder" => Payload::SubmitOrder,
			"reply" => Payload::Reply,
			"ping" => Payload::Ping(Ping::deserialize(&mut &*payload_bytes)?),
			"pong" => Payload::Pong(Pong::deserialize(&mut &*payload_bytes)?),
			"reject" => Payload::Reject,
			"filterload" => Payload::FilterLoad,
			"filteradd" => Payload::FilterAdd,
			"filterclear" => Payload::FilterClear,
			"merkleblock" => Payload::MerkleBlock,
			"alert" => Payload::Alert,
			"feefilter" => Payload::FeeFilter(FeeFilter::deserialize(&mut &*payload_bytes)?),
			"sendcmpct" => Payload::SendCmpct(SendCmpct::deserialize(&mut &*payload_bytes)?),
			"cmpctblock" => Payload::CmpctBlock,
			"getblocktxn" => Payload::GetBlockTxn,
			"blocktxn" => Payload::BlockTxn,

			_ => Err(Err::NetworkError(format!("invalid message name: {}", name)))?,
		};

		Ok(Message { network, payload })
	}
}
