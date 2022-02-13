use std::net::{ToSocketAddrs, SocketAddr, IpAddr};
use std::io::{Write, Read};
use std::fmt;

use crate::{
    err::*,
    crypto::sha256::compute_double_sha256,
    crypto::sha256::Sha256,
    json::*,
};

use crate::common::{
	read_u16_be,
	read_u32,
	read_u32_be,
	read_u64,
	read_buf_exact,
	read_str_exact,
	write_u16_be,
	write_u32,
	write_u32_be,
	write_u64,
	write_buf_exact,
	write_str_exact,
};

use super::{
	Serialize,
	Deserialize,
};

mod version;
mod sendcmpct;
mod ping;
mod pong;
mod addr;
mod feefilter;
mod inv;
mod tx;
mod getheaders;
mod headers;
mod block;

pub use {
    version::*,
	sendcmpct::*,
	ping::*,
	pong::*,
	addr::*,
	feefilter::*,
	inv::*,
	tx::*,
	getheaders::*,
	headers::*,
	block::*,
};

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
}

impl ToJson for ShortNetAddr {
	fn to_json(&self) -> JsonValue {
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
}

impl ToJson for NetAddr {
	fn to_json(&self) -> JsonValue {
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
	GetData(GetData),
	NotFound,
	GetHeaders(GetHeaders),
	GetBlocks(GetHeaders),
	Tx(Sha256, Tx),
	Block(Block),
	Headers(Headers),
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
			Payload::GetData(_) => "getdata",
			Payload::NotFound => "notfound",
			Payload::GetBlocks(_) => "getblocks",
			Payload::GetHeaders(_) => "getheaders",
			Payload::Tx(..) => "tx",
			Payload::Block(_) => "block",
			Payload::Headers(_) => "headers",
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
}

impl ToJson for Payload {
	fn to_json(&self) -> JsonValue {
		match self {
			Payload::Version(x) => x.to_json(),
			Payload::Verack => JsonValue::null(),
			Payload::WTxIdRelay => JsonValue::null(),
			Payload::SendAddrV2 => JsonValue::null(),
			Payload::SendHeaders => JsonValue::null(),
			Payload::Addr(x) => x.to_json(),
			Payload::Inv(x) => x.to_json(),
			Payload::GetData(x) => x.to_json(),
			Payload::NotFound => JsonValue::null(),
			Payload::GetBlocks(x) => x.to_json(),
			Payload::GetHeaders(x) => x.to_json(),
			Payload::Tx(_, x) => x.to_json(),
			Payload::Block(x) => x.to_json(),
			Payload::Headers(x) => x.to_json(),
			Payload::GetAddr => JsonValue::null(),
			Payload::MemPool => JsonValue::null(),
			Payload::CheckOrder => JsonValue::null(),
			Payload::SubmitOrder => JsonValue::null(),
			Payload::Reply => JsonValue::null(),
			Payload::Ping(x) => x.to_json(),
			Payload::Pong(x) => x.to_json(),
			Payload::Reject => JsonValue::null(),
			Payload::FilterLoad => JsonValue::null(),
			Payload::FilterAdd => JsonValue::null(),
			Payload::FilterClear => JsonValue::null(),
			Payload::MerkleBlock => JsonValue::null(),
			Payload::Alert => JsonValue::null(),
			Payload::FeeFilter(x) => x.to_json(),
			Payload::SendCmpct(x) => x.to_json(),
			Payload::CmpctBlock => JsonValue::null(),
			Payload::GetBlockTxn => JsonValue::null(),
			Payload::BlockTxn => JsonValue::null(),
		}
	}
}

impl Serialize for Payload {
	fn serialize(&self, stream: &mut dyn Write) -> Result<()> {
		match self {
			Payload::Version(x) => x.serialize(stream),
			Payload::Verack => Ok(()),
			Payload::WTxIdRelay => Ok(()),
			Payload::SendAddrV2 => Ok(()),
			Payload::SendHeaders => Ok(()),
			Payload::Addr(x) => x.serialize(stream),
			Payload::Inv(x) => x.serialize(stream),
			Payload::GetData(x) => x.serialize(stream),
			Payload::NotFound => Ok(()),
			Payload::GetHeaders(x) => x.serialize(stream),
			Payload::GetBlocks(x) => x.serialize(stream),
			Payload::Tx(_, x) => x.serialize(stream),
			Payload::Block(x) => x.serialize(stream),
			Payload::Headers(x) => x.serialize(stream),
			Payload::GetAddr => Ok(()),
			Payload::MemPool => Ok(()),
			Payload::CheckOrder => Ok(()),
			Payload::SubmitOrder => Ok(()),
			Payload::Reply => Ok(()),
			Payload::Ping(x) => x.serialize(stream),
			Payload::Pong(x) => x.serialize(stream),
			Payload::Reject => Ok(()),
			Payload::FilterLoad => Ok(()),
			Payload::FilterAdd => Ok(()),
			Payload::FilterClear => Ok(()),
			Payload::MerkleBlock => Ok(()),
			Payload::Alert => Ok(()),
			Payload::FeeFilter(x) => x.serialize(stream),
			Payload::SendCmpct(x) => x.serialize(stream),
			Payload::CmpctBlock => Ok(()),
			Payload::GetBlockTxn => Ok(()),
			Payload::BlockTxn => Ok(()),
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
	
	pub fn getheaders(hashes: &[Sha256]) -> Self {
		Message {
			network: Network::Main,
			payload: Payload::GetHeaders(GetHeaders::new(hashes)),
		}
	}
	
	// pub fn getblocks(hashes: &[Sha256]) -> Self {
	// 	Message {
	// 		network: Network::Main,
	// 		payload: Payload::GetBlocks(GetHeaders::new(hashes)),
	// 	}
	// }

	pub fn sendheaders() -> Self {
		Message {
			network: Network::Main,
			payload: Payload::SendHeaders,
		}
	}

	pub fn getdata(inv: Vec<InvItem>) -> Self {
		Message {
			network: Network::Main,
			payload: Payload::GetData(GetData::new(inv)),
		}
	}

	pub fn payload(&self) -> &Payload {
		&self.payload
	}

	pub fn take_payload(self) -> Payload {
		self.payload
	}
}

impl fmt::Display for Message {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let mut props = vec![
			("network", JsonValue::string(format!("{}", self.network))),
			("message", JsonValue::string(self.payload.name())),
		];
		if let Payload::Tx(id, _) = self.payload {
			props.push(("id", JsonValue::string(format!("{}", id))));
		}
		props.push(("payload", self.payload.to_json()));

		write!(f, "{}", JsonValue::object(props))
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

		let payload_stream = &mut &*payload_bytes as &mut dyn Read;
		let payload = match name.as_str() {
			"version" => Payload::Version(Version::deserialize(payload_stream)?),
			"verack" => Payload::Verack,
			"wtxidrelay" => Payload::WTxIdRelay,
			"sendaddrv2" => Payload::SendAddrV2,
			"sendheaders" => Payload::SendHeaders,
			"addr" => Payload::Addr(Addr::deserialize(payload_stream)?),
			"inv" => Payload::Inv(Inv::deserialize(payload_stream)?),
			"getdata" => Payload::GetData(GetData::deserialize(payload_stream)?),
			"notfound" => Payload::NotFound,
			"getblocks" => Payload::GetBlocks(GetHeaders::deserialize(payload_stream)?),
			"getheaders" => Payload::GetHeaders(GetHeaders::deserialize(payload_stream)?),
			"tx" => Payload::Tx(sha256, Tx::deserialize(payload_stream)?),
			"block" => Payload::Block(Block::deserialize(payload_stream)?),
			"headers" => Payload::Headers(Headers::deserialize(payload_stream)?),
			"getaddr" => Payload::GetAddr,
			"mempool" => Payload::MemPool,
			"checkorder" => Payload::CheckOrder,
			"submitorder" => Payload::SubmitOrder,
			"reply" => Payload::Reply,
			"ping" => Payload::Ping(Ping::deserialize(payload_stream)?),
			"pong" => Payload::Pong(Pong::deserialize(payload_stream)?),
			"reject" => Payload::Reject,
			"filterload" => Payload::FilterLoad,
			"filteradd" => Payload::FilterAdd,
			"filterclear" => Payload::FilterClear,
			"merkleblock" => Payload::MerkleBlock,
			"alert" => Payload::Alert,
			"feefilter" => Payload::FeeFilter(FeeFilter::deserialize(payload_stream)?),
			"sendcmpct" => Payload::SendCmpct(SendCmpct::deserialize(payload_stream)?),
			"cmpctblock" => Payload::CmpctBlock,
			"getblocktxn" => Payload::GetBlockTxn,
			"blocktxn" => Payload::BlockTxn,

			_ => Err(Err::NetworkError(format!("invalid message name: {}", name)))?,
		};

		Ok(Message { network, payload })
	}
}
