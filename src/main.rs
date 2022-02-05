#![feature(try_blocks)]

use std::{
	collections::HashMap,
	net::{TcpStream},
	sync::mpsc::{Sender, Receiver},
	thread,
};

mod err;
mod common;
mod sha256;
mod json;
mod network;

use sha256::Sha256;

use network::{
	Peer,
	message::{
		Message,
		Payload,
		Version,
		Ping,
		Inv,
		InvType,
	}
};

use err::*;

#[derive(Default)]
struct Config {
	wxtxid: bool,
	addrv2: bool,
}

struct Mempool {
	ids: Vec<Sha256>,
	txs: HashMap<Sha256, ()>,
}

impl Mempool {
	fn new() -> Self {
		Mempool {
			ids: Vec::new(),
			txs: HashMap::new(),
		}
	}

	fn add_tx_id(&mut self, id: Sha256) {
		println!("add tx id to mempool: {}", id);
		self.ids.push(id);
	}
}

struct Node {
	peer: TcpStream,
	config: Config,
	peer_info: Option<Version>,
	handshake_complete: bool,
	mempool: Mempool,
}

impl Node {
	pub fn new(addr: String) -> Result<Node> {
		let peer = TcpStream::connect(addr)
			.map_err(|_| Err::NetworkError("failed to connect to peer".to_owned()))?;
		
		Ok(Node {
			peer,
			config: Config::default(),
			peer_info: None,
			handshake_complete: false,
			mempool: Mempool::new(),
		})
	}

	fn handle_message(&mut self, m: Message) -> Result<()> {
		match m.payload() {
			Payload::Version(payload) => self.handle_version_message(payload),
			Payload::Verack => self.handle_verack_message(),
			Payload::WTxIdRelay => self.handle_wtxidrelay_message(),
			Payload::SendAddrV2 => self.handle_sendaddrv2_message(),
			Payload::Ping(ping) => self.handle_ping_message(ping),
			Payload::Inv(inv) => self.handle_inv_message(inv),
			p => {
				println!("{}: no response implemented\n", p.name());
				Ok(())
			},
		}
	}

	fn handle_version_message(&mut self, payload: &Version) -> Result<()> {
		if !self.handshake_complete && self.peer_info.is_none() {
			self.peer_info = Some(payload.clone());
			self.peer.send(Message::verack())?;
		}
		Ok(())
	}
	
	fn handle_ping_message(&mut self, payload: &Ping) -> Result<()> {
		self.peer.send(Message::pong(payload.nonce()))?;
		Ok(())
	}

	fn handle_verack_message(&mut self) -> Result<()> {
		if !self.handshake_complete {
			if  self.peer_info.is_none() {
				return Err(Err::NetworkError("failed to complete handshake (missing version message)".to_owned()));
			}
			self.handshake_complete = true;
		}
		Ok(())
	}

	fn handle_wtxidrelay_message(&mut self) -> Result<()> {
		if !self.handshake_complete {
			self.config.wxtxid = true;
			println!("SET PARAM: wxtxid = true\n");
		}
		Ok(())
	}

	fn handle_sendaddrv2_message(&mut self) -> Result<()> {
		if !self.handshake_complete {
			self.config.addrv2 = true;
			println!("SET PARAM: addrv2 = true\n");
		}
		Ok(())
	}

	fn handle_inv_message(&mut self, inv: &Inv) -> Result<()> {
		for item in inv.items().iter() {
			match item.object_type {
				InvType::Tx => self.mempool.add_tx_id(item.hash),
				// InvType::Block => {},
				// InvType::FilteredBlock => {},
				// InvType::CmpctBlock => {},
				// InvType::WitnessTx => {},
				// InvType::WitnessBlock => {},
				// InvType::FilteredWitnessBlock => {},
				InvType::Error => {},
				_ => unimplemented!("inv object type: {}", item.object_type),
			}
		}
		
		Ok(())
	}

	fn receive_messages(&mut self) -> Result<()> {
		loop {
			let message = self.peer.receive()?;
			self.handle_message(message)?;
		}
	}

	fn do_handshake(&mut self) -> Result<()> {
		assert!(self.handshake_complete == false);

		self.peer.send(Message::version(self.peer.peer_addr().unwrap()))?;
		self.receive_messages()?;

		if !self.handshake_complete {
			return Err(Err::NetworkError("failed to complete handshake".to_owned()));
		}

		Ok(())
	}
	
	pub fn run(&mut self) -> Result<()> {
		self.do_handshake()?;
		Ok(())
	}
}

fn main() -> Result<()> {
	let addr = std::env::args().nth(1).expect("no IP address specified");
	let mut node = Node::new(addr)?;
	node.run()
}