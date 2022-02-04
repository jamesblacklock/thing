#![feature(try_blocks)]

use std::net::{TcpStream};

mod err;
mod common;
mod sha256;
mod json;
mod network;

use network::{
	Peer,
	message::{
		Message,
		Payload,
		Version,
		Ping,
	}
};

use err::*;

#[derive(Default)]
struct Config {
	wxtxid: bool,
	addrv2: bool,
}

struct Node {
	peer: TcpStream,
	config: Config,
	peer_info: Option<Version>,
	handshake_complete: bool,
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
		})
	}

	fn handle_message(&mut self, m: Message) -> Result<()> {
		match m.payload() {
			Payload::Version(payload) => self.handle_version_message(payload),
			Payload::Verack => self.handle_verack_message(),
			Payload::WTxIdRelay => self.handle_wtxidrelay_message(),
			Payload::SendAddrV2 => self.handle_sendaddrv2_message(),
			Payload::Ping(ping) => self.handle_ping_message(ping),
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

	fn receive_messages(&mut self) -> Result<()> {
		while let Some(response) = self.peer.receive()? {
			self.handle_message(response)?;
		}
		Ok(())
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