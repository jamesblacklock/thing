#![feature(try_blocks)]

use std::{
	collections::{HashMap, HashSet},
	net::{TcpStream},
	sync::mpsc,
	sync::mpsc::{Receiver},
	thread,
};

mod err;
mod common;
mod sha256;
mod json;
mod network;
mod script;

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
		Tx,
		FeeFilter,
	}
};

use err::*;
use json::*;

#[derive(Default)]
struct Config {
	wxtxid: bool,
	addrv2: bool,
	feerate: u64,
}

struct Mempool {
	pending: HashSet<Sha256>,
	txs: HashMap<Sha256, Tx>,
}

impl Mempool {
	fn new() -> Self {
		Mempool {
			pending: HashSet::new(),
			txs: HashMap::new(),
		}
	}
	
	fn add_tx(&mut self, id: Sha256, tx: Tx) {
		self.pending.remove(&id);
		if self.txs.contains_key(&id) {
			println!("tx already in mempool: {}", id);
		} else {
			println!("add tx to mempool: {}", id);
			self.txs.insert(id, tx);
		}
	}

	fn contains(&self, id: Sha256) -> bool {
		self.pending.contains(&id) || self.txs.contains_key(&id)
	}
}


enum ApplicationMessage {
	ShowMempool,
	Shutdown,
}

struct PeerHandle {
	addr: String,
	writer: TcpStream,
	// handle: thread::JoinHandle<()>,
	info: Option<Version>,
	config: Config,
	handshake_complete: bool,
}

struct Node {
	peers: HashMap<usize, PeerHandle>,
	recv: Receiver<(usize, Message)>,
	mempool: Mempool,
}

impl Node {
	pub fn new(addrs: Vec<String>) -> Result<Node> {
		let mut peers = HashMap::new();
		let (send_to_parent, recv) = mpsc::channel();

		for (i, addr) in addrs.iter().enumerate() {
			println!("trying to connect to: {}", addr);
			let writer = match TcpStream::connect(addr.clone()) {
				Ok(stream) => stream,
				Err(e) => {
					println!("failed to connect to peer: {}: {}", addr, e.to_string());
					continue;
				}
			};

			let mut reader = writer.try_clone().unwrap();
			let send_to_parent = send_to_parent.clone();
			// let handle = 
			thread::spawn(move || {
				loop {
					let message = reader.receive().unwrap();
					send_to_parent.send((i, message)).unwrap();
				}
			});
			
			peers.insert(i, PeerHandle {
				writer,
				// handle,
				addr: addr.clone(),
				info: None,
				handshake_complete: false,
				config: Config::default(),
			});

			println!("Connected to: {}", addr);
		}

		if peers.len() == 0 {
			return Err(Err::NetworkError("no peers connected!".to_owned()));
		}

		println!("{} peers conntected.", peers.len());
		
		Ok(Node {
			peers,
			recv,
			mempool: Mempool::new(),
		})
	}

	fn handle_message(&mut self, peer_index: usize, m: Message) -> Result<()> {
		match m.take_payload() {
			Payload::Version(payload) => self.handle_version_message(peer_index, payload),
			Payload::Verack => self.handle_verack_message(peer_index),
			Payload::FeeFilter(filter) => self.handle_feefilter_message(peer_index, filter),
			Payload::WTxIdRelay => self.handle_wtxidrelay_message(peer_index),
			Payload::SendAddrV2 => self.handle_sendaddrv2_message(peer_index),
			Payload::Ping(ping) => self.handle_ping_message(peer_index, ping),
			Payload::Inv(inv) => self.handle_inv_message(peer_index, inv),
			Payload::Tx(id, tx) => self.handle_tx_message(peer_index, id, tx),
			p => {
				println!("peer {}: {}: no response implemented\n", peer_index, p.name());
				Ok(())
			},
		}
	}

	fn handle_version_message(&mut self, peer_index: usize, payload: Version) -> Result<()> {
		if let Some(peer) = self.peers.get_mut(&peer_index) {
			if !peer.handshake_complete && peer.info.is_none() {
				peer.info = Some(payload);
				peer.writer.send(Message::verack())?;
			}
		}
		Ok(())
	}
	
	fn handle_ping_message(&mut self, peer_index: usize, payload: Ping) -> Result<()> {
		if let Some(peer) = self.peers.get_mut(&peer_index) {
			peer.writer.send(Message::pong(payload.nonce()))?;
		}
		Ok(())
	}

	fn handle_verack_message(&mut self, peer_index: usize) -> Result<()> {
		if let Some(peer) = self.peers.get_mut(&peer_index) {
			if !peer.handshake_complete {
				if  peer.info.is_none() {
					return Err(Err::NetworkError("failed to complete handshake (missing version message)".to_owned()));
				}
				peer.handshake_complete = true;
			}
		}
		Ok(())
	}

	fn handle_feefilter_message(&mut self, peer_index: usize, feefilter: FeeFilter) -> Result<()> {
		if let Some(peer) = self.peers.get_mut(&peer_index) {
			peer.config.feerate = feefilter.feerate();
			println!("SET PARAM: feerate = {}\n", peer.config.feerate);
		}
		Ok(())
	}

	fn handle_wtxidrelay_message(&mut self, peer_index: usize) -> Result<()> {
		if let Some(peer) = self.peers.get_mut(&peer_index) {
			if !peer.handshake_complete {
				peer.config.wxtxid = true;
				println!("SET PARAM: wxtxid = true\n");
			}
		}
		Ok(())
	}

	fn handle_sendaddrv2_message(&mut self, peer_index: usize) -> Result<()> {
		if let Some(peer) = self.peers.get_mut(&peer_index) {
			if !peer.handshake_complete {
				peer.config.addrv2 = true;
				println!("SET PARAM: addrv2 = true\n");
			}
		}
		Ok(())
	}

	fn handle_inv_message(&mut self, peer_index: usize, inv: Inv) -> Result<()> {
		let mut items = Vec::new();
		for item in inv.items().iter() {
			match item.object_type {
				InvType::Tx => {
					if !self.mempool.contains(item.hash) {
						items.push(item.clone());
					}
				},
				//self.mempool.add_tx_id(item.hash),
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

		if items.len() > 0 {
			self.peers.get_mut(&peer_index).unwrap().writer.send(Message::getdata(items))?;
		}

		Ok(())
	}

	fn handle_tx_message(&mut self, _peer_index: usize, id: Sha256, tx: Tx) -> Result<()> {
		self.mempool.add_tx(id, tx);
		Ok(())
	}
	
	pub fn run(mut self) -> Result<()> {
		for (i, peer) in self.peers.iter_mut() {
			if let Err(e) = peer.writer.send(Message::version(peer.addr.clone())) {
				println!("peer {}: error: {}", i, e);
			}
		}
		
		let (send, recv) = mpsc::channel();
		let t = thread::spawn(move || {
			'outer: loop {
				while let Ok((i, m)) = self.recv.try_recv() {
					if let Err(e) = self.handle_message(i, m) {
						println!("{}", e);
					}
				}
				while let Ok(m) = recv.try_recv() {
					match m {
						ApplicationMessage::Shutdown => {		
							println!("shutting down...");
							break 'outer;
						},
						ApplicationMessage::ShowMempool => {
							println!("{}", JsonValue::object(
								self.mempool.txs.iter().map(|(id, tx)| {
									(format!("{}", id), tx.into_json())
								})));
						},
					}
				}
				
				thread::yield_now();
			}
		});

		let stdin = std::io::stdin();
		
		loop {
			let mut buf = String::new();
			stdin.read_line(&mut buf).unwrap();
			match buf.trim() {
				"exit" => {
					send.send(ApplicationMessage::Shutdown).unwrap();
					break;
				},
				"mempool" => {
					send.send(ApplicationMessage::ShowMempool).unwrap();
				}
				_ => {},
			}
		}

		t.join().unwrap();
		Ok(())
	}
}

fn main() -> Result<()> {
	let addrs = std::env::args().skip(1).collect();
	let node = Node::new(addrs)?;
	node.run()
}