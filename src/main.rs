#![feature(try_blocks)]

use std::{
	collections::{HashMap, HashSet},
	net::{TcpStream},
	sync::mpsc,
	sync::mpsc::{Receiver},
	thread,
	io::Write,
};

#[macro_use]
mod log;
mod err;
mod common;
mod sha256;
mod json;
mod network;
mod script;

use sha256::Sha256;

use network::{
	Peer,
	Serialize,
	Deserialize,
	message::{
		Message,
		Payload,
		Version,
		Ping,
		Inv,
		InvType,
		InvItem,
		Tx,
		UTXOID,
		TxOutput,
		FeeFilter,
		Block,
		Header,
		Headers,
		ValidationResult,
	}
};

use err::*;
use json::*;

#[derive(Default)]
struct Config {
	wxtxid: bool,
	addrv2: bool,
	sendheaders: bool,
	feerate: u64,
}

struct BlocksDB {
	blocks_requested: usize,
	blocks_validated: usize,
	hashes: Vec<Sha256>,
	headers: HashMap<Sha256, Header>,
}

impl BlocksDB {
	fn new() -> Self {
		let genesis = Block::genesis().header;
		let genesis_hash = genesis.compute_hash();
		BlocksDB {
			blocks_requested: 0,
			blocks_validated: 0,
			hashes: vec![genesis_hash],
			headers: HashMap::from([(genesis_hash, genesis)]),
		}
	}

	fn store_block(&self, block: Block) -> Result<()> {
		let hash = block.header.compute_hash();
		if self.has_block(hash) {
			return Ok(());
		}
		std::fs::create_dir_all("./data/block_db")
			.map_err(|err| Err::IOError(err.to_string()))?;
		let mut file = std::fs::File::create(format!("./data/block_db/{}.block", hash))
			.map_err(|err| Err::IOError(err.to_string()))?;
		block.serialize(&mut file)?;
		Ok(())
	}

	fn load_block(&self, hash: Sha256) -> Result<Block> {
		let mut file = std::fs::File::open(format!("./data/block_db/{}.block", hash))
			.map_err(|err| Err::IOError(err.to_string()))?;
		Block::deserialize(&mut file)
	}

	fn has_block(&self, hash: Sha256) -> bool {
		std::path::Path::new(&format!("./data/block_db/{}.block", hash)).exists()
	}
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
			log_trace!("tx already in mempool: {}", id);
		} else {
			log_debug!("add tx to mempool: {}", id);
			self.txs.insert(id, tx);
		}
	}

	fn contains(&self, id: Sha256) -> bool {
		self.pending.contains(&id) || self.txs.contains_key(&id)
	}
}


enum ApplicationMessage {
	ShowMempool,
	ShowBlockHashes,
	ShowHeader(String),
	ShowBlock(String),
	ShowTx(String),
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
	block_db: BlocksDB,
	utxos: HashMap<UTXOID, TxOutput>,
}

impl Node {
	pub fn new(addrs: Vec<String>) -> Result<Node> {
		let mut peers = HashMap::new();
		let (send_to_parent, recv) = mpsc::channel();

		for (i, addr) in addrs.iter().enumerate() {
			log_info!("trying to connect to: {}", addr);
			let writer = match TcpStream::connect(addr.clone()) {
				Ok(stream) => stream,
				Err(e) => {
					log_error!("failed to connect to peer: {}: {}", addr, e.to_string());
					continue;
				}
			};

			let mut reader = writer.try_clone().unwrap();
			let send_to_parent = send_to_parent.clone();
			// let handle = 
			thread::spawn(move || {
				while let Some(message) = reader.receive().unwrap() {
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

			log_info!("Connected to: {}", addr);
		}

		if peers.len() == 0 {
			return Err(Err::NetworkError("no peers connected!".to_owned()));
		}

		log_debug!("{} peers conntected.", peers.len());
		
		Ok(Node {
			peers,
			recv,
			mempool: Mempool::new(),
			block_db: BlocksDB::new(),
			utxos: HashMap::new(),
		})
	}

	fn handle_message(&mut self, peer_index: usize, m: Message) -> Result<()> {
		match m.take_payload() {
			Payload::Version(payload)  => self.handle_version_message(peer_index, payload),
			Payload::Verack            => self.handle_verack_message(peer_index),
			Payload::FeeFilter(filter) => self.handle_feefilter_message(peer_index, filter),
			Payload::WTxIdRelay        => self.handle_wtxidrelay_message(peer_index),
			Payload::SendAddrV2        => self.handle_sendaddrv2_message(peer_index),
			Payload::Ping(payload)     => self.handle_ping_message(peer_index, payload),
			Payload::Inv(payload)      => self.handle_inv_message(peer_index, payload),
			Payload::Tx(id, payload)   => self.handle_tx_message(peer_index, id, payload),
			Payload::SendHeaders       => self.handle_sendheaders_message(peer_index),
			Payload::Headers(payload)  => self.handle_headers_message(peer_index, payload),
			Payload::Block(payload)    => self.handle_block_message(peer_index, payload),
			p => {
				log_debug!("peer {}: {}: no response implemented\n", peer_index, p.name());
				Ok(())
			},
		}
	}

	fn handle_version_message(&mut self, peer_index: usize, payload: Version) -> Result<()> {
		if let Some(peer) = self.peers.get_mut(&peer_index) {
			if !peer.handshake_complete && peer.info.is_none() {
				peer.info = Some(payload);
				peer.writer.send(Message::verack())?;
				peer.writer.send(Message::sendheaders())?;
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

				peer.writer.send(Message::getheaders(&self.block_db.hashes))?;
			}
		}
		Ok(())
	}

	fn handle_feefilter_message(&mut self, peer_index: usize, feefilter: FeeFilter) -> Result<()> {
		if let Some(peer) = self.peers.get_mut(&peer_index) {
			peer.config.feerate = feefilter.feerate();
			log_debug!("SET PARAM: feerate = {}\n", peer.config.feerate);
		}
		Ok(())
	}

	fn handle_wtxidrelay_message(&mut self, peer_index: usize) -> Result<()> {
		if let Some(peer) = self.peers.get_mut(&peer_index) {
			if !peer.handshake_complete {
				peer.config.wxtxid = true;
				log_debug!("SET PARAM: wxtxid = true\n");
			}
		}
		Ok(())
	}

	fn handle_sendaddrv2_message(&mut self, peer_index: usize) -> Result<()> {
		if let Some(peer) = self.peers.get_mut(&peer_index) {
			if !peer.handshake_complete {
				peer.config.addrv2 = true;
				log_debug!("SET PARAM: addrv2 = true\n");
			}
		}
		Ok(())
	}

	fn handle_sendheaders_message(&mut self, peer_index: usize) -> Result<()> {
		if let Some(peer) = self.peers.get_mut(&peer_index) {
			peer.config.sendheaders = true;
			log_debug!("SET PARAM: sendheaders = true\n");
		}
		Ok(())
	}

	fn handle_headers_message(&mut self, peer_index: usize, headers: Headers) -> Result<()> {
		for header in headers {
			let last = *self.block_db.hashes.last().unwrap();
			if header.prev_block == last {
				let hash = header.compute_hash();
				self.block_db.headers.insert(hash, header);
				self.block_db.hashes.push(hash);
			} else {
				unimplemented!();
			}
		}

		if let Some(peer) = self.peers.get_mut(&peer_index) {
			let m = Message::getheaders(&self.block_db.hashes);
			peer.writer.send(m)?;

			if self.block_db.blocks_requested < 10000 {
				let have = self.block_db.blocks_requested;
				let need = &self.block_db.hashes[have..have+500];
				self.block_db.blocks_requested += 500;
				let need = need.iter()
					.filter(|e| !self.block_db.has_block(**e))
					.map(|e| InvItem::new(InvType::Block, e.clone()))
					.collect::<Vec<_>>();
				if need.len() > 0 {	
					let m = Message::getdata(need);
					peer.writer.send(m)?;
				}
			}
		}

		Ok(())
	}

	fn handle_block_message(&mut self, _peer_index: usize, block: Block) -> Result<()> {
		if self.block_db.blocks_validated == 2817 {
			println!();
		}
		if let ValidationResult::Valid(diff) = block.validate(&mut self.utxos) {
			self.block_db.store_block(block)?;
			diff.apply(&mut self.utxos);
			self.block_db.blocks_validated += 1;
		} else {
			panic!();
		}
		Ok(())
	}

	fn handle_inv_message(&mut self, peer_index: usize, inv: Inv) -> Result<()> {
		let mut items = Vec::new();
		for item in inv.iter() {
			match item.object_type {
				InvType::Tx => {
					if !self.mempool.contains(item.hash) {
						items.push(item.clone());
					}
				},
				InvType::Block => {
					// items.push(item.clone());
				},
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

	fn show_object<T, F>(id: String, f: F)
		where T: ToJson, F: FnOnce(Sha256) -> Option<T> {
		let found = if let Ok(id) = Sha256::try_from(id.as_str()) {
			println!("got id: {}", id);
			if let Some(object) = f(id) {
				println!("{}", object.to_json());
				true
			} else {
				false
			}
		} else {
			false
		};
		if !found {
			println!("<not found>");
		}
	}
	
	pub fn run(mut self) -> Result<()> {
		for (i, peer) in self.peers.iter_mut() {
			if let Err(e) = peer.writer.send(Message::version(peer.addr.clone())) {
				log_error!("peer {}: error: {}", i, e);
			}
		}
		
		let (send_cmd, recv_cmd) = mpsc::channel();
		let (send_cmd_done, recv_cmd_done) = mpsc::channel();
		let t = thread::spawn(move || {
			'outer: loop {
				while let Ok((i, m)) = self.recv.try_recv() {
					if let Err(e) = self.handle_message(i, m) {
						log_error!("{}", e);
					}
				}
				while let Ok(m) = recv_cmd.try_recv() {
					match m {
						ApplicationMessage::Shutdown => {		
							println!("<shutting down>");
							send_cmd_done.send(()).unwrap();
							break 'outer;
						},
						ApplicationMessage::ShowMempool => {
							if self.mempool.txs.len() == 0 {
								println!("<empty>");
							}
							for id in self.mempool.txs.keys() {
								println!("{}", id);
							}
						},
						ApplicationMessage::ShowBlockHashes => {
							for (i, hash) in self.block_db.hashes.iter().take(self.block_db.blocks_requested).enumerate() {
								println!("{:010}: {}", i, hash);
							}
						},
						ApplicationMessage::ShowHeader(id) => {
							Node::show_object(id, |id| self.block_db.headers.get(&id).map(|e| e.clone()));
						},
						ApplicationMessage::ShowBlock(id) => {
							Node::show_object(id, |id| self.block_db.load_block(id).ok());
						},
						ApplicationMessage::ShowTx(id) => {
							Node::show_object(id, |id| self.mempool.txs.get(&id).map(|e| e.clone()));
						},
					}
					send_cmd_done.send(()).unwrap();
				}
				
				thread::yield_now();
			}
		});

		let stdin = std::io::stdin();
		let mut stdout = std::io::stdout();
		
		loop {
			let mut buf = String::new();
			stdout.write(">> ".as_bytes()).unwrap();
			stdout.flush().unwrap();
			stdin.read_line(&mut buf).unwrap();
			let tok: Vec<_> = buf.split_ascii_whitespace().collect();
			match *tok {
				["exit"] => {
					send_cmd.send(ApplicationMessage::Shutdown).unwrap();
					recv_cmd_done.recv().unwrap();
					break;
				},
				["mempool"] => {
					send_cmd.send(ApplicationMessage::ShowMempool).unwrap();
					recv_cmd_done.recv().unwrap();
				},
				["db"] => {
					send_cmd.send(ApplicationMessage::ShowBlockHashes).unwrap();
					recv_cmd_done.recv().unwrap();
				},
				["header", id] => {
					send_cmd.send(ApplicationMessage::ShowHeader(id.into())).unwrap();
					recv_cmd_done.recv().unwrap();
				},
				["block", id] => {
					send_cmd.send(ApplicationMessage::ShowBlock(id.into())).unwrap();
					recv_cmd_done.recv().unwrap();
				},
				["tx", id] => {
					send_cmd.send(ApplicationMessage::ShowTx(id.into())).unwrap();
					recv_cmd_done.recv().unwrap();
				},
				[] => {},
				_ => {
					println!("<invalid command>");
				},
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