#![feature(try_blocks)]

use std::{
	collections::{HashMap, HashSet},
	net::{TcpStream},
	sync::mpsc,
	sync::mpsc::{Receiver},
	thread,
	io::Write,
	io::BufReader,
	io::BufRead,
};

#[macro_use]
mod log;
mod err;
mod common;
mod json;
mod network;
mod script;
mod crypto;

use crypto::sha256::Sha256;

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
		GENESIS_BLOCK_HASH,
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

#[derive(Debug)]
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
			blocks_requested: 1,
			blocks_validated: 1,
			hashes: vec![genesis_hash],
			headers: HashMap::from([(genesis_hash, genesis)]),
		}
	}

	fn load() -> Self {
		use std::path::Path;
		const HEADERS_PATH: &str = "./data/block_db/headers.dat";
		const IDS_PATH: &str = "./data/block_db/ids.txt";
		let mut db = BlocksDB::new();

		if Path::new(HEADERS_PATH).is_file() && Path::new(IDS_PATH).is_file() {
			let mut headers_file = match std::fs::File::open(HEADERS_PATH) {
				Ok(file) => file,
				Err(err) => {
					eprintln!("warning: failed to load headers.dat: {}", err.to_string());
					return db;
				}
			};
			let ids_file = match std::fs::File::open(IDS_PATH) {
				Ok(file) => file,
				Err(err) => {
					eprintln!("warning: failed to load ids.txt: {}", err.to_string());
					return db;
				}
			};

			let mut hashes = db.hashes.clone();
			let mut headers = db.headers.clone();
			for hash in BufReader::new(ids_file).lines() {
				let hash = match hash {
					Ok(hash) => hash,
					Err(err) => {
						eprintln!("warning: failed to read from ids.txt: {}", err.to_string());
						return db;
					}
				};
				let hash = match Sha256::try_from(hash.as_str()) {
					Ok(hash) => hash,
					Err(_) => {
						eprintln!("warning: ids.txt contains invalid hash: {}", hash);
						return db;
					}
				};
				let header = match Header::deserialize(&mut headers_file) {
					Ok(header) => header,
					Err(_) => {
						eprintln!("warning: headers.dat is corrupt");
						return db;
					}
				};
				hashes.push(hash);
				headers.insert(hash, header);
			}

			db.blocks_requested = hashes.len();
			db.blocks_validated = hashes.len();
			db.hashes = hashes;
			db.headers = headers;
		}

		db
	}

	fn save(&self) {
		if let Err(err) = std::fs::create_dir_all("./data/block_db") {
			eprintln!("warning: failed to save block_db state: {}", err.to_string());
			return;
		}
		let mut file = match std::fs::File::create("./data/block_db/headers.dat") {
			Ok(file) => file,
			Err(err) => {
				eprintln!("warning: failed to save block_db state: {}", err.to_string());
				return;
			}
		};
		for hash in self.hashes.iter() {
			let header = self.headers.get(hash)
				.expect("warning: hashes Vec contains a hash that is missing from headers HashMap (this should never happen)");
			if let Err(err) = header.serialize(&mut file) {
				eprintln!("warning: failed to save block_db state: {}", err.to_string());
				return;
			}
		}
	}

	fn store_block(&self, block: Block) -> Result<()> {
		let hash = block.header.compute_hash();
		if self.has_block(hash) {
			return Ok(());
		}
		std::fs::create_dir_all("./data/block_db")
			.map_err(|err| Err::IOError(err.to_string()))?;
		let mut file = std::fs::File::create(format!("./data/block_db/{}.dat", hash))
			.map_err(|err| Err::IOError(err.to_string()))?;
		let mut ids = std::fs::OpenOptions::new()
			.create(true)
			.append(true)
            .open("./data/block_db/ids.txt")
			.map_err(|err| Err::IOError(err.to_string()))?;
		
		block.serialize(&mut file)?;
		writeln!(ids, "{}", hash).map_err(|err| Err::IOError(err.to_string()))?;

		Ok(())
	}

	fn load_block(&self, hash: Sha256) -> Result<Block> {
		if hash == GENESIS_BLOCK_HASH.try_into().unwrap() {
			return Ok(Block::genesis())
		}
		let mut file = std::fs::File::open(format!("./data/block_db/{}.dat", hash))
			.map_err(|err| Err::IOError(err.to_string()))?;
		Block::deserialize(&mut file)
	}

	fn has_block(&self, hash: Sha256) -> bool {
		std::path::Path::new(&format!("./data/block_db/{}.block", hash)).is_file()
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
	ShowUTXOs,
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
		
		let node = Node {
			peers,
			recv,
			mempool: Mempool::new(),
			block_db: BlocksDB::load(),
			utxos: Node::load_utxos(),
		};

		Ok(node)
	}

	fn load_utxos() -> HashMap<UTXOID, TxOutput> {
		use std::path::Path;

		const UTXOS_PATH: &str = "./data/utxos.dat";
		
		if Path::new(UTXOS_PATH).is_file() {
			let mut utxos_file = match std::fs::File::open(UTXOS_PATH) {
				Ok(file) => file,
				Err(err) => {
					eprintln!("warning: failed to load utxos.dat: {}", err.to_string());
					return HashMap::new();
				}
			};

			let result: Result<_> = try {
				let count = common::read_u64(&mut utxos_file)?;
				let mut utxos = HashMap::new();
				for _ in 0..count {
					let hash = common::read_sha256(&mut utxos_file)?;
					let index = common::read_u32(&mut utxos_file)?;
					let utxo = TxOutput::deserialize(&mut utxos_file)?;
					utxos.insert(UTXOID(hash, index), utxo);
				}
				utxos
			};

			match result {
				Ok(utxos) => {
					return utxos
				},
				Err(err) => {
					eprintln!("warning: failed to save utxo set: {}", err.to_string());
					return HashMap::new();
				},
			}
		}

		return HashMap::new();
	}

	fn save_utxos(&self) {
		if self.utxos.len() == 0 {
			return;
		}

		let mut file = match std::fs::File::create("./data/utxos.dat") {
			Ok(file) => file,
			Err(err) => {
				eprintln!("warning: failed to save utxo set: {}", err.to_string());
				return;
			}
		};
		let result: Result<()> = try {
			common::write_u64(&mut file, self.utxos.len() as u64)?;
			for (k, v) in self.utxos.iter() {
				common::write_sha256(&mut file, &k.0)?;
				common::write_u32(&mut file, k.1)?;
				v.serialize(&mut file)?;
			}
		};

		if let Err(err) = result {
			eprintln!("warning: failed to save utxo set: {}", err.to_string());
		}
	}

	fn shutdown(self) {
		self.block_db.save();
		self.save_utxos();
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

			if self.block_db.blocks_requested < 211_000 {
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
		if let ValidationResult::Valid(diff) = block.validate(&mut self.utxos, self.block_db.blocks_validated) {
			self.block_db.store_block(block)?;
			// if self.block_db.blocks_validated == 91842 {
			// 	println!("{}", diff.added.values().collect::<Vec<_>>()[0].to_json());
			// 	println!("{}", self.utxos[diff.added.keys().collect::<Vec<_>>()[0]].to_json());
			// 	println!();
			// }
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
			loop {
				if let Ok((i, m)) = self.recv.try_recv() {
					if let Err(e) = self.handle_message(i, m) {
						log_error!("{}", e);
					}
				}
				if let Ok(m) = recv_cmd.try_recv() {
					match m {
						ApplicationMessage::Shutdown => {		
							println!("<shutting down>");
							self.shutdown();
							send_cmd_done.send(()).unwrap();
							break;
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
							for (i, hash) in self.block_db.hashes.iter().take(self.block_db.blocks_validated).enumerate() {
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
						ApplicationMessage::ShowUTXOs => {
							if self.utxos.len() == 0 {
								println!("<empty>");
							}
							for (id, utxo) in self.utxos.iter() {
								println!("{:?}:\n{}\n", id, utxo.to_json());
							}
						},
					}
					send_cmd_done.send(()).unwrap();
				}
				
				thread::yield_now();
			}
		});

		let stdin = std::io::stdin();
		let mut stdout = std::io::stdout();

		let send_cmd_ctrlc = send_cmd.clone();
		ctrlc::set_handler(move || send_cmd_ctrlc.send(ApplicationMessage::Shutdown).unwrap()).unwrap();
		
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
				["utxos"] => {
					send_cmd.send(ApplicationMessage::ShowUTXOs).unwrap();
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