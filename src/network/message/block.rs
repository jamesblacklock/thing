use std::{
	io::{
		Read,
		Write,
	},
	collections::HashMap,
	collections::HashSet,
};

use crate::{
	json::*,
	network::{
		Deserialize,
		Serialize,
	},
	err::*,
	common::*,
	crypto::sha256::Sha256,
	script::*,
};

use super::{
	Header,
	Tx,
	TxInput,
	TxOutput,
};

#[derive(PartialEq, Eq, Hash, Debug, Clone)]
pub struct UTXOID(pub Sha256, pub u32);

pub struct UTXOState<'a> {
	base: &'a HashMap<UTXOID, TxOutput>,
	added: HashMap<UTXOID, TxOutput>,
	removed: HashSet<UTXOID>,
	block_height: usize,
	pub tx_fee: u64,
}

pub struct UTXODiff {
	added: HashMap<UTXOID, TxOutput>,
	removed: HashSet<UTXOID>,
}

#[must_use]
pub enum ValidationResult {
	Valid(UTXODiff),
	Invalid
}

impl <'a> UTXOState<'a> {
	pub fn new(utxos: &'a HashMap<UTXOID, TxOutput>, block_height: usize) -> Self {
		UTXOState {
			base: utxos,
			added: HashMap::new(),
			removed: HashSet::new(),
			block_height,
			tx_fee: 0,
		}
	}

	pub fn block_height(&self) -> usize {
		self.block_height
	}
	
	pub fn contains(&self, id: &UTXOID) -> bool {
		!self.removed.contains(id) &&
		(self.base.contains_key(id) || self.added.contains_key(id))
	}

	pub fn add(&mut self, id: UTXOID, utxo: TxOutput) {
		self.added.insert(id, utxo);
	}

	#[must_use]
	pub fn remove(&mut self, id: UTXOID) -> TxOutput {
		if self.base.contains_key(&id) {
			let utxo = self.base[&id].clone();
			assert!(self.removed.insert(id) == true);
			utxo
		} else {
			self.added.remove(&id).unwrap()
		}
	}

	pub fn diff(self) -> UTXODiff {
		UTXODiff {
			added: self.added,
			removed: self.removed,
		}
	}
}

impl UTXODiff {
	pub fn apply(self, utxos: &mut HashMap<UTXOID, TxOutput>) {
		for k in self.removed {
			// println!("removed UTXO: {:?}", k);
			utxos.remove(&k).unwrap();
		}
		for (k, v) in self.added {
			// println!("added UTXO: {:?}", k);
			let replaced = utxos.insert(k.clone(), v);
			if !replaced.is_none() {
				// TODO: implement BIP 30 & BIP 34
				log_warn!("UTXO with duplicate ID added to UTXO set!");
				log_warn!("(this is known to have happened only twice and should not happen again)");
				log_warn!("UTXO: {:?}", k);
			}
		}
	}
}

pub struct Block {
	pub header: Header,
	pub txs: Vec<Tx>,
}

pub const GENESIS_BLOCK_HASH: &str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

impl Block {
	pub fn genesis() -> Self {
		let mut input = TxInput::default();
		input.index = 0xffff_ffff;
		input.unlock
			.append(Op::data_u32(486604799))
			.append(Op::data_u8(4))
			.append(Op::data_str("The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"));
		let mut output = TxOutput::default();
		output.value = 50 * SAT_PER_COIN;
		output.lock
			.append(Op::data_hex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"))
			.append(Op::CHECKSIG);
		let mut tx = Tx::default();
		tx.inputs.push(input);
		tx.outputs.push(output);

		let merkle_root = tx.compute_hash();

		let block = Block {
			header: Header {
				version: 1,
				prev_block: Sha256::default(),
				merkle_root,
				timestamp: 1231006505,
				bits: 0x1d00ffff,
				nonce: 2083236893,
				tx_count: 1,
			},
			txs: vec![tx],
		};

		let genesis_merkle_root = Sha256::try_from("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b").unwrap();
		let genesis_block_hash = Sha256::try_from(GENESIS_BLOCK_HASH).unwrap();
		let block_hash = block.header.compute_hash();

		assert!(merkle_root == genesis_merkle_root, "{} != {}", merkle_root, genesis_merkle_root);
		assert!(block_hash == genesis_block_hash, "{} != {}", block_hash, genesis_block_hash);

		block
	}

	#[must_use]
	pub fn validate(&self, utxos: &mut HashMap<UTXOID, TxOutput>, block_height: usize) -> ValidationResult {
		if Tx::check_merkle_root(&self.txs, self.header.merkle_root) == false {
			return ValidationResult::Invalid;
		}
		
		let mut state = UTXOState::new(utxos, block_height);
		let count = self.txs.len();
		log_trace!("  validating {} txs...", count);
		for (i, tx) in self.txs.iter().enumerate().skip(1) {
			if tx.validate(&mut state, false) == false {
				return ValidationResult::Invalid;
			}

			log_trace!("  validated tx {}/{}", i, count);
		}

		if self.txs[0].validate(&mut state, true) == false {
			return ValidationResult::Invalid;
		}

		log_trace!("  validated coinbase tx");
		ValidationResult::Valid(state.diff())
	}
}

impl ToJson for Block {
	fn to_json(&self) -> JsonValue {
		JsonValue::object([
			("header", self.header.to_json()),
			("txs", JsonValue::array(self.txs.iter().map(|e| e.to_json()))),
		])
	}
}

impl Deserialize for Block {
	fn deserialize(stream: &mut dyn Read) -> Result<Self> {
		let header = Header::deserialize(stream)?;
		let mut txs = Vec::new();
		for _ in 0..header.tx_count() {
			txs.push(Tx::deserialize(stream)?);
		}

		Ok(Block {
			header,
			txs,
		})
	}
}

impl Serialize for Block {
	fn serialize(&self, stream: &mut dyn Write) -> Result<()> {
		self.header.serialize(stream)?;
		assert!(self.header.tx_count() == self.txs.len());
		for tx in self.txs.iter() {
			tx.serialize(stream)?;
		}
		
		Ok(())
	}
}
