use std::{
	io::{
		Read,
		Write,
	},
};

use crate::{
	json::*,
	network::{
		Deserialize,
		Serialize,
	},
	err::*,
	common::*,
	sha256::Sha256,
	script::*,
};

use super::{
	Header,
	Tx,
	TxInput,
	TxOutput,
};

pub struct Block {
	pub header: Header,
	pub txs: Vec<Tx>,
}

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

		let txs = vec![tx];

		let merkle_root = Tx::compute_merkle_root(&txs);

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
			txs,
		};

		let genesis_merkle_root = Sha256::try_from("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b").unwrap();
		let genesis_block_hash = Sha256::try_from("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f").unwrap();
		let block_hash = block.header.compute_hash();

		assert!(merkle_root == genesis_merkle_root, "{} != {}", merkle_root, genesis_merkle_root);
		assert!(block_hash == genesis_block_hash, "{} != {}", block_hash, genesis_block_hash);

		block
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
