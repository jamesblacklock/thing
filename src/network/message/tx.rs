use std::{
	io::{Read, Write},
};

use crate::{
	State,
	err::*,
	json::*,
	crypto::sha256::*,
	script::*,
	common::SAT_PER_COIN,
};

use crate::common::{
	read_u8,
	read_u32,
	read_u64,
	read_sha256,
	read_var_int,
	read_buf_exact,
	write_u16_be,
	write_u32,
	write_u64,
	write_sha256,
	write_var_int,
	write_buf_exact,
	serialize,
};

use super::{
	Deserialize,
	Serialize,
	block::{UTXOState, UTXOID},
};

#[derive(Clone, Copy)]
pub enum AbsoluteLockTime {
	BlockNumber(u32),
	Timestamp(u32),
	None,
}

impl AbsoluteLockTime {
	pub fn from_u32(n: u32) -> Self {
		match n {
			0 => AbsoluteLockTime::None,
			x if x < 500000000 => AbsoluteLockTime::BlockNumber(x),
			x => AbsoluteLockTime::Timestamp(x),
		}
	}
}

impl ToJson for AbsoluteLockTime {
	fn to_json(&self) -> JsonValue {
		match *self {
			AbsoluteLockTime::BlockNumber(n) => JsonValue::object([("block", JsonValue::number(n))]),
			AbsoluteLockTime::Timestamp(n) => JsonValue::object([("timestamp", JsonValue::number(n))]),
			AbsoluteLockTime::None => JsonValue::null(),
		}
	}
}

impl Serialize for AbsoluteLockTime {
	fn serialize(&self, stream: &mut dyn Write) -> Result<()> {
		let n = match *self {
			AbsoluteLockTime::None => 0,
			AbsoluteLockTime::BlockNumber(n) => n,
			AbsoluteLockTime::Timestamp(n) => n,
		};
		write_u32(stream, n)
	}
}

impl Deserialize for AbsoluteLockTime {
	fn deserialize(stream: &mut dyn Read) -> Result<AbsoluteLockTime> {
		Ok(AbsoluteLockTime::from_u32(read_u32(stream)?))
	}
}

#[derive(Clone, Copy)]
enum RelativeLockTime {
	Blocks(u32),
	Seconds(u32),
	None,
}

impl ToJson for RelativeLockTime {
	fn to_json(&self) -> JsonValue {
		match *self {
			RelativeLockTime::Blocks(n) => JsonValue::object([("blocks", JsonValue::number(n))]),
			RelativeLockTime::Seconds(n) => JsonValue::object([("seconds", JsonValue::number(n))]),
			RelativeLockTime::None => JsonValue::null(),
		}
	}
}

const RELATIVE_LOCK_TIME_DISABLE: u32 = 1 << 31;
const RELATIVE_LOCK_TIME_SECONDS: u32 = 1 << 22;
const RELATIVE_LOCK_TIME_VALUE: u32   = 0xffff;

impl From<u32> for RelativeLockTime {
	fn from(n: u32) -> RelativeLockTime {
		let disable     = n & RELATIVE_LOCK_TIME_DISABLE != 0;
		let use_seconds = n & RELATIVE_LOCK_TIME_SECONDS != 0;
		let value       = n & RELATIVE_LOCK_TIME_VALUE;
		if disable {
			RelativeLockTime::None
		} else if use_seconds {
			RelativeLockTime::Seconds(value * 512)
		} else {
			RelativeLockTime::Blocks(value)
		}
	}
}

#[derive(Clone)]
pub struct TxInput {
	pub tx_hash: Sha256,
	pub index: u32,
	pub unlock: Script,
	pub witness: Vec<Vec<u8>>,
	pub sequence: u32,
}

type Input = TxInput;

impl Input {
	fn utxo_id(&self) -> UTXOID {
		UTXOID(self.tx_hash, self.index)
	}

	fn rel_lock_time(&self) -> RelativeLockTime {
		RelativeLockTime::from(self.sequence)
	}
}

impl ToJson for Input {
	fn to_json(&self) -> JsonValue {
		JsonValue::object([
			("tx_hash", JsonValue::string(format!("{}", self.tx_hash))),
			("index", JsonValue::number(self.index)),
			("unlock", JsonValue::string(format!("{}", self.unlock))),
			("witness", JsonValue::string(format!("{:?}", self.witness))),
			("rel_lock_time", self.rel_lock_time().to_json()),
		])
	}
}

impl Default for Input {
	fn default() -> Self {
		Input {
			tx_hash: Sha256::default(),
			index: 0,
			unlock: Script::new(),
			witness: Vec::new(),
			sequence: 0xffff_ffff,
		}
	}
}

impl Deserialize for Input {
	fn deserialize(stream: &mut dyn Read) -> Result<Self> {
        let tx_hash = read_sha256(stream)?;
		let index = read_u32(stream)?;
		let unlock_size = read_var_int(stream)? as usize;
		let mut unlock = vec![0; unlock_size];
		read_buf_exact(stream, &mut unlock)?;
		let sequence = read_u32(stream)?;

		Ok(Input {
			tx_hash,
			index,
			unlock: Script::from(unlock),
			witness: Vec::new(),
			sequence,
		})
	}
}

impl Serialize for Input {
	fn serialize(&self, stream: &mut dyn Write) -> Result<()> {
        write_sha256(stream, &self.tx_hash)?;
		write_u32(stream, self.index)?;
		write_var_int(stream, self.unlock.len() as u64)?;
		write_buf_exact(stream, self.unlock.as_bytes())?;
		write_u32(stream, self.sequence)
	}
}

#[derive(Clone)]
pub struct TxOutput {
	pub value: u64,
	pub lock: Script,
}

type Output = TxOutput;

impl ToJson for Output {
	fn to_json(&self) -> JsonValue {
		JsonValue::object([
			("value", JsonValue::number(self.value)),
			("lock", JsonValue::string(format!("{}", self.lock))),
		])
	}
}

impl std::fmt::Debug for TxOutput {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(f, "{}", self.to_json())
	}
}

impl Default for Output {
	fn default() -> Self {
		Output {
			value: 0,
			lock: Script::new(),
		}
	}
}

impl Deserialize for Output {
	fn deserialize(stream: &mut dyn Read) -> Result<Self> {
		let value = read_u64(stream)?;
		let lock_length = read_var_int(stream)? as usize;
		let mut lock = vec![0; lock_length];
		read_buf_exact(stream, &mut lock)?;

		Ok(Output {
			value,
			lock: Script::from(lock),
		})
	}
}

impl Serialize for Output {
	fn serialize(&self, stream: &mut dyn Write) -> Result<()> {
		write_u64(stream, self.value)?;
		write_var_int(stream, self.lock.len() as u64)?;
		write_buf_exact(stream, self.lock.as_bytes())
	}
}

#[derive(Clone)]
pub struct Tx {
	pub version: u32,
	pub segwit: bool,
	pub inputs: Vec<TxInput>,
	pub outputs: Vec<TxOutput>,
	pub abs_lock_time: AbsoluteLockTime,
}

impl Tx {
	#[must_use]
	pub fn check_merkle_root(txs: &[Tx], expected: Sha256) -> bool {
		if let Some(merkle_root) = Tx::compute_merkle_root(txs) {
			merkle_root == expected
		} else {
			false
		}
	}

	pub fn compute_merkle_root(txs: &[Tx]) -> Option<Sha256> {
		assert!(txs.len() > 0);
		if txs.len() == 1 {
			Some(txs[0].compute_hash())
		} else {
			if txs[txs.len() - 1].compute_hash() == txs[txs.len() - 2].compute_hash() {
				return None
			}

			let mut hashes = txs.iter().map(|e| e.compute_hash()).collect::<Vec<_>>();
			
			while hashes.len() > 1 {
				if hashes.len() % 2 != 0 {
					hashes.push(hashes.last().unwrap().clone());
				}
				hashes = hashes.chunks(2)
					.map(|e| {
						let mut combined = Vec::with_capacity(e[0].as_bytes().len() + e[1].as_bytes().len());
						combined.extend_from_slice(e[0].as_bytes());
						combined.extend_from_slice(e[1].as_bytes());
						compute_double_sha256(&*combined)
					})
					.collect::<Vec<_>>();
			}

			Some(hashes[0])
		}
	}

	#[must_use]
	pub fn validate(&self, utxos: &mut UTXOState, is_coinbase: bool, state: &State) -> bool {
		let txid = compute_double_sha256(&*serialize(self).unwrap());
		if is_coinbase {
			if self.inputs.len() != 1 {
				return false;
			}
			let input = &self.inputs[0];
			if input.tx_hash != Sha256::default() {
				return false;
			}
			if input.index != 0xffff_ffff {
				return false;
			}

			let mut available = 50 * SAT_PER_COIN;
			for _ in 0..(state.height()/210_000) {
				available /= 2;
			}

			available += utxos.tx_fee;
			for (i, output) in self.outputs.iter().cloned().enumerate() {
				if available < output.value {
					return false;
				}
				available -= output.value;
				utxos.add(UTXOID(txid, i as u32), output);
			}

			return true;
		}

		let mut available = 0;
		let count = self.inputs.len();
		for (i, input) in self.inputs.iter().enumerate() {
			let id = input.utxo_id();
			if !utxos.contains(&id) {
				log_info!("invalid UTXO in tx input: {:?}", input.utxo_id());
				return false;
			}
			let utxo = utxos.remove(id);
			available += utxo.value;
			
			let mut runtime = ScriptRuntime::new(&self, i, state);
			let result = runtime.execute(&input.unlock)
				.and_then(|_| runtime.execute(&utxo.lock))
				.and_then(|_| runtime.finalize());
			if result.unwrap_or(StackObject::Empty).is_falsey() {
				log_info!("scripts failed (block height {})", state.height());
				return false;
			}

			log_trace!("    validated input {}/{}", i+1, count);
		}

		for (i, output) in self.outputs.iter().cloned().enumerate() {
			if available < output.value {
				return false;
			}
			available -= output.value;
			utxos.add(UTXOID(txid, i as u32), output);
		}
		utxos.tx_fee += available;

		true
	}

	pub fn build_utxo_diff(&self, utxos: &mut UTXOState, is_coinbase: bool) {
		let txid = compute_double_sha256(&*serialize(self).unwrap());
		if !is_coinbase {
			for input in self.inputs.iter() {
				let id = input.utxo_id();
				let _ = utxos.remove(id);
			}
		}
		for (i, output) in self.outputs.iter().cloned().enumerate() {
			utxos.add(UTXOID(txid, i as u32), output);
		}
	}

	pub fn compute_hash(&self) -> Sha256 {
		compute_double_sha256(&*serialize(self).unwrap())
	}
}

impl ToJson for Tx {
	fn to_json(&self) -> JsonValue {
		JsonValue::object([
			("version", JsonValue::number(self.version)),
			("segwit", JsonValue::bool(self.segwit)),
			("inputs", JsonValue::array(self.inputs.iter().map(|e| e.to_json()))),
			("outputs", JsonValue::array(self.outputs.iter().map(|e| e.to_json()))),
			("abs_lock_time", self.abs_lock_time.to_json()),
		])
	}
}

impl Default for Tx {
	fn default() -> Self {
		Tx {
			version: 1,
			segwit: false,
			inputs: Vec::new(),
			outputs: Vec::new(),
			abs_lock_time: AbsoluteLockTime::None,
		}
	}
}

impl Deserialize for Tx {
	fn deserialize(stream: &mut dyn Read) -> Result<Tx> {
		let version = read_u32(stream)?;
		let (segwit, input_count) = {
			let maybe_input_count = read_var_int(stream)?;
			if maybe_input_count == 0 {
				let flag = read_u8(stream)?;
				if flag != 1 {
					return Err(Err::NetworkError("invalid transaction: zero inputs".to_owned()));
				}
				(true, read_var_int(stream)?)
			} else {
				(false, maybe_input_count)
			}
		};

		let mut inputs = Vec::new();
		for _ in 0..input_count {
			inputs.push(Input::deserialize(stream)?);
		}

		let output_count = read_var_int(stream)? as usize;
		let mut outputs = Vec::new();
		for _ in 0..output_count {
			outputs.push(Output::deserialize(stream)?);
		}

		if segwit {
			for input in inputs.iter_mut() {
				let item_count = read_var_int(stream)?;
				let mut items = Vec::new();
				for _ in 0..item_count {
					let size = read_var_int(stream)? as usize;
					let mut buf = vec![0; size];
					read_buf_exact(stream, &mut buf)?;
					items.push(buf);
				}

				input.witness = items;
			}
		}

		let abs_lock_time = AbsoluteLockTime::deserialize(stream)?;

		Ok(Tx {
			version,
			segwit,
			inputs,
			outputs,
			abs_lock_time,
		})
	}
}

impl Serialize for Tx {
	fn serialize(&self, stream: &mut dyn Write) -> Result<()> {
		write_u32(stream, self.version)?;
		if self.segwit {
			write_u16_be(stream, 1)?;
		}
		
		write_var_int(stream, self.inputs.len() as u64)?;
		for input in self.inputs.iter() {
			input.serialize(stream)?;
		}

		write_var_int(stream, self.outputs.len() as u64)?;
		for output in self.outputs.iter() {
			output.serialize(stream)?;
		}

		if self.segwit {
			for input in self.inputs.iter() {
				write_var_int(stream, input.witness.len() as u64)?;
				for witness in input.witness.iter() {
					write_var_int(stream, witness.len() as u64)?;
					write_buf_exact(stream, &witness)?;
				}
			}
		}

		self.abs_lock_time.serialize(stream)
	}
}