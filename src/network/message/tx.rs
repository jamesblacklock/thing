use std::{
	io::{Read, Write},
};

use crate::{
	err::*,
	json::JsonValue,
	sha256::*,
	script::*,
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
};

#[derive(Clone, Copy)]
pub enum AbsoluteLockTime {
	BlockNumber(u32),
	Timestamp(u32),
	None,
}

impl AbsoluteLockTime {
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
		let n = read_u32(stream)?;
		match n {
			0 => Ok(AbsoluteLockTime::None),
			x if x < 500000000 => Ok(AbsoluteLockTime::BlockNumber(x)),
			x => Ok(AbsoluteLockTime::Timestamp(x)),
		}
	}
}

#[derive(Clone, Copy)]
enum RelativeLockTime {
	Blocks(u32),
	Seconds(u32),
	None,
}

impl RelativeLockTime {
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
	fn to_json(&self) -> JsonValue {
		JsonValue::object([
			("tx_hash", JsonValue::string(format!("{}", self.tx_hash))),
			("index", JsonValue::number(self.index)),
			("unlock", JsonValue::string(format!("{}", self.unlock))),
			("witness", JsonValue::string(format!("{:?}", self.witness))),
			("rel_lock_time", self.rel_lock_time().to_json()),
		])
	}

	fn rel_lock_time(&self) -> RelativeLockTime {
		RelativeLockTime::from(self.sequence)
	}
}

impl Default for Input {
	fn default() -> Self {
		Input {
			tx_hash: Sha256::default(),
			index: 0,
			unlock: Script::new(Vec::new()),
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
			unlock: Script::new(unlock),
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

impl Output {
	fn to_json(&self) -> JsonValue {
		JsonValue::object([
			("value", JsonValue::number(self.value)),
			("lock", JsonValue::string(format!("{}", self.lock))),
		])
	}
}

impl Default for Output {
	fn default() -> Self {
		Output {
			value: 0,
			lock: Script::new(Vec::new()),
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
			lock: Script::new(lock),
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
	pub fn to_json(&self) -> JsonValue {
		JsonValue::object([
			("version", JsonValue::number(self.version)),
			("segwit", JsonValue::bool(self.segwit)),
			("inputs", JsonValue::array(self.inputs.iter().map(|e| e.to_json()))),
			("outputs", JsonValue::array(self.outputs.iter().map(|e| e.to_json()))),
			("abs_lock_time", self.abs_lock_time.to_json()),
		])
	}

	pub fn compute_merkle_root(txs: &[Tx]) -> Sha256 {
		assert!(txs.len() > 0);
		if txs.len() == 1 {
			compute_double_sha256(&*serialize(&txs[0]).unwrap())
		} else {
			unimplemented!()
		}
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