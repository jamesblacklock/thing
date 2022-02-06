use std::{
	io::{Read, Write},
};

use crate::{
	err::*,
	json::JsonValue,
	sha256::Sha256,
	script::*,
};

use crate::common::{
	read_u8,
	read_u32,
	read_u64,
	read_buf_exact,
	write_u8,
	write_u32,
	write_u64,
};

use super::{
	Deserialize,
	Serialize,
	VarInt,
};

#[derive(Clone, Copy)]
enum LockTime {
	BlockNumber(u32),
	Timestamp(u32),
	None,
}

impl LockTime {
	fn to_json(&self) -> JsonValue {
		match *self {
			LockTime::BlockNumber(n) => JsonValue::object([("block", JsonValue::number(n))]),
			LockTime::Timestamp(n) => JsonValue::object([("timestamp", JsonValue::number(n))]),
			LockTime::None => JsonValue::null(),
		}
	}
}

impl From<u32> for LockTime {
	fn from(n: u32) -> LockTime {
		match n {
			0 => LockTime::None,
			x if x < 500000000 => LockTime::BlockNumber(x),
			x => LockTime::Timestamp(x),
		}
	}
}

struct Input {
	tx_hash: Sha256,
	index: u32,
	unlock: Script,
	witness: Vec<Vec<u8>>,
	sequence: u32,
}

impl Input {
	fn into_json(&self) -> JsonValue {
		JsonValue::object([
			("tx_hash", JsonValue::string(format!("{}", self.tx_hash))),
			("index", JsonValue::number(self.index)),
			("unlock", JsonValue::string(format!("{}", self.unlock))),
			("witness", JsonValue::string(format!("{:?}", self.witness))),
			("sequence", JsonValue::number(self.sequence)),
		])
	}
}

impl Deserialize for Input {
	fn deserialize(stream: &mut dyn Read) -> Result<Self> {
		let mut tx_hash_buf = [0; 32];
        read_buf_exact(stream, &mut tx_hash_buf)?;
        let tx_hash = Sha256::from(tx_hash_buf);
		let index = read_u32(stream)?;
		let unlock_size = VarInt::deserialize(stream)?.0 as usize;
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

struct Output {
	value: u64,
	lock: Script,
}

impl Output {
	fn into_json(&self) -> JsonValue {
		JsonValue::object([
			("value", JsonValue::number(self.value)),
			("lock", JsonValue::string(format!("{}", self.lock))),
		])
	}
}

impl Deserialize for Output {
	fn deserialize(stream: &mut dyn Read) -> Result<Self> {
		let value = read_u64(stream)?;
		let lock_length = VarInt::deserialize(stream)?.0 as usize;
		let mut lock = vec![0; lock_length];
		read_buf_exact(stream, &mut lock)?;

		Ok(Output {
			value,
			lock: Script::new(lock),
		})
	}
}

pub struct Tx {
	version: u32,
	segwit: bool,
	inputs: Vec<Input>,
	outputs: Vec<Output>,
	lock_time: LockTime,
}

impl Tx {
	pub fn into_json(&self) -> JsonValue {
		JsonValue::object([
			("version", JsonValue::number(self.version)),
			("segwit", JsonValue::bool(self.segwit)),
			("inputs", JsonValue::array(self.inputs.iter().map(|e| e.into_json()))),
			("outputs", JsonValue::array(self.outputs.iter().map(|e| e.into_json()))),
			("lock_time", self.lock_time.to_json()),
		])
	}
}

impl Deserialize for Tx {
	fn deserialize(stream: &mut dyn Read) -> Result<Tx> {
		let version = read_u32(stream)?;
		let (segwit, input_count) = {
			let maybe_input_count = VarInt::deserialize(stream)?;
			if maybe_input_count.0 == 0 {
				let flag = read_u8(stream)?;
				if flag != 1 {
					return Err(Err::NetworkError("invalid transaction: zero inputs".to_owned()));
				}
				(true, VarInt::deserialize(stream)?.0)
			} else {
				(false, maybe_input_count.0)
			}
		};

		let mut inputs = Vec::new();
		for _ in 0..input_count {
			inputs.push(Input::deserialize(stream)?);
		}

		let output_count = VarInt::deserialize(stream)?.0;
		let mut outputs = Vec::new();
		for _ in 0..output_count {
			outputs.push(Output::deserialize(stream)?);
		}

		if segwit {
			for input in inputs.iter_mut() {
				let item_count = VarInt::deserialize(stream)?.0;
				let mut items = Vec::new();
				for _ in 0..item_count {
					let size = VarInt::deserialize(stream)?.0 as usize;
					let mut buf = vec![0; size];
					read_buf_exact(stream, &mut buf);
					items.push(buf);
				}

				input.witness = items;
			}
		}

		let lock_time = LockTime::from(read_u32(stream)?);

		Ok(Tx {
			version,
			segwit,
			inputs,
			outputs,
			lock_time,
		})
	}
}

impl Serialize for Tx {
	fn serialize(&self, stream: &mut dyn Write) -> Result<()> {
		Ok(())
	}
}