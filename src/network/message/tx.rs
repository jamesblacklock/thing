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
enum AbsoluteLockTime {
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

impl From<u32> for AbsoluteLockTime {
	fn from(n: u32) -> AbsoluteLockTime {
		match n {
			0 => AbsoluteLockTime::None,
			x if x < 500000000 => AbsoluteLockTime::BlockNumber(x),
			x => AbsoluteLockTime::Timestamp(x),
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

struct Input {
	tx_hash: Sha256,
	index: u32,
	unlock: Script,
	witness: Vec<Vec<u8>>,
	rel_lock_time: RelativeLockTime,
}

impl Input {
	fn into_json(&self) -> JsonValue {
		JsonValue::object([
			("tx_hash", JsonValue::string(format!("{}", self.tx_hash))),
			("index", JsonValue::number(self.index)),
			("unlock", JsonValue::string(format!("{}", self.unlock))),
			("witness", JsonValue::string(format!("{:?}", self.witness))),
			("rel_lock_time", self.rel_lock_time.to_json()),
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
		let rel_lock_time = RelativeLockTime::from(read_u32(stream)?);

		Ok(Input {
			tx_hash,
			index,
			unlock: Script::new(unlock),
			witness: Vec::new(),
			rel_lock_time,
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
	abs_lock_time: AbsoluteLockTime,
}

impl Tx {
	pub fn into_json(&self) -> JsonValue {
		JsonValue::object([
			("version", JsonValue::number(self.version)),
			("segwit", JsonValue::bool(self.segwit)),
			("inputs", JsonValue::array(self.inputs.iter().map(|e| e.into_json()))),
			("outputs", JsonValue::array(self.outputs.iter().map(|e| e.into_json()))),
			("abs_lock_time", self.abs_lock_time.to_json()),
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
					read_buf_exact(stream, &mut buf)?;
					items.push(buf);
				}

				input.witness = items;
			}
		}

		let abs_lock_time = AbsoluteLockTime::from(read_u32(stream)?);

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
		Ok(())
	}
}