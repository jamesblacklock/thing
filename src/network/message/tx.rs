use std::{
	io::{Read, Write},
};

use crate::{
	err::*,
	json::JsonValue,
	sha256::Sha256,
};

use super::{
	Deserialize,
	Serialize,
	VarInt,
	super::{
		read_u8,
		read_u32,
		read_u64,
		read_buf_exact,
		write_u8,
		write_u32,
		write_u64,
	}
};

#[derive(Clone, Copy)]
enum LockTime {
	BlockNumber(u32),
	Timestamp(u32),
	None,
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
	unlock: Vec<u8>,
	witness: Vec<Vec<u8>>,
	sequence: u32,
}

impl Deserialize for Input {
	fn deserialize(stream: &mut dyn Read) -> Result<Self> {
		unimplemented!()
	}
}

struct Output {
	value: u64,
	lock: Vec<u8>,
}

impl Deserialize for Output {
	fn deserialize(stream: &mut dyn Read) -> Result<Self> {
		unimplemented!()
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
		JsonValue::null()
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