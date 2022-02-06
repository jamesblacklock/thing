use std::{
	io::{Read, Write},
};

use crate::{
	err::*,
	json::JsonValue,
};

use crate::common::{
	read_u64,
	write_u64,
};

use super::{
	Deserialize,
	Serialize,
};

#[derive(Clone)]
pub struct FeeFilter {
	feerate: u64,
}

impl FeeFilter {
	// pub fn new(feerate: u64) -> Self {
	// 	FeeFilter { feerate }
	// }

	pub fn into_json(&self) -> JsonValue {
		JsonValue::number(self.feerate)
	}
}

impl Deserialize for FeeFilter {
	fn deserialize(stream: &mut dyn Read) -> Result<FeeFilter> {
		Ok(FeeFilter { feerate: read_u64(stream)? })
	}
}

impl Serialize for FeeFilter {
	fn serialize(&self, stream: &mut dyn Write) -> Result<()> {
		write_u64(stream, self.feerate)
	}
}