use std::{
	io::{Read, Write},
    fmt,
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
		read_u32,
        read_buf_exact,
		write_u32,
        write_buf_exact,
	}
};

#[repr(u32)]
#[derive(Clone, Copy)]
pub enum InvType {
    Error = 0x00000000,
    Tx = 0x00000001,
    Block = 0x00000002,
    FilteredBlock = 0x00000003,
    CmpctBlock = 0x00000004,
    WitnessTx = 0x40000001,
    WitnessBlock = 0x40000002,
    FilteredWitnessBlock = 0x40000003,
}

impl From<u32> for InvType {
    fn from(v: u32) -> Self {
        match v {
            x if x == InvType::Tx as u32 => InvType::Tx,
            x if x == InvType::Block as u32 => InvType::Block,
            x if x == InvType::FilteredBlock as u32 => InvType::FilteredBlock,
            x if x == InvType::CmpctBlock as u32 => InvType::CmpctBlock,
            x if x == InvType::WitnessTx as u32 => InvType::WitnessTx,
            x if x == InvType::WitnessBlock as u32 => InvType::WitnessBlock,
            x if x == InvType::FilteredWitnessBlock as u32 => InvType::FilteredWitnessBlock,
            _ => InvType::Error,
        }
    }
}

impl fmt::Display for InvType {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
            InvType::Error => write!(f, "ERROR"),
            InvType::Tx => write!(f, "TX"),
            InvType::Block => write!(f, "BLOCK"),
            InvType::FilteredBlock => write!(f, "FILTERED_BLOCK"),
            InvType::CmpctBlock => write!(f, "CMPCT_BLOCK"),
            InvType::WitnessTx => write!(f, "WITNESS_TX"),
            InvType::WitnessBlock => write!(f, "WITNESS_BLOCK"),
            InvType::FilteredWitnessBlock => write!(f, "FILTERED_WITNESS_BLOCK"),
		}
	}
}

#[derive(Clone)]
pub struct InvItem {
    pub object_type: InvType,
    pub hash: Sha256,
}

impl InvItem {
    fn into_json(&self) -> JsonValue {
        JsonValue::object([
            ("type", JsonValue::string(format!("{}", self.object_type))),
            ("hash", JsonValue::string(format!("{}", self.hash))),
        ])
    }
}

impl Deserialize for InvItem {
    fn deserialize(stream: &mut dyn Read) -> Result<Self> {
        let object_type = InvType::from(read_u32(stream)?);
        let mut hash_buf = [0; 32];
        read_buf_exact(stream, &mut hash_buf)?;
        let hash = Sha256::from(hash_buf);
        
        Ok(InvItem {
            object_type,
            hash,
        })
    }
}

impl Serialize for InvItem {
    fn serialize(&self, stream: &mut dyn Write) -> Result<()> {
        write_u32(stream, self.object_type as u32)?;
        write_buf_exact(stream, self.hash.as_bytes())?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct Inv {
	inv: Vec<InvItem>,
}

impl Inv {
	// pub fn new() -> Self {
	// 	Inv {
	// 		inv: Vec::new(),
	// 	}
	// }

    pub fn items(&self) -> &[InvItem] {
        &self.inv
    }

	pub fn into_json(&self) -> JsonValue {
        JsonValue::Array(self.inv.iter().map(|e| e.into_json()).collect())
	}
}

impl Deserialize for Inv {
	fn deserialize(stream: &mut dyn Read) -> Result<Inv> {
		let count = VarInt::deserialize(stream)?.0 as usize;
        let mut inv = Vec::new();
        for _ in 0..count {
            inv.push(InvItem::deserialize(stream)?);
        }

        Ok(Inv {inv})
	}
}

impl Serialize for Inv {
	fn serialize(&self, stream: &mut dyn Write) -> Result<()> {
        VarInt(self.inv.len() as u64).serialize(stream)?;
		for inv in &self.inv {
            inv.serialize(stream)?;
        }
        Ok(())
	}
}

#[derive(Clone)]
pub struct GetData(Inv);

impl GetData {
	pub fn new(inv: Vec<InvItem>) -> Self {
		GetData(Inv {
			inv: inv,
		})
	}

    pub fn items(&self) -> &[InvItem] {
        self.0.items()
    }

	pub fn into_json(&self) -> JsonValue {
        self.0.into_json()
	}
}

impl Deserialize for GetData {
	fn deserialize(stream: &mut dyn Read) -> Result<Self> {
        Ok(GetData(Inv::deserialize(stream)?))
	}
}

impl Serialize for GetData {
	fn serialize(&self, stream: &mut dyn Write) -> Result<()> {
        self.0.serialize(stream)
	}
}