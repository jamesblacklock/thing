use std::{
	io::{Read, Write},
};

use crate::{
	err::*,
	json::*,
    sha256::*,
};

use crate::common::{
	read_i32,
	read_var_int,
    read_sha256,
	write_i32,
	write_var_int,
    write_sha256,
};

use super::{
	Deserialize,
	Serialize,
    version::PROTOCOL_VERSION,
};

#[derive(Clone)]
pub struct GetHeaders {
    version: i32,
    hashes: Vec<Sha256>,
    hash_stop: Option<Sha256>,
}

impl GetHeaders {
	pub fn new(hashes: &[Sha256]) -> Self {
        let mut sparse_hashes = Vec::new();
        let mut step = 1;
        let mut offset = 1;
        let len = hashes.len();
        while offset < hashes.len() {
            sparse_hashes.push(hashes[len - offset].clone());
            if sparse_hashes.len() > 10 {
                step *= 2;
            }
            offset += step;
        }
        
        sparse_hashes.push(hashes[0].clone());

		GetHeaders {
			version: PROTOCOL_VERSION,
            hashes: sparse_hashes,
            hash_stop: None,
		}
	}
}

impl ToJson for GetHeaders {
	fn to_json(&self) -> JsonValue {
        let hash_stop = if let Some(hash_stop) = self.hash_stop {
            JsonValue::string(format!("{}", hash_stop))
        } else {
            JsonValue::null()
        };

		JsonValue::object([
            ("version", JsonValue::number(self.version)),
            ("hashes", JsonValue::array(self.hashes.iter().map(|e| JsonValue::string(format!("{}", e))))),
            ("hash_stop", hash_stop),
        ])
	}
}

impl Deserialize for GetHeaders {
	fn deserialize(stream: &mut dyn Read) -> Result<GetHeaders> {
		let version = read_i32(stream)?;
		let hash_count = read_var_int(stream)?;
        let mut hashes = Vec::new();
        for _ in 0..hash_count {
            let hash = read_sha256(stream)?;
            hashes.push(hash);
        }

        let hash_stop = read_sha256(stream)?;
        let hash_stop = if hash_stop == Sha256::default() {
            None
        } else {
            Some(hash_stop)
        };
        
        Ok(GetHeaders {
            version,
            hashes,
            hash_stop,
        })
	}
}

impl Serialize for GetHeaders {
	fn serialize(&self, stream: &mut dyn Write) -> Result<()> {
        write_i32(stream, self.version)?;
		write_var_int(stream, self.hashes.len() as u64)?;
        for hash in self.hashes.iter() {
            write_sha256(stream, &hash)?;
        }
        if let Some(hash_stop) = self.hash_stop {
            write_sha256(stream, &hash_stop)?;
        } else {
            write_sha256(stream, &Sha256::default())?;
        }

		Ok(())
	}
}