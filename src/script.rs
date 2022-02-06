use std::{
	iter::Iterator,
	fmt,
	io::{
		Read,
		Seek,
		Cursor,
	}
};

use crate::common::*;

pub struct Script(Vec<u8>);

struct ScriptIterator<'a> {
	script: &'a [u8],
	offset: usize,
}

impl <'a> ScriptIterator<'a> {
	fn check_size(&self, size: usize) -> usize {
		if self.offset + size > self.script.len() {
			println!("script error: specified data size ({}) exceeds script length (offset={}, size={})",
				size, self.offset, self.script.len());
			println!("data size truncated.");
			self.script.len() - self.offset
		} else {
			size
		}
	}
	fn next_u8(&mut self) -> u8 {
		let n = self.script[self.offset];
		self.offset += 1;
		n
	}
	fn next_u16(&mut self) -> u16 {
		const SIZE: usize = std::mem::size_of::<u16>();
		let n = u16::from_le_bytes(self.script[self.offset..self.offset + SIZE].try_into().unwrap());
		self.offset += 2;
		n
	}
	fn next_u32(&mut self) -> u32 {
		const SIZE: usize = std::mem::size_of::<u32>();
		let n = u32::from_le_bytes(self.script[self.offset..self.offset + SIZE].try_into().unwrap());
		self.offset += SIZE;
		n
	}
	fn next_slice(&mut self, size: usize) -> &'a [u8] {
		let size = self.check_size(size);
		let slice = &self.script[self.offset..self.offset + size];
		self.offset += size;
		slice
	}
}

impl Script {
	pub fn new(bytes: Vec<u8>) -> Self {
		Script(bytes)
	}

	pub fn ops(&self) -> ScriptIterator {
		ScriptIterator {
			script: &self.0,
			offset: 0,
		}
	}
}

#[allow(non_camel_case_types)]
enum Op<'a> {
	OP_0,
	OP_DATA(&'a[u8]),
	OP_PUSHDATA1(&'a[u8]),
	OP_PUSHDATA2(&'a[u8]),
	OP_PUSHDATA4(&'a[u8]),
	// OP_1NEGATE,
	// OP_1
	// OP_2
	// OP_3
	// OP_4
	// OP_5
	// OP_6
	// OP_7
	// OP_8
	// OP_9
	// OP_10
	// OP_11
	// OP_12
	// OP_13
	// OP_14
	// OP_15
	// OP_16
	// OP_NOP
	// OP_IF
	// OP_NOTIF
	// OP_ELSE
	// OP_IF
	// OP_NOTIF
	// OP_ELSE
	// OP_IF
	// OP_NOTIF
	// OP_ELSE
	// OP_ENDIF
	// OP_ENDIF
	// OP_IF
	// OP_VERIFY
	OP_RETURN,
	// OP_TOALTSTACK
	// OP_FROMALTSTACK
	// OP_IFDUP
	// OP_DEPTH
	// OP_DROP
	OP_DUP,
	// OP_NIP
	// OP_OVER
	// OP_PICK
	// OP_ROLL
	// OP_ROT
	// OP_SWAP
	// OP_TUCK
	// OP_2DROP
	// OP_2DUP
	// OP_3DUP
	// OP_2OVER
	// OP_2ROT
	// OP_2SWAP
	// OP_CAT
	// OP_SUBSTR
	// OP_LEFT
	// OP_RIGHT
	// OP_SIZE
	// OP_INVERT
	// OP_AND
	// OP_OR
	// OP_XOR
	OP_EQUAL,
	OP_EQUALVERIFY,
	// OP_1ADD
	// OP_1SUB
	// OP_2MUL
	// OP_2DIV
	// OP_NEGATE
	// OP_ABS
	// OP_NOT
	// OP_0NOTEQUAL
	// OP_ADD
	// OP_SUB
	// OP_MUL
	// OP_DIV
	// OP_MOD
	// OP_LSHIFT
	// OP_RSHIFT
	// OP_BOOLAND
	// OP_BOOLOR
	// OP_NUMEQUAL
	// OP_NUMEQUALVERIFY
	// OP_NUMEQUAL
	// OP_VERIFY
	// OP_NUMNOTEQUAL
	// OP_LESSTHAN
	// OP_GREATERTHAN
	// OP_LESSTHANOREQUAL
	// OP_GREATERTHANOREQUAL
	// OP_MIN
	// OP_MAX
	// OP_WITHIN
	// OP_RIPEMD160
	// OP_SHA1
	// OP_SHA256
	OP_HASH160,
	// OP_HASH256
	// OP_CODESEPARATOR
	// OP_CODESEPARATOR
	OP_CHECKSIG,
	// OP_CODESEPARATOR
	// OP_CHECKSIG
	// OP_CHECKSIGVERIFY
	// OP_CHECKSIG
	// OP_VERIFY
	// OP_CHECKMULTISIG
	// OP_CHECKMULTISIGVERIFY
	// OP_CHECKMULTISIG
	// OP_VERIFY
	// OP_CHECKLOCKTIMEVERIFY
	// OP_NOP2
	// OP_NOP
	// OP_CHECKSEQUENCEVERIFY
	// OP_NOP3
	// OP_PUBKEYHASH
	// OP_HASH160
	// OP_PUBKEY
	// OP_CHECKSIG
	// OP_INVALIDOPCODE
	// OP_RESERVED
	// OP_IF
	// OP_VER
	// OP_IF
	// OP_VERIF
	// OP_IF
	// OP_VERNOTIF
	// OP_IF
	// OP_RESERVED1
	// OP_IF
	// OP_RESERVED2
	// OP_IF
	// OP_NOP1
	// OP_NOP4
	// OP_NOP10
	Unknown(u8),
}

fn write_data(f: &mut fmt::Formatter, op: &str, data: &[u8]) -> fmt::Result {
	if op.len() > 0 {
		write!(f, "{} ", op)?;
	}
	for &b in data.iter() {
		write!(f, "{:02x}", b)?;
	}
	Ok(())
}

impl <'a> fmt::Display for Op<'a> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Op::OP_0 => write!(f, "OP_0"),
			Op::OP_DATA(data) => write_data(f, "", data),
			Op::OP_PUSHDATA1(data) => write_data(f, "OP_PUSHDATA1", data),
			Op::OP_PUSHDATA2(data) => write_data(f, "OP_PUSHDATA2", data),
			Op::OP_PUSHDATA4(data) => write_data(f, "OP_PUSHDATA4", data),
			Op::OP_DUP => write!(f, "OP_DUP"),
			Op::OP_RETURN => write!(f, "OP_RETURN"),
			Op::OP_EQUALVERIFY => write!(f, "OP_EQUALVERIFY"),
			Op::OP_EQUAL => write!(f, "OP_EQUAL"),
			Op::OP_HASH160 => write!(f, "OP_HASH160"),
			Op::OP_CHECKSIG => write!(f, "OP_CHECKSIG"),
			Op::Unknown(b) => write!(f, "0x{:x}??", b),
		}
	}
}

impl <'a> Iterator for ScriptIterator<'a> {
	type Item = Op<'a>;

	fn next(&mut self) -> Option<Op<'a>> {
		if self.offset >= self.script.len() {
			return None
		}
		
		let opcode = self.script[self.offset];
		self.offset += 1;
		match opcode {
			0 => Some(Op::OP_0),
			x if x < 76 => Some(Op::OP_DATA(self.next_slice(x as usize))),
			76 => {
				let size = self.next_u8() as usize;
				Some(Op::OP_PUSHDATA1(self.next_slice(size)))
			},
			77 => {
				let size = self.next_u16() as usize;
				Some(Op::OP_PUSHDATA2(self.next_slice(size)))
			},
			78 => {
				let size = self.next_u32() as usize;
				Some(Op::OP_PUSHDATA1(self.next_slice(size)))
			},
			106 => Some(Op::OP_RETURN),
			118 => Some(Op::OP_DUP),
			135 => Some(Op::OP_EQUAL),
			136 => Some(Op::OP_EQUALVERIFY),
			169 => Some(Op::OP_HASH160),
			172 => Some(Op::OP_CHECKSIG),
			b => Some(Op::Unknown(b)),
		}
	}
}

impl fmt::Display for Script {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let mut it = self.ops();

		if let Some(item) = it.next() {
			write!(f, "{}", item)?;
		}
		
		for item in it {
			write!(f, " {}", item)?;
		}

		Ok(())
	}
}