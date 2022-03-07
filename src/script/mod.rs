use std::{
	iter::Iterator,
	fmt,
	io::Read,
};

use crate::{
	crypto::ecdsa::*,
	network::Deserialize,
	network::message::Tx,
	err::*,
	common::read_u8,
};

mod op;
pub use op::*;

#[derive(Clone)]
pub struct Script(Vec<u8>);

impl Script {
	pub fn new() -> Self {
		Script(Vec::new())
	}

	pub fn builder() -> ScriptBuilder {
		ScriptBuilder(Script::new())
	}

	pub fn ops(&self) -> ScriptIterator {
		ScriptIterator {
			script: &self.0,
			offset: 0,
		}
	}

	pub fn len(&self) -> usize {
		self.0.len()
	}

	pub fn as_bytes(&self) -> &[u8] {
		&*self.0
	}

	pub fn append(&mut self, op: Op) -> &mut Self {
		op.append_to(&mut self.0);
		self
	}
}

impl std::convert::From<Vec<u8>> for Script {
	fn from(bytes: Vec<u8>) -> Self {
		Script(bytes)
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

pub struct ScriptBuilder(Script);

impl ScriptBuilder {
	#[must_use]
	pub fn append(mut self, op: Op) -> Self {
		self.0.append(op);
		self
	}

	pub fn build(self) -> Script {
		self.0
	}
}


pub struct ScriptIterator<'a> {
	script: &'a [u8],
	offset: usize,
}

impl <'a> ScriptIterator<'a> {
	fn check_size(&self, size: usize) -> usize {
		if self.offset + size > self.script.len() {
			log_error!("script error: specified data size ({}) exceeds script length (offset={}, size={})",
				size, self.offset, self.script.len());
			log_error!("data size truncated.");
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
		self.offset += SIZE;
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

impl <'a> Iterator for ScriptIterator<'a> {
	type Item = Op<'a>;

	fn next(&mut self) -> Option<Op<'a>> {
		if self.offset >= self.script.len() {
			return None
		}
		Some(Op::next(self))
	}
}

pub enum StackObject {
	Empty,
	Int(i64),
	Bytes(Vec<u8>),
}

impl StackObject {
	fn is_truthy(&self) -> bool {
		match *self {
			StackObject::Empty => false,
			StackObject::Int(n) => n != 0,
			StackObject::Bytes(_) => true,
		}
	}

	pub fn to_ecdsa_pubkey(&self) -> Result<ECDSAPubKey> {
		match self {
			StackObject::Bytes(bytes) => ECDSAPubKey::deserialize(&mut bytes.as_slice()),
			_ => Err(Err::ScriptError("could not convert stack object to ECDSA pubkey".to_owned()))
		}
	}

	pub fn to_ecdsa_sig(&self) -> Result<(ECDSASig, u8)> {
		match self {
			StackObject::Bytes(bytes) => {
				let stream = &mut bytes.as_slice();
				let sig = ECDSASig::deserialize(stream)?;
				let hash_type = read_u8(stream)?;
				Ok((sig, hash_type))
			},
			_ => Err(Err::ScriptError("could not convert stack object to ECDSA sig".to_owned()))
		}
	}
}

impl fmt::Debug for StackObject {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			StackObject::Empty    => write!(f, "Empty"),
			StackObject::Int(n)   => write!(f, "Int({})", n),
			StackObject::Bytes(v) => fmt_data(f, "", &*v),
		}
	}
}

pub struct ScriptRuntime<'a> {
	tx: &'a Tx,
	index: usize,
	lock: &'a Script,
	stack: Vec<StackObject>,
	invalid: bool,
}

impl <'a> ScriptRuntime<'a> {
	pub fn new(tx: &'a Tx, index: usize, lock: &'a Script) -> Self {
		ScriptRuntime {
			tx,
			index,
			lock,
			stack: Vec::new(),
			invalid: false,
		}
	}

	pub fn execute(&mut self, script: &Script) -> Result<()> {
		if self.invalid {
			return Err(Err::ScriptError("attempt to execute script previous state was already invalid".to_owned()));
		}
		for op in script.ops() {
			op.affect(self)?;
		}
		Ok(())
	}

	pub fn is_valid(&self) -> bool {
		if self.invalid || self.stack.len() == 0 {
			false
		} else {
			self.stack[self.stack.len() - 1].is_truthy()
		}
	}

	pub fn push_stack(&mut self, item: StackObject) -> Result<()> {
		self.stack.push(item);
		Ok(())
	}

	pub fn pop_stack(&mut self) -> Result<StackObject> {
		self.stack.pop().ok_or(Err::ScriptError("tried to pop empty stack".to_owned()))
	}
}

impl <'a> fmt::Debug for ScriptRuntime<'a> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "stack:\n")?;
		for item in self.stack.iter() {
			writeln!(f, "    {:?}", item)?;
		}
		Ok(())
	}
}