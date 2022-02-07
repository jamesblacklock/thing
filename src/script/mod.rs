use std::{
	iter::Iterator,
	fmt,
};

mod op;
pub use op::*;

pub struct Script(Vec<u8>);

pub struct ScriptIterator<'a> {
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

impl <'a> Iterator for ScriptIterator<'a> {
	type Item = Op<'a>;

	fn next(&mut self) -> Option<Op<'a>> {
		if self.offset >= self.script.len() {
			return None
		}
		Some(Op::next(self))
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