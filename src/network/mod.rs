use std::net::{TcpStream};
use std::io::{Write, Read};
use crate::err::*;

pub mod message;

use message::Message;

trait Serialize {
	fn serialize(&self, stream: &mut dyn Write) -> Result<()>;
}

trait Deserialize: Sized {
	fn deserialize(stream: &mut dyn Read) -> Result<Self>;
}

fn read_u8(stream: &mut dyn Read) -> Result<u8> {
	let mut buf = [0; 1];
	stream.read_exact(&mut buf).map_err(|err| Err::NetworkError(err.to_string()))?;
	Ok(buf[0])
}

fn read_bool(stream: &mut dyn Read) -> Result<bool> {
	Ok(read_u8(stream)? == 1)
}

fn read_u16(stream: &mut dyn Read) -> Result<u16> {
	let mut buf = [0; 2];
	stream.read_exact(&mut buf).map_err(|err| Err::NetworkError(err.to_string()))?;
	Ok(u16::from_le_bytes(buf))
}

fn read_u16_be(stream: &mut dyn Read) -> Result<u16> {
	let mut buf = [0; 2];
	stream.read_exact(&mut buf).map_err(|err| Err::NetworkError(err.to_string()))?;
	Ok(u16::from_be_bytes(buf))
}

fn read_u32(stream: &mut dyn Read) -> Result<u32> {
	let mut buf = [0; 4];
	stream.read_exact(&mut buf).map_err(|err| Err::NetworkError(err.to_string()))?;
	Ok(u32::from_le_bytes(buf))
}

fn read_u32_be(stream: &mut dyn Read) -> Result<u32> {
	let mut buf = [0; 4];
	stream.read_exact(&mut buf).map_err(|err| Err::NetworkError(err.to_string()))?;
	Ok(u32::from_be_bytes(buf))
}

fn read_i32(stream: &mut dyn Read) -> Result<i32> {
	let mut buf = [0; 4];
	stream.read_exact(&mut buf).map_err(|err| Err::NetworkError(err.to_string()))?;
	Ok(i32::from_le_bytes(buf))
}

fn read_u64(stream: &mut dyn Read) -> Result<u64> {
	let mut buf = [0; 8];
	stream.read_exact(&mut buf).map_err(|err| Err::NetworkError(err.to_string()))?;
	Ok(u64::from_le_bytes(buf))
}

fn read_i64(stream: &mut dyn Read) -> Result<i64> {
	let mut buf = [0; 8];
	stream.read_exact(&mut buf).map_err(|err| Err::NetworkError(err.to_string()))?;
	Ok(i64::from_le_bytes(buf))
}

fn read_buf_exact(stream: &mut dyn Read, buf: &mut [u8]) -> Result<()> {
	stream.read_exact(buf).map_err(|err| Err::NetworkError(err.to_string()))?;
	Ok(())
}

fn read_str_exact(stream: &mut dyn Read, size: usize) -> Result<String> {
	let mut buf = vec![0; size];
	read_buf_exact(stream, &mut buf)?;
	let s = String::from_utf8(buf)
		.map_err(|err| Err::NetworkError(err.to_string()))?
		.trim_matches(char::from(0))
		.to_owned();
	
	Ok(s)
}

fn write_u8(stream: &mut dyn Write, n: u8) -> Result<()> {
	let size = stream.write(&[n]).map_err(|err| Err::NetworkError(err.to_string()))?;
	if size != 1 {
		Err(Err::NetworkError("failed to write 1 byte to stream".to_owned()))?;
	}
	Ok(())
}

fn write_bool(stream: &mut dyn Write, n: bool) -> Result<()> {
	write_u8(stream, if n { 1 } else { 0 })
}

fn write_u16(stream: &mut dyn Write, n: u16) -> Result<()> {
	let size = stream.write(&n.to_le_bytes()).map_err(|err| Err::NetworkError(err.to_string()))?;
	if size != 2 {
		Err(Err::NetworkError(format!("failed to write {} byte(s) to stream", 2 - size)))?;
	}
	Ok(())
}

fn write_u16_be(stream: &mut dyn Write, n: u16) -> Result<()> {
	let size = stream.write(&n.to_be_bytes()).map_err(|err| Err::NetworkError(err.to_string()))?;
	if size != 2 {
		Err(Err::NetworkError(format!("failed to write {} byte(s) to stream", 2 - size)))?;
	}
	Ok(())
}

fn write_u32(stream: &mut dyn Write, n: u32) -> Result<()> {
	let size = stream.write(&n.to_le_bytes()).map_err(|err| Err::NetworkError(err.to_string()))?;
	if size != 4 {
		Err(Err::NetworkError(format!("failed to write {} byte(s) to stream", 4 - size)))?;
	}
	Ok(())
}

fn write_u32_be(stream: &mut dyn Write, n: u32) -> Result<()> {
	let size = stream.write(&n.to_be_bytes()).map_err(|err| Err::NetworkError(err.to_string()))?;
	if size != 4 {
		Err(Err::NetworkError(format!("failed to write {} byte(s) to stream", 4 - size)))?;
	}
	Ok(())
}

fn write_i32(stream: &mut dyn Write, n: i32) -> Result<()> {
	let size = stream.write(&n.to_le_bytes()).map_err(|err| Err::NetworkError(err.to_string()))?;
	if size != 4 {
		Err(Err::NetworkError(format!("failed to write {} byte(s) to stream", 4 - size)))?;
	}
	Ok(())
}

fn write_u64(stream: &mut dyn Write, n: u64) -> Result<()> {
	let size = stream.write(&n.to_le_bytes()).map_err(|err| Err::NetworkError(err.to_string()))?;
	if size != 8 {
		Err(Err::NetworkError(format!("failed to write {} byte(s) to stream", 8 - size)))?;
	}
	Ok(())
}

fn write_i64(stream: &mut dyn Write, n: i64) -> Result<()> {
	let size = stream.write(&n.to_le_bytes()).map_err(|err| Err::NetworkError(err.to_string()))?;
	if size != 8 {
		Err(Err::NetworkError(format!("failed to write {} byte(s) to stream", 8 - size)))?;
	}
	Ok(())
}

fn write_buf_exact(stream: &mut dyn Write, buf: &[u8]) -> Result<()> {
	stream.write(buf).map_err(|err| Err::NetworkError(err.to_string()))?;
	Ok(())
}

fn write_str_exact(stream: &mut dyn Write, s: &str, size: usize) -> Result<()> {
	let mut buf = vec![0; size];
	let len = std::cmp::min(size, s.len());
	buf[..len].copy_from_slice(&s.as_bytes()[..len]);
	write_buf_exact(stream, &*buf)?;
	Ok(())
}

pub trait Peer {
	fn send(&mut self, message: Message) -> Result<()>;
	fn receive(&mut self) -> Result<Message>;
}

impl Peer for TcpStream {
	fn send(&mut self, m: Message) -> Result<()> {
		println!("SENT:\n{}\n", m);
		m.serialize(self)
	}

	fn receive(&mut self) -> Result<Message> {
		match self.peek(&mut [0]) {
			Ok(0) => {
				// AFAIK this should not happen because the `recv` syscall should block until data is available.
				// If the socket connection is closed, `peek` will result in an error, not a zero result.
				unreachable!();
			},
			Ok(_) => {
				let m = Message::deserialize(self)?;
				println!("RECEIVED:\n{}\n", m);
				return Ok(m)
			},
			Err(e) => {
				return Err(Err::NetworkError(e.to_string()));
			},
		}
	}
}