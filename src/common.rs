use std::io::{Read, Write};
use crate::err::*;

pub fn now() -> u64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

pub fn read_u8(stream: &mut dyn Read) -> Result<u8> {
	let mut buf = [0; 1];
	stream.read_exact(&mut buf).map_err(|err| Err::NetworkError(err.to_string()))?;
	Ok(buf[0])
}

pub fn read_bool(stream: &mut dyn Read) -> Result<bool> {
	Ok(read_u8(stream)? == 1)
}

pub fn read_u16(stream: &mut dyn Read) -> Result<u16> {
	let mut buf = [0; 2];
	stream.read_exact(&mut buf).map_err(|err| Err::NetworkError(err.to_string()))?;
	Ok(u16::from_le_bytes(buf))
}

pub fn read_u16_be(stream: &mut dyn Read) -> Result<u16> {
	let mut buf = [0; 2];
	stream.read_exact(&mut buf).map_err(|err| Err::NetworkError(err.to_string()))?;
	Ok(u16::from_be_bytes(buf))
}

pub fn read_u32(stream: &mut dyn Read) -> Result<u32> {
	let mut buf = [0; 4];
	stream.read_exact(&mut buf).map_err(|err| Err::NetworkError(err.to_string()))?;
	Ok(u32::from_le_bytes(buf))
}

pub fn read_u32_be(stream: &mut dyn Read) -> Result<u32> {
	let mut buf = [0; 4];
	stream.read_exact(&mut buf).map_err(|err| Err::NetworkError(err.to_string()))?;
	Ok(u32::from_be_bytes(buf))
}

pub fn read_i32(stream: &mut dyn Read) -> Result<i32> {
	let mut buf = [0; 4];
	stream.read_exact(&mut buf).map_err(|err| Err::NetworkError(err.to_string()))?;
	Ok(i32::from_le_bytes(buf))
}

pub fn read_u64(stream: &mut dyn Read) -> Result<u64> {
	let mut buf = [0; 8];
	stream.read_exact(&mut buf).map_err(|err| Err::NetworkError(err.to_string()))?;
	Ok(u64::from_le_bytes(buf))
}

pub fn read_i64(stream: &mut dyn Read) -> Result<i64> {
	let mut buf = [0; 8];
	stream.read_exact(&mut buf).map_err(|err| Err::NetworkError(err.to_string()))?;
	Ok(i64::from_le_bytes(buf))
}

pub fn read_buf_exact(stream: &mut dyn Read, buf: &mut [u8]) -> Result<()> {
	stream.read_exact(buf).map_err(|err| Err::NetworkError(err.to_string()))?;
	Ok(())
}

pub fn read_str_exact(stream: &mut dyn Read, size: usize) -> Result<String> {
	let mut buf = vec![0; size];
	read_buf_exact(stream, &mut buf)?;
	let s = String::from_utf8(buf)
		.map_err(|err| Err::NetworkError(err.to_string()))?
		.trim_matches(char::from(0))
		.to_owned();
	
	Ok(s)
}

pub fn write_u8(stream: &mut dyn Write, n: u8) -> Result<()> {
	let size = stream.write(&[n]).map_err(|err| Err::NetworkError(err.to_string()))?;
	if size != 1 {
		Err(Err::NetworkError("failed to write 1 byte to stream".to_owned()))?;
	}
	Ok(())
}

pub fn write_bool(stream: &mut dyn Write, n: bool) -> Result<()> {
	write_u8(stream, if n { 1 } else { 0 })
}

pub fn write_u16(stream: &mut dyn Write, n: u16) -> Result<()> {
	let size = stream.write(&n.to_le_bytes()).map_err(|err| Err::NetworkError(err.to_string()))?;
	if size != 2 {
		Err(Err::NetworkError(format!("failed to write {} byte(s) to stream", 2 - size)))?;
	}
	Ok(())
}

pub fn write_u16_be(stream: &mut dyn Write, n: u16) -> Result<()> {
	let size = stream.write(&n.to_be_bytes()).map_err(|err| Err::NetworkError(err.to_string()))?;
	if size != 2 {
		Err(Err::NetworkError(format!("failed to write {} byte(s) to stream", 2 - size)))?;
	}
	Ok(())
}

pub fn write_u32(stream: &mut dyn Write, n: u32) -> Result<()> {
	let size = stream.write(&n.to_le_bytes()).map_err(|err| Err::NetworkError(err.to_string()))?;
	if size != 4 {
		Err(Err::NetworkError(format!("failed to write {} byte(s) to stream", 4 - size)))?;
	}
	Ok(())
}

pub fn write_u32_be(stream: &mut dyn Write, n: u32) -> Result<()> {
	let size = stream.write(&n.to_be_bytes()).map_err(|err| Err::NetworkError(err.to_string()))?;
	if size != 4 {
		Err(Err::NetworkError(format!("failed to write {} byte(s) to stream", 4 - size)))?;
	}
	Ok(())
}

pub fn write_i32(stream: &mut dyn Write, n: i32) -> Result<()> {
	let size = stream.write(&n.to_le_bytes()).map_err(|err| Err::NetworkError(err.to_string()))?;
	if size != 4 {
		Err(Err::NetworkError(format!("failed to write {} byte(s) to stream", 4 - size)))?;
	}
	Ok(())
}

pub fn write_u64(stream: &mut dyn Write, n: u64) -> Result<()> {
	let size = stream.write(&n.to_le_bytes()).map_err(|err| Err::NetworkError(err.to_string()))?;
	if size != 8 {
		Err(Err::NetworkError(format!("failed to write {} byte(s) to stream", 8 - size)))?;
	}
	Ok(())
}

pub fn write_i64(stream: &mut dyn Write, n: i64) -> Result<()> {
	let size = stream.write(&n.to_le_bytes()).map_err(|err| Err::NetworkError(err.to_string()))?;
	if size != 8 {
		Err(Err::NetworkError(format!("failed to write {} byte(s) to stream", 8 - size)))?;
	}
	Ok(())
}

pub fn write_buf_exact(stream: &mut dyn Write, buf: &[u8]) -> Result<()> {
	stream.write(buf).map_err(|err| Err::NetworkError(err.to_string()))?;
	Ok(())
}

pub fn write_str_exact(stream: &mut dyn Write, s: &str, size: usize) -> Result<()> {
	let mut buf = vec![0; size];
	let len = std::cmp::min(size, s.len());
	buf[..len].copy_from_slice(&s.as_bytes()[..len]);
	write_buf_exact(stream, &*buf)?;
	Ok(())
}