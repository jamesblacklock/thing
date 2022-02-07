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

pub trait Peer {
	fn send(&mut self, message: Message) -> Result<()>;
	fn receive(&mut self) -> Result<Message>;
}

impl Peer for TcpStream {
	fn send(&mut self, m: Message) -> Result<()> {
		log_trace!("SENT:\n{}\n", m);
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
				log_trace!("RECEIVED:\n{}\n", m);
				return Ok(m)
			},
			Err(e) => {
				return Err(Err::NetworkError(e.to_string()));
			},
		}
	}
}