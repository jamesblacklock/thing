use std::net::{TcpStream};
use std::io::{Write, Read};
use crate::err::*;

pub mod message;

use message::Message;

pub trait Serialize {
	fn serialize(&self, stream: &mut dyn Write) -> Result<()>;
}

pub trait Deserialize: Sized {
	fn deserialize(stream: &mut dyn Read) -> Result<Self>;
}

pub trait Peer {
	fn send(&mut self, message: Message) -> Result<()>;
	fn receive(&mut self) -> Result<Option<Message>>;
}

impl Peer for TcpStream {
	fn send(&mut self, m: Message) -> Result<()> {
		// log_trace!("SENT:\n{}\n", m);
		log_trace!("SENT: {}", m.payload().name());
		m.serialize(self)
	}

	fn receive(&mut self) -> Result<Option<Message>> {
		match self.peek(&mut [0]) {
			Ok(0) => {
				Ok(None)
			},
			Ok(_) => {
				let m = Message::deserialize(self)?;
				// log_trace!("RECEIVED:\n{}", m);
				log_trace!("RECEIVED: {}", m.payload().name());
				return Ok(Some(m))
			},
			Err(e) => {
				return Err(Err::NetworkError(e.to_string()));
			},
		}
	}
}