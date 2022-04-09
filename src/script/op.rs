use std::fmt;
use super::*;
use crate::{
	network::{Serialize, Deserialize},
	common::write_u32,
	crypto::sha256,
	crypto::sha256::Sha256,
	crypto::ripemd160,
	crypto::ecdsa,
	network::message::AbsoluteLockTime,
};

const OP_0: u8                   = 0;
const OP_PUSHDATA1: u8           = 76;
const OP_PUSHDATA2: u8           = 77;
const OP_PUSHDATA4: u8           = 78;
const OP_1NEGATE: u8             = 79;
const OP_RESERVED: u8            = 80;
const OP_1: u8                   = 81;
const OP_2: u8                   = 82;
const OP_3: u8                   = 83;
const OP_4: u8                   = 84;
const OP_5: u8                   = 85;
const OP_6: u8                   = 86;
const OP_7: u8                   = 87;
const OP_8: u8                   = 88;
const OP_9: u8                   = 89;
const OP_10: u8                  = 90;
const OP_11: u8                  = 91;
const OP_12: u8                  = 92;
const OP_13: u8                  = 93;
const OP_14: u8                  = 94;
const OP_15: u8                  = 95;
const OP_16: u8                  = 96;
const OP_NOP: u8                 = 97;
const OP_VER: u8                 = 98;
const OP_IF: u8                  = 99;
const OP_NOTIF: u8               = 100;
const OP_VERIF: u8               = 101;
const OP_VERNOTIF: u8            = 102;
const OP_ELSE: u8                = 103;
const OP_ENDIF: u8               = 104;
const OP_VERIFY: u8              = 105;
const OP_RETURN: u8              = 106;
const OP_TOALTSTACK: u8          = 107;
const OP_FROMALTSTACK: u8        = 108;
const OP_2DROP: u8               = 109;
const OP_2DUP: u8                = 110;
const OP_3DUP: u8                = 111;
const OP_2OVER: u8               = 112;
const OP_2ROT: u8                = 113;
const OP_2SWAP: u8               = 114;
const OP_IFDUP: u8               = 115;
const OP_DEPTH: u8               = 116;
const OP_DROP: u8                = 117;
const OP_DUP: u8                 = 118;
const OP_NIP: u8                 = 119;
const OP_OVER: u8                = 120;
const OP_PICK: u8                = 121;
const OP_ROLL: u8                = 122;
const OP_ROT: u8                 = 123;
const OP_SWAP: u8                = 124;
const OP_TUCK: u8                = 125;
const OP_CAT: u8                 = 126;
const OP_SUBSTR: u8              = 127;
const OP_LEFT: u8                = 128;
const OP_RIGHT: u8               = 129;
const OP_SIZE: u8                = 130;
const OP_INVERT: u8              = 131;
const OP_AND: u8                 = 132;
const OP_OR: u8                  = 133;
const OP_XOR: u8                 = 134;
const OP_EQUAL: u8               = 135;
const OP_EQUALVERIFY: u8         = 136;
const OP_RESERVED1: u8           = 137;
const OP_RESERVED2: u8           = 138;
const OP_1ADD: u8                = 139;
const OP_1SUB: u8                = 140;
const OP_2MUL: u8                = 141;
const OP_2DIV: u8                = 142;
const OP_NEGATE: u8              = 143;
const OP_ABS: u8                 = 144;
const OP_NOT: u8                 = 145;
const OP_0NOTEQUAL: u8           = 146;
const OP_ADD: u8                 = 147;
const OP_SUB: u8                 = 148;
const OP_MUL: u8                 = 149;
const OP_DIV: u8                 = 150;
const OP_MOD: u8                 = 151;
const OP_LSHIFT: u8              = 152;
const OP_RSHIFT: u8              = 153;
const OP_BOOLAND: u8             = 154;
const OP_BOOLOR: u8              = 155;
const OP_NUMEQUAL: u8            = 156;
const OP_NUMEQUALVERIFY: u8      = 157;
const OP_NUMNOTEQUAL: u8         = 158;
const OP_LESSTHAN: u8            = 159;
const OP_GREATERTHAN: u8         = 160;
const OP_LESSTHANOREQUAL: u8     = 161;
const OP_GREATERTHANOREQUAL: u8  = 162;
const OP_MIN: u8                 = 163;
const OP_MAX: u8                 = 164;
const OP_WITHIN: u8              = 165;
const OP_RIPEMD160: u8           = 166;
const OP_SHA1: u8                = 167;
const OP_SHA256: u8              = 168;
const OP_HASH160: u8             = 169;
const OP_HASH256: u8             = 170;
const OP_CODESEPARATOR: u8       = 171;
const OP_CHECKSIG: u8            = 172;
const OP_CHECKSIGVERIFY: u8      = 173;
const OP_CHECKMULTISIG: u8       = 174;
const OP_CHECKMULTISIGVERIFY: u8 = 175;
const OP_NOP1: u8                = 176;
const OP_CHECKLOCKTIMEVERIFY: u8 = 177;
const OP_CHECKSEQUENCEVERIFY: u8 = 178;
const OP_NOP4: u8                = 179;
const OP_NOP5: u8                = 180;
const OP_NOP6: u8                = 181;
const OP_NOP7: u8                = 182;
const OP_NOP8: u8                = 183;
const OP_NOP9: u8                = 184;
const OP_NOP10: u8               = 185;

#[allow(non_camel_case_types)]
pub enum Op<'a> {
	OP_0,
	DATA(&'a[u8]),
	OWNED_DATA(Vec<u8>),
	PUSHDATA1(&'a[u8]),
	PUSHDATA2(&'a[u8]),
	PUSHDATA4(&'a[u8]),
	OP_1NEGATE,
	RESERVED,
	OP_1,
	OP_2,
	OP_3,
	OP_4,
	OP_5,
	OP_6,
	OP_7,
	OP_8,
	OP_9,
	OP_10,
	OP_11,
	OP_12,
	OP_13,
	OP_14,
	OP_15,
	OP_16,
	NOP,
	VER,
	IF,
	NOTIF,
	VERIF,
	VERNOTIF,
	ELSE,
	ENDIF,
	VERIFY,
	RETURN,
	TOALTSTACK,
	FROMALTSTACK,
	OP_2DROP,
	OP_2DUP,
	OP_3DUP,
	OP_2OVER,
	OP_2ROT,
	OP_2SWAP,
	IFDUP,
	DEPTH,
	DROP,
	DUP,
	NIP,
	OVER,
	PICK,
	ROLL,
	ROT,
	SWAP,
	TUCK,
	CAT,
	SUBSTR,
	LEFT,
	RIGHT,
	SIZE,
	INVERT,
	AND,
	OR,
	XOR,
	EQUAL,
	EQUALVERIFY,
	RESERVED1,
	RESERVED2,
	OP_1ADD,
	OP_1SUB,
	OP_2MUL,
	OP_2DIV,
	NEGATE,
	ABS,
	NOT,
	OP_0NOTEQUAL,
	ADD,
	SUB,
	MUL,
	DIV,
	MOD,
	LSHIFT,
	RSHIFT,
	BOOLAND,
	BOOLOR,
	NUMEQUAL,
	NUMEQUALVERIFY,
	NUMNOTEQUAL,
	LESSTHAN,
	GREATERTHAN,
	LESSTHANOREQUAL,
	GREATERTHANOREQUAL,
	MIN,
	MAX,
	WITHIN,
	RIPEMD160,
	SHA1,
	SHA256,
	HASH160,
	HASH256,
	CODESEPARATOR,
	CHECKSIG,
	CHECKSIGVERIFY,
	CHECKMULTISIG,
	CHECKMULTISIGVERIFY,
	NOP1,
	CHECKLOCKTIMEVERIFY,
	CHECKSEQUENCEVERIFY,
	NOP4,
	NOP5,
	NOP6,
	NOP7,
	NOP8,
	NOP9,
	NOP10,
	INVALIDOPCODE(u8),
}

pub fn fmt_data(f: &mut fmt::Formatter, op: &str, data: &[u8]) -> fmt::Result {
	write!(f, "{}", op)?;
	for &b in data.iter() {
		write!(f, "{:02x}", b)?;
	}
	Ok(())
}

impl <'a> Op<'a> {
	pub fn data_u32(n: u32) -> Self {
		Op::OWNED_DATA(n.to_le_bytes().as_slice().to_vec())
	}

	pub fn data_u8(n: u8) -> Self {
		Op::OWNED_DATA(vec![n])
	}

	pub fn data_str(s: &'a str) -> Self {
		assert!(s.len() <= 75);
		Op::DATA(s.as_bytes())
	}

	pub fn data_hex(s: &str) -> Self {
		let bytes = crate::common::hex_to_bytes(s).unwrap();
		assert!(bytes.len() <= 75);
		Op::OWNED_DATA(bytes.to_vec())
	}

	pub(super) fn append_to(&self, v: &mut Vec<u8>) {
		match self {
			Op::OP_0                => v.push(OP_0),
			Op::DATA(data)          => {
				v.push(data.len() as u8);
				v.extend_from_slice(data);
			},
			Op::OWNED_DATA(data)    => {
				v.push(data.len() as u8);
				v.extend(data);
			},
			Op::PUSHDATA1(data)     => {
				v.push(OP_PUSHDATA1);
				v.push(data.len() as u8);
				v.extend_from_slice(data);
			},
			Op::PUSHDATA2(data)     => {
				v.push(OP_PUSHDATA2);
				v.extend_from_slice(&(data.len() as u16).to_le_bytes());
				v.extend_from_slice(data);
			},
			Op::PUSHDATA4(data)     => {
				v.push(OP_PUSHDATA4);
				v.extend_from_slice(&(data.len() as u32).to_le_bytes());
				v.extend_from_slice(data);
			},
			Op::OP_1NEGATE          => v.push(OP_1NEGATE),
			Op::RESERVED            => v.push(OP_RESERVED),
			Op::OP_1                => v.push(OP_1),
			Op::OP_2                => v.push(OP_2),
			Op::OP_3                => v.push(OP_3),
			Op::OP_4                => v.push(OP_4),
			Op::OP_5                => v.push(OP_5),
			Op::OP_6                => v.push(OP_6),
			Op::OP_7                => v.push(OP_7),
			Op::OP_8                => v.push(OP_8),
			Op::OP_9                => v.push(OP_9),
			Op::OP_10               => v.push(OP_10),
			Op::OP_11               => v.push(OP_11),
			Op::OP_12               => v.push(OP_12),
			Op::OP_13               => v.push(OP_13),
			Op::OP_14               => v.push(OP_14),
			Op::OP_15               => v.push(OP_15),
			Op::OP_16               => v.push(OP_16),
			Op::NOP                 => v.push(OP_NOP),
			Op::VER                 => v.push(OP_VER),
			Op::IF                  => v.push(OP_IF),
			Op::NOTIF               => v.push(OP_NOTIF),
			Op::VERIF               => v.push(OP_VERIF),
			Op::VERNOTIF            => v.push(OP_VERNOTIF),
			Op::ELSE                => v.push(OP_ELSE),
			Op::ENDIF               => v.push(OP_ENDIF),
			Op::VERIFY              => v.push(OP_VERIFY),
			Op::RETURN              => v.push(OP_RETURN),
			Op::TOALTSTACK          => v.push(OP_TOALTSTACK),
			Op::FROMALTSTACK        => v.push(OP_FROMALTSTACK),
			Op::OP_2DROP            => v.push(OP_2DROP),
			Op::OP_2DUP             => v.push(OP_2DUP),
			Op::OP_3DUP             => v.push(OP_3DUP),
			Op::OP_2OVER            => v.push(OP_2OVER),
			Op::OP_2ROT             => v.push(OP_2ROT),
			Op::OP_2SWAP            => v.push(OP_2SWAP),
			Op::IFDUP               => v.push(OP_IFDUP),
			Op::DEPTH               => v.push(OP_DEPTH),
			Op::DROP                => v.push(OP_DROP),
			Op::DUP                 => v.push(OP_DUP),
			Op::NIP                 => v.push(OP_NIP),
			Op::OVER                => v.push(OP_OVER),
			Op::PICK                => v.push(OP_PICK),
			Op::ROLL                => v.push(OP_ROLL),
			Op::ROT                 => v.push(OP_ROT),
			Op::SWAP                => v.push(OP_SWAP),
			Op::TUCK                => v.push(OP_TUCK),
			Op::CAT                 => v.push(OP_CAT),
			Op::SUBSTR              => v.push(OP_SUBSTR),
			Op::LEFT                => v.push(OP_LEFT),
			Op::RIGHT               => v.push(OP_RIGHT),
			Op::SIZE                => v.push(OP_SIZE),
			Op::INVERT              => v.push(OP_INVERT),
			Op::AND                 => v.push(OP_AND),
			Op::OR                  => v.push(OP_OR),
			Op::XOR                 => v.push(OP_XOR),
			Op::EQUAL               => v.push(OP_EQUAL),
			Op::EQUALVERIFY         => v.push(OP_EQUALVERIFY),
			Op::RESERVED1           => v.push(OP_RESERVED1),
			Op::RESERVED2           => v.push(OP_RESERVED2),
			Op::OP_1ADD             => v.push(OP_1ADD),
			Op::OP_1SUB             => v.push(OP_1SUB),
			Op::OP_2MUL             => v.push(OP_2MUL),
			Op::OP_2DIV             => v.push(OP_2DIV),
			Op::NEGATE              => v.push(OP_NEGATE),
			Op::ABS                 => v.push(OP_ABS),
			Op::NOT                 => v.push(OP_NOT),
			Op::OP_0NOTEQUAL        => v.push(OP_0NOTEQUAL),
			Op::ADD                 => v.push(OP_ADD),
			Op::SUB                 => v.push(OP_SUB),
			Op::MUL                 => v.push(OP_MUL),
			Op::DIV                 => v.push(OP_DIV),
			Op::MOD                 => v.push(OP_MOD),
			Op::LSHIFT              => v.push(OP_LSHIFT),
			Op::RSHIFT              => v.push(OP_RSHIFT),
			Op::BOOLAND             => v.push(OP_BOOLAND),
			Op::BOOLOR              => v.push(OP_BOOLOR),
			Op::NUMEQUAL            => v.push(OP_NUMEQUAL),
			Op::NUMEQUALVERIFY      => v.push(OP_NUMEQUALVERIFY),
			Op::NUMNOTEQUAL         => v.push(OP_NUMNOTEQUAL),
			Op::LESSTHAN            => v.push(OP_LESSTHAN),
			Op::GREATERTHAN         => v.push(OP_GREATERTHAN),
			Op::LESSTHANOREQUAL     => v.push(OP_LESSTHANOREQUAL),
			Op::GREATERTHANOREQUAL  => v.push(OP_GREATERTHANOREQUAL),
			Op::MIN                 => v.push(OP_MIN),
			Op::MAX                 => v.push(OP_MAX),
			Op::WITHIN              => v.push(OP_WITHIN),
			Op::RIPEMD160           => v.push(OP_RIPEMD160),
			Op::SHA1                => v.push(OP_SHA1),
			Op::SHA256              => v.push(OP_SHA256),
			Op::HASH160             => v.push(OP_HASH160),
			Op::HASH256             => v.push(OP_HASH256),
			Op::CODESEPARATOR       => v.push(OP_CODESEPARATOR),
			Op::CHECKSIG            => v.push(OP_CHECKSIG),
			Op::CHECKSIGVERIFY      => v.push(OP_CHECKSIGVERIFY),
			Op::CHECKMULTISIG       => v.push(OP_CHECKMULTISIG),
			Op::CHECKMULTISIGVERIFY => v.push(OP_CHECKMULTISIGVERIFY),
			Op::NOP1                => v.push(OP_NOP1),
			Op::CHECKLOCKTIMEVERIFY => v.push(OP_CHECKLOCKTIMEVERIFY),
			Op::CHECKSEQUENCEVERIFY => v.push(OP_CHECKSEQUENCEVERIFY),
			Op::NOP4                => v.push(OP_NOP4),
			Op::NOP5                => v.push(OP_NOP5),
			Op::NOP6                => v.push(OP_NOP6),
			Op::NOP7                => v.push(OP_NOP7),
			Op::NOP8                => v.push(OP_NOP8),
			Op::NOP9                => v.push(OP_NOP9),
			Op::NOP10               => v.push(OP_NOP10),
			Op::INVALIDOPCODE(b)    => v.push(*b),
		}
	}

	pub(super) fn next(it: &mut ScriptIterator<'a>) -> Self {
		let opcode = it.next_u8();
		match opcode {
			OP_0                   => Op::OP_0,
			x @ 1..=75             => Op::DATA(it.next_slice(x as usize)),
			OP_PUSHDATA1           => {
				let size = it.next_u8() as usize;
				Op::PUSHDATA1(it.next_slice(size))
			},
			OP_PUSHDATA2           => {
				let size = it.next_u16() as usize;
				Op::PUSHDATA2(it.next_slice(size))
			},
			OP_PUSHDATA4           => {
				let size = it.next_u32() as usize;
				Op::PUSHDATA4(it.next_slice(size))
			},
			OP_1NEGATE             => Op::OP_1NEGATE,
			OP_RESERVED            => Op::RESERVED,
			OP_1                   => Op::OP_1,
			OP_2                   => Op::OP_2,
			OP_3                   => Op::OP_3,
			OP_4                   => Op::OP_4,
			OP_5                   => Op::OP_5,
			OP_6                   => Op::OP_6,
			OP_7                   => Op::OP_7,
			OP_8                   => Op::OP_8,
			OP_9                   => Op::OP_9,
			OP_10                  => Op::OP_10,
			OP_11                  => Op::OP_11,
			OP_12                  => Op::OP_12,
			OP_13                  => Op::OP_13,
			OP_14                  => Op::OP_14,
			OP_15                  => Op::OP_15,
			OP_16                  => Op::OP_16,
			OP_NOP                 => Op::NOP,
			OP_VER                 => Op::VER,
			OP_IF                  => Op::IF,
			OP_NOTIF               => Op::NOTIF,
			OP_VERIF               => Op::VERIF,
			OP_VERNOTIF            => Op::VERNOTIF,
			OP_ELSE                => Op::ELSE,
			OP_ENDIF               => Op::ENDIF,
			OP_VERIFY              => Op::VERIFY,
			OP_RETURN              => Op::RETURN,
			OP_TOALTSTACK          => Op::TOALTSTACK,
			OP_FROMALTSTACK        => Op::FROMALTSTACK,
			OP_2DROP               => Op::OP_2DROP,
			OP_2DUP                => Op::OP_2DUP,
			OP_3DUP                => Op::OP_3DUP,
			OP_2OVER               => Op::OP_2OVER,
			OP_2ROT                => Op::OP_2ROT,
			OP_2SWAP               => Op::OP_2SWAP,
			OP_IFDUP               => Op::IFDUP,
			OP_DEPTH               => Op::DEPTH,
			OP_DROP                => Op::DROP,
			OP_DUP                 => Op::DUP,
			OP_NIP                 => Op::NIP,
			OP_OVER                => Op::OVER,
			OP_PICK                => Op::PICK,
			OP_ROLL                => Op::ROLL,
			OP_ROT                 => Op::ROT,
			OP_SWAP                => Op::SWAP,
			OP_TUCK                => Op::TUCK,
			OP_CAT                 => Op::CAT,
			OP_SUBSTR              => Op::SUBSTR,
			OP_LEFT                => Op::LEFT,
			OP_RIGHT               => Op::RIGHT,
			OP_SIZE                => Op::SIZE,
			OP_INVERT              => Op::INVERT,
			OP_AND                 => Op::AND,
			OP_OR                  => Op::OR,
			OP_XOR                 => Op::XOR,
			OP_EQUAL               => Op::EQUAL,
			OP_EQUALVERIFY         => Op::EQUALVERIFY,
			OP_RESERVED1           => Op::RESERVED1,
			OP_RESERVED2           => Op::RESERVED2,
			OP_1ADD                => Op::OP_1ADD,
			OP_1SUB                => Op::OP_1SUB,
			OP_2MUL                => Op::OP_2MUL,
			OP_2DIV                => Op::OP_2DIV,
			OP_NEGATE              => Op::NEGATE,
			OP_ABS                 => Op::ABS,
			OP_NOT                 => Op::NOT,
			OP_0NOTEQUAL           => Op::OP_0NOTEQUAL,
			OP_ADD                 => Op::ADD,
			OP_SUB                 => Op::SUB,
			OP_MUL                 => Op::MUL,
			OP_DIV                 => Op::DIV,
			OP_MOD                 => Op::MOD,
			OP_LSHIFT              => Op::LSHIFT,
			OP_RSHIFT              => Op::RSHIFT,
			OP_BOOLAND             => Op::BOOLAND,
			OP_BOOLOR              => Op::BOOLOR,
			OP_NUMEQUAL            => Op::NUMEQUAL,
			OP_NUMEQUALVERIFY      => Op::NUMEQUALVERIFY,
			OP_NUMNOTEQUAL         => Op::NUMNOTEQUAL,
			OP_LESSTHAN            => Op::LESSTHAN,
			OP_GREATERTHAN         => Op::GREATERTHAN,
			OP_LESSTHANOREQUAL     => Op::LESSTHANOREQUAL,
			OP_GREATERTHANOREQUAL  => Op::GREATERTHANOREQUAL,
			OP_MIN                 => Op::MIN,
			OP_MAX                 => Op::MAX,
			OP_WITHIN              => Op::WITHIN,
			OP_RIPEMD160           => Op::RIPEMD160,
			OP_SHA1                => Op::SHA1,
			OP_SHA256              => Op::SHA256,
			OP_HASH160             => Op::HASH160,
			OP_HASH256             => Op::HASH256,
			OP_CODESEPARATOR       => Op::CODESEPARATOR,
			OP_CHECKSIG            => Op::CHECKSIG,
			OP_CHECKSIGVERIFY      => Op::CHECKSIGVERIFY,
			OP_CHECKMULTISIG       => Op::CHECKMULTISIG,
			OP_CHECKMULTISIGVERIFY => Op::CHECKMULTISIGVERIFY,
			OP_NOP1                => Op::NOP1,
			OP_CHECKLOCKTIMEVERIFY => Op::CHECKLOCKTIMEVERIFY,
			OP_CHECKSEQUENCEVERIFY => Op::CHECKSEQUENCEVERIFY,
			OP_NOP4                => Op::NOP4,
			OP_NOP5                => Op::NOP5,
			OP_NOP6                => Op::NOP6,
			OP_NOP7                => Op::NOP7,
			OP_NOP8                => Op::NOP8,
			OP_NOP9                => Op::NOP9,
			OP_NOP10               => Op::NOP10,
			b                      => Op::INVALIDOPCODE(b),
		}
	}

	pub(super) fn affect(&'a self, runtime: &mut ScriptRuntime) -> Result<()> {
		let result = match self {
			Op::VERIF               => Op::do_reserved("OP_VERIF"),
			Op::VERNOTIF            => Op::do_reserved("OP_VERNOTIF"),
			Op::CAT                 => Op::do_disabled("OP_CAT"),
			Op::SUBSTR              => Op::do_disabled("OP_SUBSTR"),
			Op::LEFT                => Op::do_disabled("OP_LEFT"),
			Op::RIGHT               => Op::do_disabled("OP_RIGHT"),
			Op::INVERT              => Op::do_disabled("OP_INVERT"),
			Op::AND                 => Op::do_disabled("OP_AND"),
			Op::OR                  => Op::do_disabled("OP_OR"),
			Op::XOR                 => Op::do_disabled("OP_XOR"),
			Op::OP_2MUL             => Op::do_disabled("OP_2MUL"),
			Op::OP_2DIV             => Op::do_disabled("OP_2DIV"),
			Op::MUL                 => Op::do_disabled("OP_MUL"),
			Op::DIV                 => Op::do_disabled("OP_DIV"),
			Op::MOD                 => Op::do_disabled("OP_MOD"),
			Op::LSHIFT              => Op::do_disabled("OP_LSHIFT"),
			Op::RSHIFT              => Op::do_disabled("OP_RSHIFT"),
			_ => Ok(()),
		};

		if let Err(err) = result {
			runtime.invalid = true;
			return Err(err);
		}
		
		if runtime.skip_depth > 0 {
			let result = match self {
				Op::IF => Op::do_if(runtime),
				Op::ELSE => Op::do_else(runtime),
				Op::ENDIF => Op::do_end_if(runtime),
				_ => Ok(()),
			};

			if let Err(err) = result {
				runtime.invalid = true;
				return Err(err);
			}
			return Ok(())
		}

		let result = match self {
			Op::OP_0                => Op::do_push_num(runtime, 0),
			Op::DATA(bytes)         => Op::do_push_bytes(runtime, bytes.to_vec()),
			Op::OWNED_DATA(bytes)   => Op::do_push_bytes(runtime, bytes.clone()),
			Op::PUSHDATA1(bytes)    => Op::do_push_bytes(runtime, bytes.to_vec()),
			Op::PUSHDATA2(bytes)    => Op::do_push_bytes(runtime, bytes.to_vec()),
			Op::PUSHDATA4(bytes)    => Op::do_push_bytes(runtime, bytes.to_vec()),
			Op::OP_1NEGATE          => Op::do_push_num(runtime, -1),
			Op::RESERVED            => Op::do_reserved("OP_RESERVED"),
			Op::OP_1                => Op::do_push_num(runtime, 1),
			Op::OP_2                => Op::do_push_num(runtime, 2),
			Op::OP_3                => Op::do_push_num(runtime, 3),
			Op::OP_4                => Op::do_push_num(runtime, 4),
			Op::OP_5                => Op::do_push_num(runtime, 5),
			Op::OP_6                => Op::do_push_num(runtime, 6),
			Op::OP_7                => Op::do_push_num(runtime, 7),
			Op::OP_8                => Op::do_push_num(runtime, 8),
			Op::OP_9                => Op::do_push_num(runtime, 9),
			Op::OP_10               => Op::do_push_num(runtime, 10),
			Op::OP_11               => Op::do_push_num(runtime, 11),
			Op::OP_12               => Op::do_push_num(runtime, 12),
			Op::OP_13               => Op::do_push_num(runtime, 13),
			Op::OP_14               => Op::do_push_num(runtime, 14),
			Op::OP_15               => Op::do_push_num(runtime, 15),
			Op::OP_16               => Op::do_push_num(runtime, 16),
			Op::NOP                 => Ok(()),
			Op::VER                 => Op::do_reserved("OP_VER"),
			Op::IF                  => Op::do_if(runtime),
			Op::NOTIF               => Op::do_not_if(runtime),
			Op::ELSE                => Op::do_else(runtime),
			Op::ENDIF               => Op::do_end_if(runtime),
			Op::VERIFY              => Op::do_verify(runtime, "OP_VERIFY"),
			Op::RETURN              => Op::do_return(runtime),
			Op::TOALTSTACK          => Op::do_to_alt_stack(runtime),
			Op::FROMALTSTACK        => Op::do_from_alt_stack(runtime),
			Op::OP_2DROP            => Op::do_drop(runtime, 2),
			Op::OP_2DUP             => Op::do_dup(runtime, 2),
			Op::OP_3DUP             => Op::do_dup(runtime, 3),
			Op::OP_2OVER            => Op::do_over2(runtime),
			Op::OP_2ROT             => Op::do_rot2(runtime),
			Op::OP_2SWAP            => Op::do_swap2(runtime),
			Op::IFDUP               => Op::do_ifdup(runtime),
			Op::DEPTH               => Op::do_depth(runtime),
			Op::DROP                => Op::do_drop(runtime, 1),
			Op::DUP                 => Op::do_dup(runtime, 1),
			Op::NIP                 => Op::do_nip(runtime),
			Op::OVER                => Op::do_over(runtime),
			Op::PICK                => Op::do_pick(runtime),
			Op::ROLL                => Op::do_roll(runtime),
			Op::ROT                 => Op::do_rot(runtime),
			Op::SWAP                => Op::do_swap(runtime),
			Op::TUCK                => Op::do_tuck(runtime),
			Op::SIZE                => Op::do_size(runtime),
			Op::EQUAL               => Op::do_equal(runtime),
			Op::EQUALVERIFY         => Op::do_equal_verify(runtime),
			Op::RESERVED1           => Op::do_reserved("OP_RESERVED1"),
			Op::RESERVED2           => Op::do_reserved("OP_RESERVED2"),
			Op::OP_1ADD             => Op::do_num_add1(runtime),
			Op::OP_1SUB             => Op::do_num_sub1(runtime),
			Op::NEGATE              => Op::do_num_neg(runtime),
			Op::ABS                 => Op::do_num_abs(runtime),
			Op::NOT                 => Op::do_num_not(runtime),
			Op::OP_0NOTEQUAL        => Op::do_num_neq0(runtime),
			Op::ADD                 => Op::do_num_add(runtime),
			Op::SUB                 => Op::do_num_sub(runtime),
			Op::BOOLAND             => Op::do_num_booland(runtime),
			Op::BOOLOR              => Op::do_num_boolor(runtime),
			Op::NUMEQUAL            => Op::do_num_eq(runtime),
			Op::NUMEQUALVERIFY      => Op::do_num_eq_verify(runtime),
			Op::NUMNOTEQUAL         => Op::do_num_ne(runtime),
			Op::LESSTHAN            => Op::do_num_lt(runtime),
			Op::GREATERTHAN         => Op::do_num_gt(runtime),
			Op::GREATERTHANOREQUAL  => Op::do_num_ge(runtime),
			Op::LESSTHANOREQUAL     => Op::do_num_le(runtime),
			Op::MIN                 => Op::do_num_min(runtime),
			Op::MAX                 => Op::do_num_max(runtime),
			Op::WITHIN              => Op::do_num_within(runtime),
			Op::RIPEMD160           => Op::do_ripemd160(runtime),
			Op::SHA1                => unimplemented!(),
			Op::SHA256              => Op::do_sha256(runtime),
			Op::HASH160             => Op::do_hash160(runtime),
			Op::HASH256             => Op::do_hash256(runtime),
			Op::CODESEPARATOR       => Op::do_code_separator(runtime),
			Op::CHECKSIG            => Op::do_check_sig(runtime),
			Op::CHECKSIGVERIFY      => Op::do_check_sig_verify(runtime),
			Op::CHECKMULTISIG       => Op::do_check_multisig(runtime),
			Op::CHECKMULTISIGVERIFY => Op::do_check_multisig_verify(runtime),
			Op::NOP1                => Ok(()),
			Op::CHECKLOCKTIMEVERIFY => Op::do_check_lock_time_verify(runtime),
			Op::CHECKSEQUENCEVERIFY => unimplemented!(),
			Op::NOP4                => Ok(()),
			Op::NOP5                => Ok(()),
			Op::NOP6                => Ok(()),
			Op::NOP7                => Ok(()),
			Op::NOP8                => Ok(()),
			Op::NOP9                => Ok(()),
			Op::NOP10               => Ok(()),
			Op::INVALIDOPCODE(op)    => Op::do_invalid(*op),
			_ => unreachable!(),
		};

		if let Err(err) = result {
			runtime.invalid = true;
			Err(err)
		} else {
			Ok(())
		}
	}

	fn do_push_num(runtime: &mut ScriptRuntime, n: i64) -> Result<()> {
		Op::push_stack(runtime, StackObject::Int(n))
	}

	fn do_push_bytes(runtime: &mut ScriptRuntime, b: Vec<u8>) -> Result<()> {
		Op::push_stack(runtime, StackObject::Bytes(b))
	}

	fn do_drop(runtime: &mut ScriptRuntime, count: usize) -> Result<()> {
		for _ in 0..count {
			Op::pop_stack(runtime).and(Ok(()))?;
		}
		Ok(())
	}

	fn do_check_sig_verify(runtime: &mut ScriptRuntime) -> Result<()> {
		Op::do_check_sig(runtime).and_then(|_| Op::do_verify(runtime, "OP_CHECKSIGVERIFY"))
	}

	fn do_check_multisig_verify(runtime: &mut ScriptRuntime) -> Result<()> {
		Op::do_check_multisig(runtime).and_then(|_| Op::do_verify(runtime, "OP_CHECKMULTISIGVERIFY"))
	}

	fn do_equal_verify(runtime: &mut ScriptRuntime) -> Result<()> {
		Op::do_equal(runtime).and_then(|_| Op::do_verify(runtime, "OP_EQUALVERIFY"))
	}

	fn do_num_eq_verify(runtime: &mut ScriptRuntime) -> Result<()> {
		Op::do_num_eq(runtime).and_then(|_| Op::do_verify(runtime, "OP_NUMEQUALERIFY"))
	}

	fn do_code_separator(runtime: &mut ScriptRuntime) -> Result<()> {
		runtime.code_sep = runtime.offset;
		Ok(())
	}

	fn do_equal(runtime: &mut ScriptRuntime) -> Result<()> {
		let i = Op::pop_stack(runtime)?;
		let j = Op::pop_stack(runtime)?;
		if i == j {
			Op::push_stack(runtime, StackObject::Int(1))
		} else {
			Op::push_stack(runtime, StackObject::Empty)
		}
	}

	fn do_verify(runtime: &mut ScriptRuntime, opcode: &str) -> Result<()> {
		let value = Op::pop_stack(runtime)?;
		if value.is_falsey() {
			return Err(Err::ScriptError(format!("{}: verification failed", opcode)))
		}
		Ok(())
	}

	fn do_if(runtime: &mut ScriptRuntime) -> Result<()> {
		Op::if_impl(runtime, true)
	}

	fn do_not_if(runtime: &mut ScriptRuntime) -> Result<()> {
		Op::if_impl(runtime, false)
	}

	fn if_impl(runtime: &mut ScriptRuntime, expected_truthiness: bool) -> Result<()> {
		if runtime.skip_depth > 0 {
			runtime.skip_depth += 1;
			return Ok(());
		}

		let value = Op::pop_stack(runtime)?;
		if value.is_truthy() == expected_truthiness {
			runtime.depth = 1;
		} else {
			runtime.skip_depth += 1;
		}

		Ok(())
	}

	fn do_else(runtime: &mut ScriptRuntime) -> Result<()> {
		if runtime.skip_depth == 1 {
			runtime.skip_depth = 0;
			runtime.depth += 1;
		} else if runtime.skip_depth > 1 {
			// do nothing
		} else if runtime.depth > 0 {
			runtime.depth -= 1;
			runtime.skip_depth = 1;
		} else {
			return Err(Err::ScriptError("encountered OP_ELSE without an associated OP_IF".to_owned()));
		}

		Ok(())
	}

	fn do_end_if(runtime: &mut ScriptRuntime) -> Result<()> {
		if runtime.skip_depth > 0 {
			runtime.skip_depth -= 1;
		} else if runtime.depth > 0 {
			runtime.depth -= 1;
		} else {
			return Err(Err::ScriptError("encountered OP_ENDIF without an associated OP_IF".to_owned()));
		}

		Ok(())
	}

	fn do_return(runtime: &mut ScriptRuntime) -> Result<()> {
		// an OP_RETURN isn't really an "error", so that's why I do this here rather than return an error
		// TODO: do not store UTXOs in the UTXO set if their locking scripts contain a RETURN
		// Also TODO: consider other heuristics that make a UTXO provably unspendable
		runtime.invalid = true;
		Ok(())
	}

	fn do_reserved(opcode: &str) -> Result<()> {
		Err(Err::ScriptError(format!("script contains reserved opcode: {}", opcode)))
	}

	fn do_disabled(opcode: &str) -> Result<()> {
		Err(Err::ScriptError(format!("script contains disabled opcode: {}", opcode)))
	}

	fn do_invalid(opcode: u8) -> Result<()> {
		Err(Err::ScriptError(format!("script contains invalid opcode: {}", opcode)))
	}

	fn do_over(runtime: &mut ScriptRuntime) -> Result<()> {
		Op::check_stack(runtime, 2)?;
		Op::push_stack(runtime, runtime.stack[runtime.stack.len() - 2].clone())
	}

	fn do_rot(runtime: &mut ScriptRuntime) -> Result<()> {
		let x3 = Op::pop_stack(runtime)?;
		let x2 = Op::pop_stack(runtime)?;
		let x1 = Op::pop_stack(runtime)?;
		Op::push_stack(runtime, x2)?;
		Op::push_stack(runtime, x3)?;
		Op::push_stack(runtime, x1)
	}

	fn do_swap(runtime: &mut ScriptRuntime) -> Result<()> {
		let x2 = Op::pop_stack(runtime)?;
		let x1 = Op::pop_stack(runtime)?;
		Op::push_stack(runtime, x2)?;
		Op::push_stack(runtime, x1)
	}

	fn do_over2(runtime: &mut ScriptRuntime) -> Result<()> {
		Op::check_stack(runtime, 4)?;
		Op::push_stack(runtime, runtime.stack[runtime.stack.len() - 4].clone())?;
		Op::push_stack(runtime, runtime.stack[runtime.stack.len() - 3].clone())
	}

	fn do_rot2(runtime: &mut ScriptRuntime) -> Result<()> {
		let x6 = Op::pop_stack(runtime)?;
		let x5 = Op::pop_stack(runtime)?;
		let x4 = Op::pop_stack(runtime)?;
		let x3 = Op::pop_stack(runtime)?;
		let x2 = Op::pop_stack(runtime)?;
		let x1 = Op::pop_stack(runtime)?;
		Op::push_stack(runtime, x3)?;
		Op::push_stack(runtime, x4)?;
		Op::push_stack(runtime, x5)?;
		Op::push_stack(runtime, x6)?; 
		Op::push_stack(runtime, x1)?;
		Op::push_stack(runtime, x2)
	}

	fn do_swap2(runtime: &mut ScriptRuntime) -> Result<()> {
		let x4 = Op::pop_stack(runtime)?;
		let x3 = Op::pop_stack(runtime)?;
		let x2 = Op::pop_stack(runtime)?;
		let x1 = Op::pop_stack(runtime)?;
		Op::push_stack(runtime, x3)?;
		Op::push_stack(runtime, x4)?;
		Op::push_stack(runtime, x1)?;
		Op::push_stack(runtime, x2)
	}

	fn do_ifdup(runtime: &mut ScriptRuntime) -> Result<()> {
		if let Some(item) = runtime.stack.last() {
			if item.is_truthy() {
				Op::do_dup(runtime, 1)?;
			}
			Ok(())
		} else {
			Err(Err::ScriptError("too few items on the stack".to_owned()))
		}
	}

	fn do_depth(runtime: &mut ScriptRuntime) -> Result<()> {
		Op::push_stack(runtime, StackObject::Int(runtime.stack.len() as i64))
	}

	fn do_nip(runtime: &mut ScriptRuntime) -> Result<()> {
		let item = Op::pop_stack(runtime)?;
		Op::pop_stack(runtime)?;
		Op::push_stack(runtime, item)
	}

	fn do_pick(runtime: &mut ScriptRuntime) -> Result<()> {
		let n = Op::pop_stack_index(runtime)?;
		let item = runtime.stack[n].clone();
		Op::push_stack(runtime, item)
	}

	fn do_roll(runtime: &mut ScriptRuntime) -> Result<()> {
		let n = Op::pop_stack_index(runtime)?;
		let item = runtime.stack[n].clone();
		for i in n..runtime.stack.len()-1 {
			runtime.stack[i] = runtime.stack[i + 1].clone();
		}
		Op::push_stack(runtime, item)
	}

	fn do_tuck(runtime: &mut ScriptRuntime) -> Result<()> {
		let x2 = Op::pop_stack(runtime)?;
		let x1 = Op::pop_stack(runtime)?;
		Op::push_stack(runtime, x2.clone())?;
		Op::push_stack(runtime, x1)?;
		Op::push_stack(runtime, x2)
	}

	fn do_size(runtime: &mut ScriptRuntime) -> Result<()> {
		let len = if let Some(item) = runtime.stack.last() {
			item.to_vec().len()
		} else {
			return Err(Err::ScriptError("too few items on the stack".to_owned()))
		};
		Op::do_push_num(runtime, len as i64)
	}

	fn do_to_alt_stack(runtime: &mut ScriptRuntime) -> Result<()> {
		let item = Op::pop_stack(runtime)?;
		Op::push_alt_stack(runtime, item)
	}

	fn do_from_alt_stack(runtime: &mut ScriptRuntime) -> Result<()> {
		let item = Op::pop_alt_stack(runtime)?;
		Op::push_stack(runtime, item)
	}

	fn do_dup(runtime: &mut ScriptRuntime, count: usize) -> Result<()> {
		assert!(count > 0);
		if runtime.stack.len() < count {
			return Err(Err::ScriptError("too few items on the stack".to_owned()))
		}

		let offset = runtime.stack.len() - count;
		for i in offset..runtime.stack.len() {
			let item = runtime.stack[i].clone();
			Op::push_stack(runtime, item)?;
		}
		Ok(())
	}

	fn do_num_eq(runtime: &mut ScriptRuntime) -> Result<()> {
		let r = Op::pop_stack(runtime)?.to_i64();
		let l = Op::pop_stack(runtime)?.to_i64();
		Op::push_stack(runtime, StackObject::Int((l == r) as i64))
	}

	fn do_num_ne(runtime: &mut ScriptRuntime) -> Result<()> {
		let r = Op::pop_stack(runtime)?.to_i64();
		let l = Op::pop_stack(runtime)?.to_i64();
		Op::push_stack(runtime, StackObject::Int((l != r) as i64))
	}

	fn do_num_lt(runtime: &mut ScriptRuntime) -> Result<()> {
		let r = Op::pop_stack(runtime)?.to_i64();
		let l = Op::pop_stack(runtime)?.to_i64();
		Op::push_stack(runtime, StackObject::Int((l < r) as i64))
	}

	fn do_num_gt(runtime: &mut ScriptRuntime) -> Result<()> {
		let r = Op::pop_stack(runtime)?.to_i64();
		let l = Op::pop_stack(runtime)?.to_i64();
		Op::push_stack(runtime, StackObject::Int((l > r) as i64))
	}

	fn do_num_ge(runtime: &mut ScriptRuntime) -> Result<()> {
		let r = Op::pop_stack(runtime)?.to_i64();
		let l = Op::pop_stack(runtime)?.to_i64();
		Op::push_stack(runtime, StackObject::Int((l >= r) as i64))
	}

	fn do_num_le(runtime: &mut ScriptRuntime) -> Result<()> {
		let r = Op::pop_stack(runtime)?.to_i64();
		let l = Op::pop_stack(runtime)?.to_i64();
		Op::push_stack(runtime, StackObject::Int((l <= r) as i64))
	}

	fn do_num_min(runtime: &mut ScriptRuntime) -> Result<()> {
		let r = Op::pop_stack(runtime)?.to_i64();
		let l = Op::pop_stack(runtime)?.to_i64();
		let min = std::cmp::min(l, r);
		Op::push_stack(runtime, StackObject::Int(min))
	}

	fn do_num_max(runtime: &mut ScriptRuntime) -> Result<()> {
		let r = Op::pop_stack(runtime)?.to_i64();
		let l = Op::pop_stack(runtime)?.to_i64();
		let max = std::cmp::max(l, r);
		Op::push_stack(runtime, StackObject::Int(max))
	}

	fn do_num_within(runtime: &mut ScriptRuntime) -> Result<()> {
		let max = Op::pop_stack(runtime)?.to_i64();
		let min = Op::pop_stack(runtime)?.to_i64();
		let n = Op::pop_stack(runtime)?.to_i64();
		Op::push_stack(runtime, StackObject::Int((min <= n && n < max) as i64))
	}

	fn do_num_add(runtime: &mut ScriptRuntime) -> Result<()> {
		let r = Op::pop_stack(runtime)?.to_i64();
		let l = Op::pop_stack(runtime)?.to_i64();
		Op::push_stack(runtime, StackObject::Int(l + r))
	}

	fn do_num_sub(runtime: &mut ScriptRuntime) -> Result<()> {
		let r = Op::pop_stack(runtime)?.to_i64();
		let l = Op::pop_stack(runtime)?.to_i64();
		Op::push_stack(runtime, StackObject::Int(l - r))
	}

	fn do_num_booland(runtime: &mut ScriptRuntime) -> Result<()> {
		let r = Op::pop_stack(runtime)?.to_i64();
		let l = Op::pop_stack(runtime)?.to_i64();
		Op::push_stack(runtime, StackObject::Int((l != 0 && r != 0) as i64))
	}

	fn do_num_boolor(runtime: &mut ScriptRuntime) -> Result<()> {
		let r = Op::pop_stack(runtime)?.to_i64();
		let l = Op::pop_stack(runtime)?.to_i64();
		Op::push_stack(runtime, StackObject::Int((l != 0 || r != 0) as i64))
	}

	fn do_num_add1(runtime: &mut ScriptRuntime) -> Result<()> {
		let n = Op::pop_stack(runtime)?.to_i64();
		Op::push_stack(runtime, StackObject::Int(n + 1))
	}

	fn do_num_sub1(runtime: &mut ScriptRuntime) -> Result<()> {
		let n = Op::pop_stack(runtime)?.to_i64();
		Op::push_stack(runtime, StackObject::Int(n - 1))
	}

	fn do_num_neg(runtime: &mut ScriptRuntime) -> Result<()> {
		let n = Op::pop_stack(runtime)?.to_i64();
		Op::push_stack(runtime, StackObject::Int(-n))
	}

	fn do_num_abs(runtime: &mut ScriptRuntime) -> Result<()> {
		let n = Op::pop_stack(runtime)?.to_i64();
		Op::push_stack(runtime, StackObject::Int(n.abs()))
	}

	fn do_num_not(runtime: &mut ScriptRuntime) -> Result<()> {
		let n = Op::pop_stack(runtime)?.to_i64();
		Op::push_stack(runtime, StackObject::Int((n != 0) as i64))
	}

	fn do_num_neq0(runtime: &mut ScriptRuntime) -> Result<()> {
		let n = Op::pop_stack(runtime)?.to_i64();
		Op::push_stack(runtime, StackObject::Int((n != 0) as i64))
	}

	fn do_ripemd160(runtime: &mut ScriptRuntime) -> Result<()> {
		let item = Op::pop_stack(runtime)?;
		let hash = ripemd160::compute_ripemd160(&*item.to_vec());
		Op::push_stack(runtime, StackObject::Bytes(hash.as_bytes().to_vec()))
	}

	fn do_sha256(runtime: &mut ScriptRuntime) -> Result<()> {
		let item = Op::pop_stack(runtime)?;
		let hash = sha256::compute_sha256(&*item.to_vec());
		Op::push_stack(runtime, StackObject::Bytes(hash.as_bytes().to_vec()))
	}

	fn do_hash160(runtime: &mut ScriptRuntime) -> Result<()> {
		let item = Op::pop_stack(runtime)?;
		let hash = ripemd160::compute_ripemd160(sha256::compute_sha256(&*item.to_vec()).as_bytes());
		Op::push_stack(runtime, StackObject::Bytes(hash.as_bytes().to_vec()))
	}

	fn do_hash256(runtime: &mut ScriptRuntime) -> Result<()> {
		let item = Op::pop_stack(runtime)?;
		let hash = sha256::compute_double_sha256(&*item.to_vec());
		Op::push_stack(runtime, StackObject::Bytes(hash.as_bytes().to_vec()))
	}

	fn do_check_sig(runtime: &mut ScriptRuntime) -> Result<()> {
		let pubkey_item = Op::pop_stack(runtime)?;
		let sig_item = Op::pop_stack(runtime)?;
		
		let pubkey = pubkey_item.to_vec();
		let sig = sig_item.to_vec();
		let hash_type = *sig.last().unwrap();
		let sig = &sig[0..sig.len()-1];
		
		let hash = Op::build_sig_hash(runtime, hash_type)?;

		if ecdsa::verify(&*pubkey, sig, &hash).is_ok() {
			Op::push_stack(runtime, StackObject::Int(1))
		} else {
			Op::push_stack(runtime, StackObject::Empty)
		}
	}

	fn do_check_multisig(runtime: &mut ScriptRuntime) -> Result<()> {
		// collect pub keys
		let n_pub = Op::pop_stack(runtime)?;
		let mut pubkeys = Vec::new();
		for _ in 0..n_pub.to_i64() {
			pubkeys.push(Op::pop_stack(runtime)?.to_vec());
		}

		// collect sigs
		let n_sig = Op::pop_stack(runtime)?;
		let mut sigs = Vec::new();
		for _ in 0..n_sig.to_i64() {
			let sig = Op::pop_stack(runtime)?.to_vec();
			let hash_type = *sig.last().unwrap();
			let sig = sig[0..sig.len()-1].to_vec();
			sigs.push((sig, hash_type));
		}

		// dummy value
		Op::pop_stack(runtime)?;

		let mut last_hash_type = None;
		let mut hash = Sha256::default();
		
		while let Some((sig, hash_type)) = sigs.pop() {
			if last_hash_type != Some(hash_type) {
				hash = Op::build_sig_hash(runtime, hash_type)?;
				last_hash_type = Some(hash_type);
			}

			let result = loop {
				if let Some(pubkey) = pubkeys.pop() {
					if ecdsa::verify(&*pubkey, &*sig, &hash).is_ok() {
						break true;
					}
				} else {
					break false;
				}
			};

			if result == false {
				return Op::push_stack(runtime, StackObject::Empty);
			}
		}

		Op::push_stack(runtime, StackObject::Int(1))
	}

	fn do_check_lock_time_verify(runtime: &mut ScriptRuntime) -> Result<()> {
		// prior to the implementation of BIP 65, OP_CLTV was OP_NOP2 (with no effect)
		if !runtime.state.cltv_enabled() {
			return Ok(());
		}

		let err = || Err(Err::ScriptError("OP_CHECKLOCKTIMEVERIFY failed".to_owned()));
		
		let val = if let Some(val) = runtime.stack.last() {
			val.to_i64()
		} else {
			return err();
		};

		if val < 0 {
			return err();
		} else if runtime.tx.inputs[runtime.index].sequence == 0xffffffff {
			return err();
		}

		let lock_time = AbsoluteLockTime::from_u32(val as u32);

		let invalid = match (runtime.tx.abs_lock_time, lock_time) {
			(AbsoluteLockTime::BlockNumber(n), AbsoluteLockTime::BlockNumber(m)) => m > n,
			(AbsoluteLockTime::Timestamp(n), AbsoluteLockTime::Timestamp(m)) => m > n,
			(AbsoluteLockTime::None, AbsoluteLockTime::None) => false,
			_ => true,
		};

		if invalid {
			return err();
		}
		
		Ok(())
	}

	fn build_sig_hash(runtime: &mut ScriptRuntime, hash_type: u8) -> Result<Sha256> {
		const SIGHASH_NONE         : u8 = 0x02;
		const SIGHASH_SINGLE       : u8 = 0x03;
		const SIGHASH_ANYONECANPAY : u8 = 0x80;

		let sighash_none = hash_type & 0x1f == SIGHASH_NONE;
		let sighash_single = hash_type & 0x1f == SIGHASH_SINGLE;
		let sighash_anyonecanpay = hash_type & SIGHASH_ANYONECANPAY != 0;

		let mut tx_copy = runtime.tx.clone();
		
		if sighash_none {
			tx_copy.outputs = Vec::new();
		} else if sighash_single {
			if runtime.index >= tx_copy.outputs.len() {
				unimplemented!();
				// return Ok(sha256::ONE);
			}
			tx_copy.outputs.truncate(runtime.index + 1);
			for (i, output) in tx_copy.outputs.iter_mut().enumerate() {
				if i == runtime.index {
					continue;
				}
				output.value = -1i64 as u64;
				output.lock = Script::new();
			}
		}

		if sighash_anyonecanpay {
			let mut input = tx_copy.inputs[runtime.index].clone();
			input.unlock = runtime.get_subscript();
			tx_copy.inputs = vec![input];
		} else {
			for (i, input) in tx_copy.inputs.iter_mut().enumerate() {
				if i == runtime.index {
					input.unlock = runtime.get_subscript();
				} else {
					input.unlock = Script::new();
					if sighash_none || sighash_single {
						input.sequence = 0;
					}
				}
			}
		}

		let serialized: crate::err::Result<_> = try {
			let mut serialized = Vec::new();
			tx_copy.serialize(&mut serialized)?;
			write_u32(&mut serialized, hash_type as u32)?;
			serialized
		};

		Ok(sha256::compute_double_sha256(&*serialized?))
	}

	fn push_stack(runtime: &mut ScriptRuntime, item: StackObject) -> Result<()> {
		runtime.stack.push(item);
		Ok(())
	}

	fn pop_stack(runtime: &mut ScriptRuntime) -> Result<StackObject> {
		runtime.stack.pop().ok_or(Err::ScriptError("too few items on stack".to_owned()))
	}

	fn push_alt_stack(runtime: &mut ScriptRuntime, item: StackObject) -> Result<()> {
		runtime.alt_stack.push(item);
		Ok(())
	}

	fn pop_alt_stack(runtime: &mut ScriptRuntime) -> Result<StackObject> {
		runtime.stack.pop().ok_or(Err::ScriptError("too few items on alt-stack".to_owned()))
	}

	fn check_stack(runtime: &mut ScriptRuntime, n: usize) -> Result<()> {
		if n > runtime.stack.len() {
			return Err(Err::ScriptError("too few items on the stack".to_owned()))
		}
		Ok(())
	}
	
	fn pop_stack_index(runtime: &mut ScriptRuntime) -> Result<usize> {
		let n = Op::pop_stack(runtime)?.to_i64() as usize;
		Op::check_stack(runtime, n + 1).and(Ok(runtime.stack.len() - 1 - n))
	}
}

impl <'a> fmt::Display for Op<'a> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Op::OP_0                => write!(f, "OP_0"),
			Op::OWNED_DATA(data)    => fmt_data(f, "", data),
			Op::DATA(data)          => fmt_data(f, "", data),
			Op::PUSHDATA1(data)     => fmt_data(f, "OP_PUSHDATA1 ", data),
			Op::PUSHDATA2(data)     => fmt_data(f, "OP_PUSHDATA2 ", data),
			Op::PUSHDATA4(data)     => fmt_data(f, "OP_PUSHDATA4 ", data),
			Op::OP_1NEGATE          => write!(f, "OP_1NEGATE"),
			Op::RESERVED            => write!(f, "OP_RESERVED"),
			Op::OP_1                => write!(f, "OP_1"),
			Op::OP_2                => write!(f, "OP_2"),
			Op::OP_3                => write!(f, "OP_3"),
			Op::OP_4                => write!(f, "OP_4"),
			Op::OP_5                => write!(f, "OP_5"),
			Op::OP_6                => write!(f, "OP_6"),
			Op::OP_7                => write!(f, "OP_7"),
			Op::OP_8                => write!(f, "OP_8"),
			Op::OP_9                => write!(f, "OP_9"),
			Op::OP_10               => write!(f, "OP_10"),
			Op::OP_11               => write!(f, "OP_11"),
			Op::OP_12               => write!(f, "OP_12"),
			Op::OP_13               => write!(f, "OP_13"),
			Op::OP_14               => write!(f, "OP_14"),
			Op::OP_15               => write!(f, "OP_15"),
			Op::OP_16               => write!(f, "OP_16"),
			Op::NOP                 => write!(f, "OP_NOP"),
			Op::VER                 => write!(f, "OP_VER"),
			Op::IF                  => write!(f, "OP_IF"),
			Op::NOTIF               => write!(f, "OP_NOTIF"),
			Op::VERIF               => write!(f, "OP_VERIF"),
			Op::VERNOTIF            => write!(f, "OP_VERNOTIF"),
			Op::ELSE                => write!(f, "OP_ELSE"),
			Op::ENDIF               => write!(f, "OP_ENDIF"),
			Op::VERIFY              => write!(f, "OP_VERIFY"),
			Op::RETURN              => write!(f, "OP_RETURN"),
			Op::TOALTSTACK          => write!(f, "OP_TOALTSTACK"),
			Op::FROMALTSTACK        => write!(f, "OP_FROMALTSTACK"),
			Op::OP_2DROP            => write!(f, "OP_2DROP"),
			Op::OP_2DUP             => write!(f, "OP_2DUP"),
			Op::OP_3DUP             => write!(f, "OP_3DUP"),
			Op::OP_2OVER            => write!(f, "OP_2OVER"),
			Op::OP_2ROT             => write!(f, "OP_2ROT"),
			Op::OP_2SWAP            => write!(f, "OP_2SWAP"),
			Op::IFDUP               => write!(f, "OP_IFDUP"),
			Op::DEPTH               => write!(f, "OP_DEPTH"),
			Op::DROP                => write!(f, "OP_DROP"),
			Op::DUP                 => write!(f, "OP_DUP"),
			Op::NIP                 => write!(f, "OP_NIP"),
			Op::OVER                => write!(f, "OP_OVER"),
			Op::PICK                => write!(f, "OP_PICK"),
			Op::ROLL                => write!(f, "OP_ROLL"),
			Op::ROT                 => write!(f, "OP_ROT"),
			Op::SWAP                => write!(f, "OP_SWAP"),
			Op::TUCK                => write!(f, "OP_TUCK"),
			Op::CAT                 => write!(f, "OP_CAT"),
			Op::SUBSTR              => write!(f, "OP_SUBSTR"),
			Op::LEFT                => write!(f, "OP_LEFT"),
			Op::RIGHT               => write!(f, "OP_RIGHT"),
			Op::SIZE                => write!(f, "OP_SIZE"),
			Op::INVERT              => write!(f, "OP_INVERT"),
			Op::AND                 => write!(f, "OP_AND"),
			Op::OR                  => write!(f, "OP_OR"),
			Op::XOR                 => write!(f, "OP_XOR"),
			Op::EQUAL               => write!(f, "OP_EQUAL"),
			Op::EQUALVERIFY         => write!(f, "OP_EQUALVERIFY"),
			Op::RESERVED1           => write!(f, "OP_RESERVED1"),
			Op::RESERVED2           => write!(f, "OP_RESERVED2"),
			Op::OP_1ADD             => write!(f, "OP_1ADD"),
			Op::OP_1SUB             => write!(f, "OP_1SUB"),
			Op::OP_2MUL             => write!(f, "OP_2MUL"),
			Op::OP_2DIV             => write!(f, "OP_2DIV"),
			Op::NEGATE              => write!(f, "OP_NEGATE"),
			Op::ABS                 => write!(f, "OP_ABS"),
			Op::NOT                 => write!(f, "OP_NOT"),
			Op::OP_0NOTEQUAL        => write!(f, "OP_0NOTEQUAL"),
			Op::ADD                 => write!(f, "OP_ADD"),
			Op::SUB                 => write!(f, "OP_SUB"),
			Op::MUL                 => write!(f, "OP_MUL"),
			Op::DIV                 => write!(f, "OP_DIV"),
			Op::MOD                 => write!(f, "OP_MOD"),
			Op::LSHIFT              => write!(f, "OP_LSHIFT"),
			Op::RSHIFT              => write!(f, "OP_RSHIFT"),
			Op::BOOLAND             => write!(f, "OP_BOOLAND"),
			Op::BOOLOR              => write!(f, "OP_BOOLOR"),
			Op::NUMEQUAL            => write!(f, "OP_NUMEQUAL"),
			Op::NUMEQUALVERIFY      => write!(f, "OP_NUMEQUALVERIFY"),
			Op::NUMNOTEQUAL         => write!(f, "OP_NUMNOTEQUAL"),
			Op::LESSTHAN            => write!(f, "OP_LESSTHAN"),
			Op::GREATERTHAN         => write!(f, "OP_GREATERTHAN"),
			Op::LESSTHANOREQUAL     => write!(f, "OP_LESSTHANOREQUAL"),
			Op::GREATERTHANOREQUAL  => write!(f, "OP_GREATERTHANOREQUAL"),
			Op::MIN                 => write!(f, "OP_MIN"),
			Op::MAX                 => write!(f, "OP_MAX"),
			Op::WITHIN              => write!(f, "OP_WITHIN"),
			Op::RIPEMD160           => write!(f, "OP_RIPEMD160"),
			Op::SHA1                => write!(f, "OP_SHA1"),
			Op::SHA256              => write!(f, "OP_SHA256"),
			Op::HASH160             => write!(f, "OP_HASH160"),
			Op::HASH256             => write!(f, "OP_HASH256"),
			Op::CODESEPARATOR       => write!(f, "OP_CODESEPARATOR"),
			Op::CHECKSIG            => write!(f, "OP_CHECKSIG"),
			Op::CHECKSIGVERIFY      => write!(f, "OP_CHECKSIGVERIFY"),
			Op::CHECKMULTISIG       => write!(f, "OP_CHECKMULTISIG"),
			Op::CHECKMULTISIGVERIFY => write!(f, "OP_CHECKMULTISIGVERIFY"),
			Op::NOP1                => write!(f, "OP_NOP1"),
			Op::CHECKLOCKTIMEVERIFY => write!(f, "OP_CHECKLOCKTIMEVERIFY"),
			Op::CHECKSEQUENCEVERIFY => write!(f, "OP_CHECKSEQUENCEVERIFY"),
			Op::NOP4                => write!(f, "OP_NOP4"),
			Op::NOP5                => write!(f, "OP_NOP5"),
			Op::NOP6                => write!(f, "OP_NOP6"),
			Op::NOP7                => write!(f, "OP_NOP7"),
			Op::NOP8                => write!(f, "OP_NOP8"),
			Op::NOP9                => write!(f, "OP_NOP9"),
			Op::NOP10               => write!(f, "OP_NOP10"),
			Op::INVALIDOPCODE(b)    => write!(f, "OP_INVALIDOPCODE({})", b),
		}
	}
}

// verify the famous "pizza transaction"
// as illustrated here:
// https://bitcoin.stackexchange.com/questions/32305/how-does-the-ecdsa-verification-algorithm-work-during-transaction
#[test]
fn pizza() {
	use crate::crypto::ecdsa::*;
	use crate::common::*;
	use crate::crypto::sha256;

	// decode transaction from bytes
	let raw_tx = hex_to_bytes("01000000018dd4f5fbd5e980fc02f35c6ce145935b11e284605bf599a13c6d415db55d07a1000000008b4830450221009908144ca6539e09512b9295c8a27050d478fbb96f8addbc3d075544dc41328702201aa528be2b907d316d2da068dd9eb1e23243d97e444d59290d2fddf25269ee0e0141042e930f39ba62c6534ee98ed20ca98959d34aa9e057cda01cfd422c6bab3667b76426529382c23f42b9b08d7832d4fee1d6b437a8526e59667ce9c4e9dcebcabbffffffff0200719a81860000001976a914df1bd49a6c9e34dfa8631f2c54cf39986027501b88ac009f0a5362000000434104cd5e9726e6afeae357b1806be25a4c3d3811775835d235417ea746b7db9eeab33cf01674b944c64561ce3388fa1abd0fa88b06c44ce81e2234aa70fe578d455dac00000000").unwrap();
	let tx = Tx::deserialize(&mut &*raw_tx).unwrap();

	// set input script to the "subscript" from the UTXO
	let mut tx_copy = tx.clone();
	tx_copy.inputs[0].unlock = Script::builder()
		.append(Op::DUP)
		.append(Op::HASH160)
		.append(Op::data_hex("46af3fb481837fadbb421727f9959c2d32a36829"))
		.append(Op::EQUALVERIFY)
		.append(Op::CHECKSIG)
		.build();

	// serialize the tx copy
	let serialized: crate::err::Result<_> = try {
		let mut serialized = Vec::new();
		tx_copy.serialize(&mut serialized)?;
		write_u32(&mut serialized, 1)?;
		serialized
	};

	// hash the tx copy
	let serialized = &*serialized.unwrap();
	let hash = sha256::compute_double_sha256(serialized);
	
	// pull sig & pubkey out of original tx input script
	let mut ops = tx.inputs[0].unlock.ops();

	let sig = match ops.next().unwrap() {
		Op::DATA(mut bytes) => ECDSASig::deserialize(&mut bytes),
		_ => unreachable!(),
	}.unwrap();

	let pubkey = match ops.next().unwrap() {
		Op::DATA(mut bytes) => ECDSAPubKey::deserialize(&mut bytes),
		_ => unreachable!(),
	}.unwrap();

	// aaaand verify!
	assert!(pubkey.verify(&sig, &hash));
}

#[test]
fn branching_if() {
	let tx = Tx::default();
	let state = Default::default();
	let mut runtime = ScriptRuntime::new(&tx, 0, &state);
	let script = Script::builder()
		.append(Op::data_u32(100))
		.append(Op::IF)
			.append(Op::data_u32(123456789))
		.append(Op::ELSE)
			.append(Op::OP_0)
		.append(Op::ENDIF)
		.build();
	
	runtime.execute(&script).unwrap();
	assert!(runtime.finalize().unwrap().to_i64() == 123456789)
}

#[test]
fn branching_else() {
	let tx = Tx::default();
	let state = Default::default();
	let mut runtime = ScriptRuntime::new(&tx, 0, &state);
	let script = Script::builder()
		.append(Op::OP_0)
		.append(Op::IF)
			.append(Op::data_u32(123456789))
		.append(Op::ELSE)
			.append(Op::OP_0)
		.append(Op::ENDIF)
		.build();
	
	runtime.execute(&script).unwrap();
	assert!(runtime.finalize().unwrap().is_falsey())
}