use std::fmt;

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
	OP_DATA(&'a[u8]),
	OP_PUSHDATA1(&'a[u8]),
	OP_PUSHDATA2(&'a[u8]),
	OP_PUSHDATA4(&'a[u8]),
	OP_1NEGATE,
	OP_RESERVED,
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
	OP_NOP,
	OP_VER,
	OP_IF,
	OP_NOTIF,
	OP_VERIF,
	OP_VERNOTIF,
	OP_ELSE,
	OP_ENDIF,
	OP_VERIFY,
	OP_RETURN,
	OP_TOALTSTACK,
	OP_FROMALTSTACK,
	OP_2DROP,
	OP_2DUP,
	OP_3DUP,
	OP_2OVER,
	OP_2ROT,
	OP_2SWAP,
	OP_IFDUP,
	OP_DEPTH,
	OP_DROP,
	OP_DUP,
	OP_NIP,
	OP_OVER,
	OP_PICK,
	OP_ROLL,
	OP_ROT,
	OP_SWAP,
	OP_TUCK,
	OP_CAT,
	OP_SUBSTR,
	OP_LEFT,
	OP_RIGHT,
	OP_SIZE,
	OP_INVERT,
	OP_AND,
	OP_OR,
	OP_XOR,
	OP_EQUAL,
	OP_EQUALVERIFY,
	OP_RESERVED1,
	OP_RESERVED2,
	OP_1ADD,
	OP_1SUB,
	OP_2MUL,
	OP_2DIV,
	OP_NEGATE,
	OP_ABS,
	OP_NOT,
	OP_0NOTEQUAL,
	OP_ADD,
	OP_SUB,
	OP_MUL,
	OP_DIV,
	OP_MOD,
	OP_LSHIFT,
	OP_RSHIFT,
	OP_BOOLAND,
	OP_BOOLOR,
	OP_NUMEQUAL,
	OP_NUMEQUALVERIFY,
	OP_NUMNOTEQUAL,
	OP_LESSTHAN,
	OP_GREATERTHAN,
	OP_LESSTHANOREQUAL,
	OP_GREATERTHANOREQUAL,
	OP_MIN,
	OP_MAX,
	OP_WITHIN,
	OP_RIPEMD160,
	OP_SHA1,
	OP_SHA256,
	OP_HASH160,
	OP_HASH256,
	OP_CODESEPARATOR,
	OP_CHECKSIG,
	OP_CHECKSIGVERIFY,
	OP_CHECKMULTISIG,
	OP_CHECKMULTISIGVERIFY,
	OP_NOP1,
	OP_CHECKLOCKTIMEVERIFY,
	OP_CHECKSEQUENCEVERIFY,
	OP_NOP4,
	OP_NOP5,
	OP_NOP6,
	OP_NOP7,
	OP_NOP8,
	OP_NOP9,
	OP_NOP10,
	OP_INVALIDOPCODE(u8),
}

fn fmt_data(f: &mut fmt::Formatter, op: &str, data: &[u8]) -> fmt::Result {
	write!(f, "{}", op)?;
	for &b in data.iter() {
		write!(f, "{:02x}", b)?;
	}
	Ok(())
}

impl <'a> Op<'a> {
	pub fn next(it: &mut super::ScriptIterator<'a>) -> Self {
		let opcode = it.next_u8();
		match opcode {
			OP_0                   => Op::OP_0,
			x @ 1..=75             => Op::OP_DATA(it.next_slice(x as usize)),
			OP_PUSHDATA1           => {
				let size = it.next_u8() as usize;
				Op::OP_PUSHDATA1(it.next_slice(size))
			},
			OP_PUSHDATA2           => {
				let size = it.next_u16() as usize;
				Op::OP_PUSHDATA2(it.next_slice(size))
			},
			OP_PUSHDATA4           => {
				let size = it.next_u32() as usize;
				Op::OP_PUSHDATA4(it.next_slice(size))
			},
			OP_1NEGATE             => Op::OP_1NEGATE,
			OP_RESERVED            => Op::OP_RESERVED,
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
			OP_NOP                 => Op::OP_NOP,
			OP_VER                 => Op::OP_VER,
			OP_IF                  => Op::OP_IF,
			OP_NOTIF               => Op::OP_NOTIF,
			OP_VERIF               => Op::OP_VERIF,
			OP_VERNOTIF            => Op::OP_VERNOTIF,
			OP_ELSE                => Op::OP_ELSE,
			OP_ENDIF               => Op::OP_ENDIF,
			OP_VERIFY              => Op::OP_VERIFY,
			OP_RETURN              => Op::OP_RETURN,
			OP_TOALTSTACK          => Op::OP_TOALTSTACK,
			OP_FROMALTSTACK        => Op::OP_FROMALTSTACK,
			OP_2DROP               => Op::OP_2DROP,
			OP_2DUP                => Op::OP_2DUP,
			OP_3DUP                => Op::OP_3DUP,
			OP_2OVER               => Op::OP_2OVER,
			OP_2ROT                => Op::OP_2ROT,
			OP_2SWAP               => Op::OP_2SWAP,
			OP_IFDUP               => Op::OP_IFDUP,
			OP_DEPTH               => Op::OP_DEPTH,
			OP_DROP                => Op::OP_DROP,
			OP_DUP                 => Op::OP_DUP,
			OP_NIP                 => Op::OP_NIP,
			OP_OVER                => Op::OP_OVER,
			OP_PICK                => Op::OP_PICK,
			OP_ROLL                => Op::OP_ROLL,
			OP_ROT                 => Op::OP_ROT,
			OP_SWAP                => Op::OP_SWAP,
			OP_TUCK                => Op::OP_TUCK,
			OP_CAT                 => Op::OP_CAT,
			OP_SUBSTR              => Op::OP_SUBSTR,
			OP_LEFT                => Op::OP_LEFT,
			OP_RIGHT               => Op::OP_RIGHT,
			OP_SIZE                => Op::OP_SIZE,
			OP_INVERT              => Op::OP_INVERT,
			OP_AND                 => Op::OP_AND,
			OP_OR                  => Op::OP_OR,
			OP_XOR                 => Op::OP_XOR,
			OP_EQUAL               => Op::OP_EQUAL,
			OP_EQUALVERIFY         => Op::OP_EQUALVERIFY,
			OP_RESERVED1           => Op::OP_RESERVED1,
			OP_RESERVED2           => Op::OP_RESERVED2,
			OP_1ADD                => Op::OP_1ADD,
			OP_1SUB                => Op::OP_1SUB,
			OP_2MUL                => Op::OP_2MUL,
			OP_2DIV                => Op::OP_2DIV,
			OP_NEGATE              => Op::OP_NEGATE,
			OP_ABS                 => Op::OP_ABS,
			OP_NOT                 => Op::OP_NOT,
			OP_0NOTEQUAL           => Op::OP_0NOTEQUAL,
			OP_ADD                 => Op::OP_ADD,
			OP_SUB                 => Op::OP_SUB,
			OP_MUL                 => Op::OP_MUL,
			OP_DIV                 => Op::OP_DIV,
			OP_MOD                 => Op::OP_MOD,
			OP_LSHIFT              => Op::OP_LSHIFT,
			OP_RSHIFT              => Op::OP_RSHIFT,
			OP_BOOLAND             => Op::OP_BOOLAND,
			OP_BOOLOR              => Op::OP_BOOLOR,
			OP_NUMEQUAL            => Op::OP_NUMEQUAL,
			OP_NUMEQUALVERIFY      => Op::OP_NUMEQUALVERIFY,
			OP_NUMNOTEQUAL         => Op::OP_NUMNOTEQUAL,
			OP_LESSTHAN            => Op::OP_LESSTHAN,
			OP_GREATERTHAN         => Op::OP_GREATERTHAN,
			OP_LESSTHANOREQUAL     => Op::OP_LESSTHANOREQUAL,
			OP_GREATERTHANOREQUAL  => Op::OP_GREATERTHANOREQUAL,
			OP_MIN                 => Op::OP_MIN,
			OP_MAX                 => Op::OP_MAX,
			OP_WITHIN              => Op::OP_WITHIN,
			OP_RIPEMD160           => Op::OP_RIPEMD160,
			OP_SHA1                => Op::OP_SHA1,
			OP_SHA256              => Op::OP_SHA256,
			OP_HASH160             => Op::OP_HASH160,
			OP_HASH256             => Op::OP_HASH256,
			OP_CODESEPARATOR       => Op::OP_CODESEPARATOR,
			OP_CHECKSIG            => Op::OP_CHECKSIG,
			OP_CHECKSIGVERIFY      => Op::OP_CHECKSIGVERIFY,
			OP_CHECKMULTISIG       => Op::OP_CHECKMULTISIG,
			OP_CHECKMULTISIGVERIFY => Op::OP_CHECKMULTISIGVERIFY,
			OP_NOP1                => Op::OP_NOP1,
			OP_CHECKLOCKTIMEVERIFY => Op::OP_CHECKLOCKTIMEVERIFY,
			OP_CHECKSEQUENCEVERIFY => Op::OP_CHECKSEQUENCEVERIFY,
			OP_NOP4                => Op::OP_NOP4,
			OP_NOP5                => Op::OP_NOP5,
			OP_NOP6                => Op::OP_NOP6,
			OP_NOP7                => Op::OP_NOP7,
			OP_NOP8                => Op::OP_NOP8,
			OP_NOP9                => Op::OP_NOP9,
			OP_NOP10               => Op::OP_NOP10,
			b                      => Op::OP_INVALIDOPCODE(b),
		}
	}
}

impl <'a> fmt::Display for Op<'a> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Op::OP_0                   => write!(f, "OP_0"),
			Op::OP_DATA(data)          => fmt_data(f, "", data),
			Op::OP_PUSHDATA1(data)     => fmt_data(f, "OP_PUSHDATA1 ", data),
			Op::OP_PUSHDATA2(data)     => fmt_data(f, "OP_PUSHDATA2 ", data),
			Op::OP_PUSHDATA4(data)     => fmt_data(f, "OP_PUSHDATA4 ", data),
			Op::OP_1NEGATE             => write!(f, "OP_1NEGATE"),
			Op::OP_RESERVED            => write!(f, "OP_RESERVED"),
			Op::OP_1                   => write!(f, "OP_1"),
			Op::OP_2                   => write!(f, "OP_2"),
			Op::OP_3                   => write!(f, "OP_3"),
			Op::OP_4                   => write!(f, "OP_4"),
			Op::OP_5                   => write!(f, "OP_5"),
			Op::OP_6                   => write!(f, "OP_6"),
			Op::OP_7                   => write!(f, "OP_7"),
			Op::OP_8                   => write!(f, "OP_8"),
			Op::OP_9                   => write!(f, "OP_9"),
			Op::OP_10                  => write!(f, "OP_10"),
			Op::OP_11                  => write!(f, "OP_11"),
			Op::OP_12                  => write!(f, "OP_12"),
			Op::OP_13                  => write!(f, "OP_13"),
			Op::OP_14                  => write!(f, "OP_14"),
			Op::OP_15                  => write!(f, "OP_15"),
			Op::OP_16                  => write!(f, "OP_16"),
			Op::OP_NOP                 => write!(f, "OP_NOP"),
			Op::OP_VER                 => write!(f, "OP_VER"),
			Op::OP_IF                  => write!(f, "OP_IF"),
			Op::OP_NOTIF               => write!(f, "OP_NOTIF"),
			Op::OP_VERIF               => write!(f, "OP_VERIF"),
			Op::OP_VERNOTIF            => write!(f, "OP_VERNOTIF"),
			Op::OP_ELSE                => write!(f, "OP_ELSE"),
			Op::OP_ENDIF               => write!(f, "OP_ENDIF"),
			Op::OP_VERIFY              => write!(f, "OP_VERIFY"),
			Op::OP_RETURN              => write!(f, "OP_RETURN"),
			Op::OP_TOALTSTACK          => write!(f, "OP_TOALTSTACK"),
			Op::OP_FROMALTSTACK        => write!(f, "OP_FROMALTSTACK"),
			Op::OP_2DROP               => write!(f, "OP_2DROP"),
			Op::OP_2DUP                => write!(f, "OP_2DUP"),
			Op::OP_3DUP                => write!(f, "OP_3DUP"),
			Op::OP_2OVER               => write!(f, "OP_2OVER"),
			Op::OP_2ROT                => write!(f, "OP_2ROT"),
			Op::OP_2SWAP               => write!(f, "OP_2SWAP"),
			Op::OP_IFDUP               => write!(f, "OP_IFDUP"),
			Op::OP_DEPTH               => write!(f, "OP_DEPTH"),
			Op::OP_DROP                => write!(f, "OP_DROP"),
			Op::OP_DUP                 => write!(f, "OP_DUP"),
			Op::OP_NIP                 => write!(f, "OP_NIP"),
			Op::OP_OVER                => write!(f, "OP_OVER"),
			Op::OP_PICK                => write!(f, "OP_PICK"),
			Op::OP_ROLL                => write!(f, "OP_ROLL"),
			Op::OP_ROT                 => write!(f, "OP_ROT"),
			Op::OP_SWAP                => write!(f, "OP_SWAP"),
			Op::OP_TUCK                => write!(f, "OP_TUCK"),
			Op::OP_CAT                 => write!(f, "OP_CAT"),
			Op::OP_SUBSTR              => write!(f, "OP_SUBSTR"),
			Op::OP_LEFT                => write!(f, "OP_LEFT"),
			Op::OP_RIGHT               => write!(f, "OP_RIGHT"),
			Op::OP_SIZE                => write!(f, "OP_SIZE"),
			Op::OP_INVERT              => write!(f, "OP_INVERT"),
			Op::OP_AND                 => write!(f, "OP_AND"),
			Op::OP_OR                  => write!(f, "OP_OR"),
			Op::OP_XOR                 => write!(f, "OP_XOR"),
			Op::OP_EQUAL               => write!(f, "OP_EQUAL"),
			Op::OP_EQUALVERIFY         => write!(f, "OP_EQUALVERIFY"),
			Op::OP_RESERVED1           => write!(f, "OP_RESERVED1"),
			Op::OP_RESERVED2           => write!(f, "OP_RESERVED2"),
			Op::OP_1ADD                => write!(f, "OP_1ADD"),
			Op::OP_1SUB                => write!(f, "OP_1SUB"),
			Op::OP_2MUL                => write!(f, "OP_2MUL"),
			Op::OP_2DIV                => write!(f, "OP_2DIV"),
			Op::OP_NEGATE              => write!(f, "OP_NEGATE"),
			Op::OP_ABS                 => write!(f, "OP_ABS"),
			Op::OP_NOT                 => write!(f, "OP_NOT"),
			Op::OP_0NOTEQUAL           => write!(f, "OP_0NOTEQUAL"),
			Op::OP_ADD                 => write!(f, "OP_ADD"),
			Op::OP_SUB                 => write!(f, "OP_SUB"),
			Op::OP_MUL                 => write!(f, "OP_MUL"),
			Op::OP_DIV                 => write!(f, "OP_DIV"),
			Op::OP_MOD                 => write!(f, "OP_MOD"),
			Op::OP_LSHIFT              => write!(f, "OP_LSHIFT"),
			Op::OP_RSHIFT              => write!(f, "OP_RSHIFT"),
			Op::OP_BOOLAND             => write!(f, "OP_BOOLAND"),
			Op::OP_BOOLOR              => write!(f, "OP_BOOLOR"),
			Op::OP_NUMEQUAL            => write!(f, "OP_NUMEQUAL"),
			Op::OP_NUMEQUALVERIFY      => write!(f, "OP_NUMEQUALVERIFY"),
			Op::OP_NUMNOTEQUAL         => write!(f, "OP_NUMNOTEQUAL"),
			Op::OP_LESSTHAN            => write!(f, "OP_LESSTHAN"),
			Op::OP_GREATERTHAN         => write!(f, "OP_GREATERTHAN"),
			Op::OP_LESSTHANOREQUAL     => write!(f, "OP_LESSTHANOREQUAL"),
			Op::OP_GREATERTHANOREQUAL  => write!(f, "OP_GREATERTHANOREQUAL"),
			Op::OP_MIN                 => write!(f, "OP_MIN"),
			Op::OP_MAX                 => write!(f, "OP_MAX"),
			Op::OP_WITHIN              => write!(f, "OP_WITHIN"),
			Op::OP_RIPEMD160           => write!(f, "OP_RIPEMD160"),
			Op::OP_SHA1                => write!(f, "OP_SHA1"),
			Op::OP_SHA256              => write!(f, "OP_SHA256"),
			Op::OP_HASH160             => write!(f, "OP_HASH160"),
			Op::OP_HASH256             => write!(f, "OP_HASH256"),
			Op::OP_CODESEPARATOR       => write!(f, "OP_CODESEPARATOR"),
			Op::OP_CHECKSIG            => write!(f, "OP_CHECKSIG"),
			Op::OP_CHECKSIGVERIFY      => write!(f, "OP_CHECKSIGVERIFY"),
			Op::OP_CHECKMULTISIG       => write!(f, "OP_CHECKMULTISIG"),
			Op::OP_CHECKMULTISIGVERIFY => write!(f, "OP_CHECKMULTISIGVERIFY"),
			Op::OP_NOP1                => write!(f, "OP_NOP1"),
			Op::OP_CHECKLOCKTIMEVERIFY => write!(f, "OP_CHECKLOCKTIMEVERIFY"),
			Op::OP_CHECKSEQUENCEVERIFY => write!(f, "OP_CHECKSEQUENCEVERIFY"),
			Op::OP_NOP4                => write!(f, "OP_NOP4"),
			Op::OP_NOP5                => write!(f, "OP_NOP5"),
			Op::OP_NOP6                => write!(f, "OP_NOP6"),
			Op::OP_NOP7                => write!(f, "OP_NOP7"),
			Op::OP_NOP8                => write!(f, "OP_NOP8"),
			Op::OP_NOP9                => write!(f, "OP_NOP9"),
			Op::OP_NOP10               => write!(f, "OP_NOP10"),
			Op::OP_INVALIDOPCODE(b)    => write!(f, "OP_INVALIDOPCODE({})", b),
		}
	}
}